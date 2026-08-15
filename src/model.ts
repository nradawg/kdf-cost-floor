/**
 * The cost model.
 *
 * One rule governs every number produced here, and it is the reason the
 * numbers disagree with the ones a simpler model reports:
 *
 *   DEFENDER figures are what the defender actually pays, as the deployed
 *   implementation is written.
 *
 *   ATTACKER figures are lower bounds computed assuming the attacker
 *   optimizes: skips work the defender cannot skip, reuses buffers the
 *   defender allocates separately, and recomputes anything cheaper to
 *   recompute than to store.
 *
 * Applying the defender's accounting to the attacker is the single most
 * common way a cost estimate comes out too high, and it comes out too high in
 * exactly the cases where the gap matters. The two sides do not run the same
 * program, so they do not get the same number.
 */

import {
  KdfCostError,
  requireExactInteger,
  requireInteger,
  type KdfErrorCode,
} from './errors.js';

// ---------------------------------------------------------------------------
// Units
// ---------------------------------------------------------------------------

/**
 * The primitive whose invocations an operation count counts.
 *
 * Op counts carry their unit because a Salsa20/8 core and a SHA-256
 * compression are not the same amount of work, and the ratio between them is
 * a property of the hardware, not of the algorithms. Adding or comparing
 * counts across units without a stated conversion produces a number with no
 * meaning, so this module refuses to do it silently. See `opUnitEquivalence`
 * in `check`.
 */
export type OpUnit =
  | 'sha1-compression'
  | 'sha256-compression'
  | 'sha512-compression'
  | 'salsa20-8-core'
  | 'argon2-block';

// ---------------------------------------------------------------------------
// Configurations
// ---------------------------------------------------------------------------

export type Pbkdf2Hash = 'sha1' | 'sha256' | 'sha512';

export interface Pbkdf2Config {
  kdf: 'pbkdf2';
  hash: Pbkdf2Hash;
  iterations: number;
  /**
   * Bytes of derived key produced, stored, and compared at verification time.
   *
   * Raising this above the hash output size raises the defender's cost and
   * nothing else. See `wasteRatio`.
   */
  dkLen: number;
  /** Salt length in bytes. Defaults to 16. */
  saltLen?: number;
}

export interface ScryptConfig {
  kdf: 'scrypt';
  /** The CPU and memory cost parameter. Must be a power of two greater than 1. */
  N: number;
  /** Block size. Memory scales with this as directly as it scales with N. */
  r: number;
  /**
   * Parallelism.
   *
   * This multiplies the defender's work and the attacker's work, and leaves
   * the attacker's memory per guess exactly where it was.
   */
  p: number;
  dkLen: number;
  /** Salt length in bytes. Defaults to 16. */
  saltLen?: number;
}

export interface Argon2idConfig {
  kdf: 'argon2id';
  /** The `m` parameter, in KiB. */
  memoryKiB: number;
  /** The `t` parameter: passes over memory. */
  iterations: number;
  /** The `p` parameter: lanes. Reduces the defender's latency, not the attacker's cost. */
  parallelism: number;
  dkLen: number;
  /** Salt length in bytes. Defaults to 16. The Argon2 specification requires at least 8. */
  saltLen?: number;
}

export type KdfConfig = Pbkdf2Config | ScryptConfig | Argon2idConfig;

/** A configuration with every optional field resolved, as validation returns it. */
export type NormalizedConfig = (Pbkdf2Config | ScryptConfig | Argon2idConfig) & {
  saltLen: number;
};

// ---------------------------------------------------------------------------
// Runtime ceilings
// ---------------------------------------------------------------------------

/**
 * The default `maxmem` for `crypto.scrypt` and `crypto.scryptSync`, 32 MiB.
 *
 * This constant is the reason a strength check alone is not enough. OWASP's
 * scrypt recommendation of N=2^17, r=8, p=1 needs 134,220,800 bytes, four
 * times this ceiling, so the recommended configuration throws
 * ERR_CRYPTO_INVALID_SCRYPT_PARAMS on a default Node call before it derives
 * anything.
 */
export const NODE_DEFAULT_SCRYPT_MAXMEM = 32 * 1024 * 1024;

/** OpenSSL rejects scrypt parameters whose product r*p exceeds this. */
export const MAX_SCRYPT_RP = 2 ** 30;

/** OpenSSL allocates scrypt working memory as a single int-sized request. */
export const MAX_SCRYPT_ALLOCATION = 2 ** 31 - 1;

export interface RuntimeLimits {
  /**
   * The `maxmem` your code will actually pass to `crypto.scrypt`.
   *
   * Defaults to Node's own default rather than to unlimited, because the
   * default is what most deployments run and it is where configurations
   * break.
   */
  scryptMaxmem?: number;
  /**
   * A ceiling on bytes one derivation may allocate, for KDFs that have no
   * runtime memory gate of their own. Argon2 has no implementation in
   * node:crypto, so without this its runtime feasibility is unverifiable and
   * this module says so instead of assuming it fits.
   */
  maxAllocationBytes?: number;
}

export type RuntimeStatus = 'withinLimits' | 'exceedsLimits' | 'notVerifiable';

export interface RuntimeAssessment {
  status: RuntimeStatus;
  /** Bytes the implementation will try to allocate for one derivation. */
  requiredBytes: number;
  /** The ceiling compared against, or null when the runtime imposes none. */
  ceilingBytes: number | null;
  /** A full sentence explaining the status. */
  detail: string;
}

// ---------------------------------------------------------------------------
// The cost model
// ---------------------------------------------------------------------------

export interface CostModel {
  kdf: KdfConfig['kdf'];
  /** The primitive that `defenderOps`, `attackerOps` and the critical path count. */
  opUnit: OpUnit;

  /** Primitive invocations the defender performs for one derivation. */
  defenderOps: number;
  /**
   * Primitive invocations on the critical path of one defender derivation.
   *
   * Wall clock tracks this, not `defenderOps`. They differ whenever the
   * implementation runs work concurrently, which Argon2 does across lanes and
   * scrypt does not do across p.
   */
  defenderCriticalPathOps: number;
  /** Bytes the defender's implementation allocates for one derivation. */
  defenderBytes: number;

  /**
   * Primitive invocations an attacker must perform to reject one wrong guess.
   *
   * A wrong guess is rejected as soon as any stored output byte disagrees, so
   * this counts the work up to the first comparable byte, not the work to
   * produce the whole derived key.
   */
  attackerOps: number;
  /**
   * Bytes an attacker must hold concurrently per in-flight guess.
   *
   * On the hardware that cracks passwords this is the binding constraint: a
   * card with a fixed pool of memory runs pool/bytes guesses at once, so this
   * figure divides the attacker's parallelism directly.
   */
  attackerBytesPerGuess: number;
  /**
   * `attackerOps * attackerBytesPerGuess`, carried as bigint.
   *
   * Throughput on memory-bound hardware is proportional to the inverse of
   * this product, which makes it the one attacker figure worth reducing to a
   * scalar. It is a bigint because the product passes 2^53 at ordinary
   * parameter sizes and a rounded cost floor is not a floor.
   */
  attackerAreaTime: bigint;

  /**
   * `defenderOps / attackerOps`.
   *
   * Above 1 means the defender is buying work the attacker never performs.
   * PBKDF2 with a derived key longer than the hash output sits at the number
   * of output blocks, less the shared HMAC key schedule.
   */
  wasteRatio: number;

  /** Whether memory cost is a parameter of this KDF at all. */
  memoryHard: boolean;

  runtime: RuntimeAssessment;

  /** Full-sentence statements of what these counts include and exclude. */
  notes: string[];
}

interface HashGeometry {
  digestBytes: number;
  blockBytes: number;
  /** Bytes of length field in the Merkle-Damgard padding. */
  lengthFieldBytes: number;
  unit: OpUnit;
}

const HASHES: Record<Pbkdf2Hash, HashGeometry> = {
  sha1: { digestBytes: 20, blockBytes: 64, lengthFieldBytes: 8, unit: 'sha1-compression' },
  sha256: { digestBytes: 32, blockBytes: 64, lengthFieldBytes: 8, unit: 'sha256-compression' },
  sha512: { digestBytes: 64, blockBytes: 128, lengthFieldBytes: 16, unit: 'sha512-compression' },
};

const CONFIG = 'invalidConfig' satisfies KdfErrorCode;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/**
 * Check that a configuration is one a real implementation will run, and fill
 * in defaults.
 *
 * Parameter validation lives ahead of the cost model rather than inside it
 * because a cost computed from parameters that throw at derivation time is a
 * score for a system that does not exist.
 */
export function validateConfig(config: KdfConfig): NormalizedConfig {
  if (config === null || typeof config !== 'object') {
    throw new KdfCostError(
      `A KDF configuration must be an object with a "kdf" field naming the ` +
        `algorithm, but received ${config === null ? 'null' : typeof config}. ` +
        `Supported values for "kdf" are "pbkdf2", "scrypt" and "argon2id".`,
      CONFIG,
    );
  }

  switch (config.kdf) {
    case 'pbkdf2':
      return validatePbkdf2(config);
    case 'scrypt':
      return validateScrypt(config);
    case 'argon2id':
      return validateArgon2id(config);
    default: {
      const seen = (config as { kdf?: unknown }).kdf;
      throw new KdfCostError(
        `Unknown KDF ${JSON.stringify(seen)}. This module models "pbkdf2", ` +
          `"scrypt" and "argon2id", and refuses to score an algorithm it has ` +
          `no cost model for rather than fall back to a generic one, because a ` +
          `generic cost model is how a fast hash gets approved. Add a model for ` +
          `this algorithm or validate it elsewhere.`,
        CONFIG,
      );
    }
  }
}

function validateSaltLen(saltLen: number | undefined, minimum: number, spec: string): number {
  if (saltLen === undefined) return 16;
  return requireInteger(saltLen, 'saltLen', CONFIG, {
    min: minimum,
    because:
      `A salt shorter than ${minimum} bytes is either rejected by ${spec} or ` +
      `collides often enough across a user table that one cracking run covers ` +
      `several accounts. Use 16 random bytes.`,
  });
}

function validatePbkdf2(config: Pbkdf2Config): NormalizedConfig {
  const geometry = HASHES[config.hash];
  if (geometry === undefined) {
    throw new KdfCostError(
      `Unknown PBKDF2 hash ${JSON.stringify(config.hash)}. This module models ` +
        `"sha1", "sha256" and "sha512". The hash choice changes both the cost ` +
        `per iteration and the output block size that sets the waste ratio, so ` +
        `it cannot be defaulted.`,
      CONFIG,
    );
  }

  const iterations = requireInteger(config.iterations, 'iterations', CONFIG, {
    min: 1,
    because: 'PBKDF2 performs at least one PRF call per output block.',
  });
  const dkLen = requireInteger(config.dkLen, 'dkLen', CONFIG, {
    min: 1,
    max: 2 ** 31 - 1,
    because:
      'A derived key of zero bytes compares equal to every candidate password, ' +
      'so it authenticates everyone.',
  });
  const saltLen = validateSaltLen(config.saltLen, 0, 'the implementation');

  return { kdf: 'pbkdf2', hash: config.hash, iterations, dkLen, saltLen };
}

function validateScrypt(config: ScryptConfig): NormalizedConfig {
  const N = requireInteger(config.N, 'N', CONFIG, {
    min: 2,
    max: 2 ** 31,
    because: 'scrypt requires N to be a power of two greater than 1.',
  });
  if ((N & (N - 1)) !== 0) {
    throw new KdfCostError(
      `N must be a power of two, but received ${N}. scrypt indexes its ` +
        `V array by masking with N-1, so a non-power-of-two N is rejected by ` +
        `OpenSSL and by node:crypto rather than rounded. Use ${2 ** Math.round(Math.log2(N))} ` +
        `or another power of two.`,
      CONFIG,
    );
  }

  const r = requireInteger(config.r, 'r', CONFIG, {
    min: 1,
    because: 'scrypt mixes blocks of 128*r bytes, so r must be at least 1.',
  });
  const p = requireInteger(config.p, 'p', CONFIG, {
    min: 1,
    because: 'scrypt performs p independent mixing passes, so p must be at least 1.',
  });

  if (r * p > MAX_SCRYPT_RP) {
    throw new KdfCostError(
      `r*p is ${r * p}, above the ${MAX_SCRYPT_RP} limit OpenSSL enforces, so ` +
        `node:crypto rejects these parameters before deriving anything. Lower r ` +
        `or p. Note that lowering p costs the attacker nothing in memory, so ` +
        `prefer lowering p and raising N if you need the cost back.`,
      CONFIG,
    );
  }

  // RFC 7914 requires N < 2^(128*r/8). The guard only bites for very small r,
  // where the V array indices run out of room, and it is the reason r=1 caps
  // out at N=2^16 no matter how much memory the host has.
  if (16 * r < 64 && N >= 2 ** (16 * r)) {
    throw new KdfCostError(
      `N must be below 2^(128*r/8) = 2^${16 * r} when r is ${r}, but received ` +
        `${N}. This is a limit in the scrypt specification, not a policy in this ` +
        `module. Raise r instead of N: r and N buy attacker memory at the same ` +
        `rate, since the V array is 128*r*N bytes either way.`,
      CONFIG,
    );
  }

  const dkLen = requireInteger(config.dkLen, 'dkLen', CONFIG, {
    min: 1,
    max: 2 ** 31 - 1,
    because:
      'A derived key of zero bytes compares equal to every candidate password, ' +
      'so it authenticates everyone.',
  });
  const saltLen = validateSaltLen(config.saltLen, 0, 'the implementation');

  const required = scryptRequiredBytes(N, r, p);
  if (required > MAX_SCRYPT_ALLOCATION) {
    throw new KdfCostError(
      `These parameters need ${required} bytes of working memory, above the ` +
        `${MAX_SCRYPT_ALLOCATION} byte single-allocation limit OpenSSL enforces, ` +
        `so no maxmem value makes them run. Lower N or r.`,
      CONFIG,
    );
  }

  return { kdf: 'scrypt', N, r, p, dkLen, saltLen };
}

function validateArgon2id(config: Argon2idConfig): NormalizedConfig {
  const parallelism = requireInteger(config.parallelism, 'parallelism', CONFIG, {
    min: 1,
    max: 2 ** 24 - 1,
    because: 'The Argon2 specification allows 1 to 2^24-1 lanes.',
  });
  const memoryKiB = requireInteger(config.memoryKiB, 'memoryKiB', CONFIG, {
    min: 8 * parallelism,
    because:
      `Argon2 requires m >= 8*p so every lane holds at least one slice of four ` +
      `blocks. With p=${parallelism} that means at least ${8 * parallelism} KiB.`,
  });
  const iterations = requireInteger(config.iterations, 'iterations', CONFIG, {
    min: 1,
    because: 'Argon2 makes at least one pass over memory.',
  });
  const dkLen = requireInteger(config.dkLen, 'dkLen', CONFIG, {
    min: 4,
    max: 2 ** 31 - 1,
    because: 'The Argon2 specification requires a tag of at least 4 bytes.',
  });
  const saltLen = validateSaltLen(config.saltLen, 8, 'the Argon2 specification');

  return { kdf: 'argon2id', memoryKiB, iterations, parallelism, dkLen, saltLen };
}

// ---------------------------------------------------------------------------
// scrypt memory
// ---------------------------------------------------------------------------

/**
 * Bytes OpenSSL allocates for a scrypt derivation, which is what `maxmem` is
 * compared against.
 *
 * The V array is 128*r*(N+2) bytes and the B array is 128*r*p, and OpenSSL
 * checks their sum. The `+2` and the `+p` are small but they are not
 * decorative: with r=8 and p=1, N=2^15 needs 33,557,504 bytes against Node's
 * 33,554,432 default, so a model that reported the round 128*r*N figure of
 * 33,554,432 would predict that it fits by exactly the margin that makes it
 * throw.
 */
export function scryptRequiredBytes(N: number, r: number, p: number): number {
  return 128 * r * (N + p + 2);
}

/**
 * The `maxmem` value to pass to `crypto.scrypt` so this configuration runs.
 *
 * Offered because the alternative repair is the dangerous one. When scrypt
 * throws for memory, lowering N until the exception stops is the change that
 * requires no argument with anyone, and it weakens every password in the
 * database. Raising maxmem costs the defender the memory they already decided
 * to spend.
 */
export function scryptMaxmemFor(config: ScryptConfig): number {
  const normalized = validateConfig(config);
  if (normalized.kdf !== 'scrypt') {
    throw new KdfCostError(
      `scryptMaxmemFor expects a scrypt configuration, but received one for ` +
        `${normalized.kdf}. Only scrypt has a maxmem parameter in node:crypto.`,
      CONFIG,
    );
  }
  return scryptRequiredBytes(normalized.N, normalized.r, normalized.p);
}

// ---------------------------------------------------------------------------
// Cost
// ---------------------------------------------------------------------------

/** Compute the cost model for a configuration. Validates first. */
export function costOf(config: KdfConfig, limits: RuntimeLimits = {}): CostModel {
  const normalized = validateConfig(config);
  switch (normalized.kdf) {
    case 'pbkdf2':
      return pbkdf2Cost(normalized, limits);
    case 'scrypt':
      return scryptCost(normalized, limits);
    case 'argon2id':
      return argon2idCost(normalized, limits);
  }
}

function areaTime(ops: number, bytes: number): bigint {
  return BigInt(ops) * BigInt(bytes);
}

function pbkdf2Cost(
  config: Pbkdf2Config & { saltLen: number },
  limits: RuntimeLimits,
): CostModel {
  const geometry = HASHES[config.hash];
  const { digestBytes, blockBytes, lengthFieldBytes, unit } = geometry;

  const compressionsFor = (messageBytes: number): number =>
    Math.ceil((messageBytes + 1 + lengthFieldBytes) / blockBytes);

  // HMAC with a precomputed key schedule costs two compressions per iteration
  // after the first: one for the inner hash over the previous 32 or 64 byte U
  // value, one for the outer hash over the resulting digest. Both fit in a
  // single block for every hash modelled here.
  const perIterationAfterFirst = 2;
  const firstIteration = compressionsFor(config.saltLen + 4) + 1;
  const perBlock = firstIteration + (config.iterations - 1) * perIterationAfterFirst;

  // The ipad and opad midstates depend on the password, so an attacker pays
  // for them once per candidate, exactly as the defender pays once per
  // derivation.
  const keySchedule = 2;

  const blocks = Math.ceil(config.dkLen / digestBytes);
  const defenderOps = requireExactInteger(keySchedule + blocks * perBlock, 'defenderOps', CONFIG);

  // This is the whole PBKDF2 argument. An attacker testing a candidate
  // password computes T1 and compares it against the first `digestBytes` of
  // the stored key. A wrong guess disagrees there, so the attacker stops.
  // Blocks two and beyond are computed only for the candidate that already
  // matched, which is to say never during a search. Raising dkLen from 32 to
  // 64 with SHA-256 therefore doubles the defender's work and adds nothing at
  // all to the cost of a guess.
  const attackerOps = requireExactInteger(keySchedule + perBlock, 'attackerOps', CONFIG);

  // PBKDF2 holds two key midstates, one working block and two digest-sized
  // accumulators. It is a constant of a few hundred bytes and it does not
  // move with any parameter, which is the point: there is no setting of
  // PBKDF2 that makes an attacker's memory the constraint.
  const stateBytes = 4 * digestBytes + blockBytes;
  const defenderBytes = stateBytes + config.dkLen;

  return {
    kdf: 'pbkdf2',
    opUnit: unit,
    defenderOps,
    // node:crypto derives the output blocks serially inside one call, so the
    // full count is on the critical path even though the blocks are
    // independent and could in principle run concurrently.
    defenderCriticalPathOps: defenderOps,
    defenderBytes,
    attackerOps,
    attackerBytesPerGuess: stateBytes,
    attackerAreaTime: areaTime(attackerOps, stateBytes),
    wasteRatio: defenderOps / attackerOps,
    memoryHard: false,
    runtime: assessRuntime('pbkdf2', defenderBytes, limits),
    notes: [
      `Operations are counted in ${unit} invocations, assuming an implementation ` +
        `that precomputes the HMAC key schedule once per derivation, which every ` +
        `serious one does.`,
      `The attacker figure counts one output block, because a wrong guess is ` +
        `rejected by the first ${digestBytes} bytes of the stored key and the ` +
        `remaining ${Math.max(0, config.dkLen - digestBytes)} bytes are never computed ` +
        `during a search.`,
      `PBKDF2 has no memory parameter, so the memory figure is a fixed ${stateBytes} ` +
        `bytes of hash state. Treat it as zero when reasoning about attacker ` +
        `economics: it is far below the per-core memory of any cracking device, ` +
        `so it never limits how many guesses run at once.`,
    ],
  };
}

function scryptCost(config: ScryptConfig & { saltLen: number }, limits: RuntimeLimits): CostModel {
  const { N, r, p } = config;

  // ROMix runs 2N BlockMix calls and each BlockMix runs 2r Salsa20/8 cores, so
  // one pass is 4*N*r cores and p passes are 4*N*r*p.
  const ops = requireExactInteger(4 * N * r * p, 'scrypt operation count', CONFIG);

  const defenderBytes = scryptRequiredBytes(N, r, p);

  // Here is the scrypt trap, in one line. The V array is 128*r*N bytes and it
  // is the only large allocation. The p mixing passes are independent, so an
  // attacker runs them one after another through a single V array and never
  // holds more than one. p multiplies the attacker's time and leaves the
  // attacker's memory exactly where it was.
  //
  // The defender's own figure above is larger, because OpenSSL materializes
  // all p blocks of B up front and adds two blocks of scratch. That is a real
  // cost the defender pays and a cost the attacker declines to pay: B chunks
  // are cheap to regenerate from the initial PBKDF2 pass, so an optimizing
  // attacker regenerates them per lane rather than storing p of them.
  const attackerBytesPerGuess = requireExactInteger(128 * r * N, 'attacker memory', CONFIG);

  return {
    kdf: 'scrypt',
    opUnit: 'salsa20-8-core',
    defenderOps: ops,
    // node:crypto runs the p passes serially inside one scrypt call, so every
    // one of them is on the wall clock. This is why a high-p configuration
    // feels as slow as a high-N one while costing an attacker far less.
    defenderCriticalPathOps: ops,
    defenderBytes,
    attackerOps: ops,
    attackerBytesPerGuess,
    attackerAreaTime: areaTime(ops, attackerBytesPerGuess),
    // Every Salsa core the defender runs is one the attacker runs too: scrypt
    // produces no output byte until ROMix finishes, so there is no early
    // rejection to exploit and no defender-only work to skip.
    wasteRatio: 1,
    memoryHard: true,
    runtime: assessRuntime('scrypt', defenderBytes, limits),
    notes: [
      'Operations are counted in Salsa20/8 core invocations: 4*N*r*p of them.',
      `The count excludes the PBKDF2-HMAC-SHA256 passes that bracket the mixing ` +
        `(about ${Math.ceil((128 * r * p) / 32) + Math.ceil(config.dkLen / 32)} HMAC calls). ` +
        `They are negligible next to ${ops} core invocations and they are measured ` +
        `in a different unit, so adding them would produce a number in no unit at all.`,
      `Attacker memory is the ${attackerBytesPerGuess} byte V array. It does not ` +
        `move with p, so raising p to buy cost raises the defender's latency and ` +
        `the attacker's time while leaving untouched the one quantity that limits ` +
        `how many guesses a memory-bound cracker runs at once.`,
    ],
  };
}

function argon2idCost(
  config: Argon2idConfig & { saltLen: number },
  limits: RuntimeLimits,
): CostModel {
  const { memoryKiB, iterations, parallelism } = config;

  // Argon2 rounds the requested memory down to a multiple of 4*p blocks so
  // every lane divides into four equal slices. Asking for memory that does not
  // divide evenly gets you less than you asked for, silently, in every
  // conforming implementation.
  const granularity = 4 * parallelism;
  const blocks = Math.floor(memoryKiB / granularity) * granularity;

  const ops = requireExactInteger(iterations * blocks, 'argon2 operation count', CONFIG);
  const bytes = requireExactInteger(blocks * 1024, 'argon2 memory', CONFIG);

  // Argon2's lanes run concurrently, so the defender's wall clock tracks
  // ops/p while the attacker's cost tracks the full m*t product. Parallelism
  // is a latency discount for the defender and nothing for the attacker, which
  // makes m*t*p the most tempting and most wrong of the available scalars.
  const criticalPath = Math.ceil(ops / parallelism);

  return {
    kdf: 'argon2id',
    opUnit: 'argon2-block',
    defenderOps: ops,
    defenderCriticalPathOps: criticalPath,
    defenderBytes: bytes,
    attackerOps: ops,
    attackerBytesPerGuess: bytes,
    attackerAreaTime: areaTime(ops, bytes),
    // Argon2 emits no output until the final block is mixed, so there is no
    // partial derivation for an attacker to reject a guess from early.
    wasteRatio: 1,
    memoryHard: true,
    runtime: assessRuntime('argon2id', bytes, limits),
    notes: [
      'Operations are counted in Argon2 block compressions: t passes over m blocks.',
      `The count treats every block of every pass as one compression, which ` +
        `overstates the first pass slightly, since the first two blocks of each ` +
        `lane come from the initial hash rather than from G.`,
      parallelism > 1
        ? `With p=${parallelism} the defender's wall clock tracks ${criticalPath} ` +
          `sequential compressions while an attacker still pays for all ${ops}. ` +
          `Parallelism buys the defender latency, not the attacker cost.`
        : 'With p=1 the defender pays the full count sequentially.',
    ],
  };
}

// ---------------------------------------------------------------------------
// Runtime feasibility
// ---------------------------------------------------------------------------

function assessRuntime(
  kdf: KdfConfig['kdf'],
  requiredBytes: number,
  limits: RuntimeLimits,
): RuntimeAssessment {
  if (kdf === 'scrypt') {
    const ceiling =
      limits.scryptMaxmem === undefined
        ? NODE_DEFAULT_SCRYPT_MAXMEM
        : requireInteger(limits.scryptMaxmem, 'limits.scryptMaxmem', CONFIG, {
            min: 1,
            because: 'maxmem is a byte count passed through to OpenSSL.',
          });

    if (requiredBytes > ceiling) {
      return {
        status: 'exceedsLimits',
        requiredBytes,
        ceilingBytes: ceiling,
        detail:
          `This derivation needs ${requiredBytes} bytes and node:crypto will be ` +
          `called with maxmem=${ceiling}, so crypto.scrypt throws ` +
          `ERR_CRYPTO_INVALID_SCRYPT_PARAMS before deriving anything. Pass ` +
          `maxmem: ${requiredBytes} or higher.`,
      };
    }

    return {
      status: 'withinLimits',
      requiredBytes,
      ceilingBytes: ceiling,
      detail:
        `This derivation needs ${requiredBytes} bytes and fits under the ` +
        `maxmem=${ceiling} it will be called with, leaving ${ceiling - requiredBytes} ` +
        `bytes of headroom.`,
    };
  }

  const ceiling =
    limits.maxAllocationBytes === undefined
      ? null
      : requireInteger(limits.maxAllocationBytes, 'limits.maxAllocationBytes', CONFIG, {
          min: 1,
          because: 'An allocation ceiling is a byte count.',
        });

  if (kdf === 'argon2id' && ceiling === null) {
    return {
      status: 'notVerifiable',
      requiredBytes,
      ceilingBytes: null,
      detail:
        `This derivation needs ${requiredBytes} bytes, and node:crypto has no ` +
        `Argon2 implementation, so this module cannot check the parameters ` +
        `against a runtime the way it checks scrypt against maxmem. Set ` +
        `limits.maxAllocationBytes to the ceiling of the implementation you will ` +
        `actually deploy, or pass allowUnverifiableRuntime to accept the gap ` +
        `knowingly.`,
    };
  }

  if (ceiling !== null && requiredBytes > ceiling) {
    return {
      status: 'exceedsLimits',
      requiredBytes,
      ceilingBytes: ceiling,
      detail:
        `This derivation needs ${requiredBytes} bytes against a stated ceiling ` +
        `of ${ceiling}, so it will fail to allocate at run time.`,
    };
  }

  return {
    status: 'withinLimits',
    requiredBytes,
    ceilingBytes: ceiling,
    detail:
      ceiling === null
        ? `This derivation needs ${requiredBytes} bytes and PBKDF2 has no runtime ` +
          `memory gate, so there is nothing here that can throw for memory.`
        : `This derivation needs ${requiredBytes} bytes and fits under the stated ` +
          `ceiling of ${ceiling}.`,
  };
}

// ---------------------------------------------------------------------------
// Description
// ---------------------------------------------------------------------------

/** A short, parameter-complete label, used in floor labels and error messages. */
export function describeConfig(config: KdfConfig): string {
  const normalized = validateConfig(config);
  switch (normalized.kdf) {
    case 'pbkdf2':
      return `PBKDF2-HMAC-${normalized.hash.toUpperCase()} with ${normalized.iterations} iterations and dkLen=${normalized.dkLen}`;
    case 'scrypt':
      return `scrypt with N=${normalized.N}, r=${normalized.r}, p=${normalized.p}`;
    case 'argon2id':
      return `Argon2id with m=${normalized.memoryKiB} KiB, t=${normalized.iterations}, p=${normalized.parallelism}`;
  }
}
