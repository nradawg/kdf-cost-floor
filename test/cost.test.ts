import { pbkdf2Sync, scryptSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  KdfCostError,
  NODE_DEFAULT_SCRYPT_MAXMEM,
  costOf,
  describeConfig,
  scryptMaxmemFor,
  scryptRequiredBytes,
  validateConfig,
  type Argon2idConfig,
  type KdfConfig,
  type Pbkdf2Config,
  type ScryptConfig,
} from '../src/index.js';

/**
 * The two scrypt configurations at the centre of this module. They perform an
 * identical number of Salsa20/8 cores, so they take the same wall clock, and
 * they cost an attacker sixteen times different amounts of memory per guess.
 */
const EQUAL_TIME_CHEAP: ScryptConfig = { kdf: 'scrypt', N: 2 ** 14, r: 8, p: 16, dkLen: 32 };
const EQUAL_TIME_STRONG: ScryptConfig = { kdf: 'scrypt', N: 2 ** 18, r: 8, p: 1, dkLen: 32 };

function code(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    if (error instanceof KdfCostError) return error.code;
    throw error;
  }
  throw new Error('expected the call to throw a KdfCostError, but it returned');
}

// ---------------------------------------------------------------------------
// Parameter validation
// ---------------------------------------------------------------------------

describe('scrypt parameter validation', () => {
  it('rejects an N that is not a power of two', () => {
    expect(() => validateConfig({ kdf: 'scrypt', N: 10000, r: 8, p: 1, dkLen: 32 })).toThrow(
      /must be a power of two/,
    );
  });

  it('rejects N below 2', () => {
    expect(() => validateConfig({ kdf: 'scrypt', N: 1, r: 8, p: 1, dkLen: 32 })).toThrow(
      /N must be at least 2/,
    );
  });

  it('rejects r of zero', () => {
    expect(() => validateConfig({ kdf: 'scrypt', N: 1024, r: 0, p: 1, dkLen: 32 })).toThrow(
      /r must be at least 1/,
    );
  });

  it('rejects p of zero', () => {
    expect(() => validateConfig({ kdf: 'scrypt', N: 1024, r: 8, p: 0, dkLen: 32 })).toThrow(
      /p must be at least 1/,
    );
  });

  it('enforces the specification bound N < 2^(128*r/8) for small r', () => {
    // With r=1 the ceiling is 2^16 no matter how much memory the host has.
    expect(() => validateConfig({ kdf: 'scrypt', N: 2 ** 16, r: 1, p: 1, dkLen: 32 })).toThrow(
      /2\^16/,
    );
    expect(() =>
      validateConfig({ kdf: 'scrypt', N: 2 ** 15, r: 1, p: 1, dkLen: 32 }),
    ).not.toThrow();
  });

  it('rejects a derived key of zero bytes', () => {
    // A zero-length key compares equal to every candidate password.
    expect(() => validateConfig({ kdf: 'scrypt', N: 1024, r: 8, p: 1, dkLen: 0 })).toThrow(
      /authenticates everyone/,
    );
  });

  it('rejects a NaN parameter with an explanation of why NaN specifically', () => {
    // Every comparison against NaN is false, so a NaN threshold passes
    // everything. This is the one bad value that must not be treated as an
    // ordinary out-of-range number.
    expect(() =>
      validateConfig({ kdf: 'scrypt', N: Number.NaN, r: 8, p: 1, dkLen: 32 }),
    ).toThrow(/every comparison against NaN is false/i);
  });

  it('rejects a fractional parameter rather than rounding it', () => {
    expect(() => validateConfig({ kdf: 'scrypt', N: 1024.5, r: 8, p: 1, dkLen: 32 })).toThrow(
      /whole number/,
    );
  });

  it('rejects a string parameter rather than coercing it', () => {
    const config = { kdf: 'scrypt', N: '16384', r: 8, p: 1, dkLen: 32 } as unknown as KdfConfig;
    expect(() => validateConfig(config)).toThrow(/must be a number/);
  });

  it('rejects r*p above the OpenSSL limit', () => {
    expect(() =>
      validateConfig({ kdf: 'scrypt', N: 1024, r: 2 ** 20, p: 2 ** 11, dkLen: 32 }),
    ).toThrow(/r\*p is/);
  });

  it('rejects parameters no maxmem value can make runnable', () => {
    // Above the OpenSSL single-allocation limit there is no ceiling to raise.
    expect(() =>
      validateConfig({ kdf: 'scrypt', N: 2 ** 22, r: 8, p: 1, dkLen: 32 }),
    ).toThrow(/no maxmem value makes them run/);
  });

  it('tags every configuration error with invalidConfig', () => {
    expect(code(() => validateConfig({ kdf: 'scrypt', N: 3, r: 8, p: 1, dkLen: 32 }))).toBe(
      'invalidConfig',
    );
  });
});

describe('pbkdf2 parameter validation', () => {
  it('rejects zero iterations', () => {
    expect(() =>
      validateConfig({ kdf: 'pbkdf2', hash: 'sha256', iterations: 0, dkLen: 32 }),
    ).toThrow(/iterations must be at least 1/);
  });

  it('rejects an unmodelled hash rather than defaulting one', () => {
    const config = {
      kdf: 'pbkdf2',
      hash: 'md5',
      iterations: 1000,
      dkLen: 32,
    } as unknown as KdfConfig;
    expect(() => validateConfig(config)).toThrow(/Unknown PBKDF2 hash/);
  });

  it('rejects a derived key of zero bytes', () => {
    expect(() =>
      validateConfig({ kdf: 'pbkdf2', hash: 'sha256', iterations: 1000, dkLen: 0 }),
    ).toThrow(/authenticates everyone/);
  });

  it('defaults the salt length to 16 bytes', () => {
    const normalized = validateConfig({
      kdf: 'pbkdf2',
      hash: 'sha256',
      iterations: 1000,
      dkLen: 32,
    });
    expect(normalized.saltLen).toBe(16);
  });
});

describe('argon2id parameter validation', () => {
  it('enforces m >= 8*p', () => {
    expect(() =>
      validateConfig({
        kdf: 'argon2id',
        memoryKiB: 16,
        iterations: 3,
        parallelism: 4,
        dkLen: 32,
      }),
    ).toThrow(/at least 32 KiB/);
  });

  it('rejects a tag shorter than 4 bytes', () => {
    expect(() =>
      validateConfig({
        kdf: 'argon2id',
        memoryKiB: 65536,
        iterations: 3,
        parallelism: 1,
        dkLen: 2,
      }),
    ).toThrow(/at least 4 bytes/);
  });

  it('rejects a salt shorter than the specification allows', () => {
    expect(() =>
      validateConfig({
        kdf: 'argon2id',
        memoryKiB: 65536,
        iterations: 3,
        parallelism: 1,
        dkLen: 32,
        saltLen: 4,
      }),
    ).toThrow(/saltLen must be at least 8/);
  });
});

describe('unknown algorithms', () => {
  it('refuses to score an algorithm it has no cost model for', () => {
    const config = { kdf: 'bcrypt', cost: 12 } as unknown as KdfConfig;
    expect(() => validateConfig(config)).toThrow(/refuses to score an algorithm/);
  });

  it('rejects a non-object configuration', () => {
    expect(() => validateConfig(null as unknown as KdfConfig)).toThrow(/must be an object/);
  });
});

// ---------------------------------------------------------------------------
// The PBKDF2 output-length trap
// ---------------------------------------------------------------------------

describe('pbkdf2 derived key length', () => {
  const base: Pbkdf2Config = { kdf: 'pbkdf2', hash: 'sha256', iterations: 1000, dkLen: 32 };

  it('charges the defender for every output block', () => {
    const short = costOf(base);
    const long = costOf({ ...base, dkLen: 64 });
    expect(long.defenderOps).toBeGreaterThan(short.defenderOps);
    expect(long.defenderOps / short.defenderOps).toBeCloseTo(2, 2);
  });

  it('charges the attacker for exactly one output block, whatever dkLen is', () => {
    // This is the claim the naive model gets wrong. An attacker rejects a
    // wrong guess on the first block and never computes the rest.
    const lengths = [32, 33, 64, 128, 1024];
    const opCounts = lengths.map((dkLen) => costOf({ ...base, dkLen }).attackerOps);
    expect(new Set(opCounts).size).toBe(1);
  });

  it('reports a waste ratio near the block count', () => {
    expect(costOf({ ...base, dkLen: 32 }).wasteRatio).toBe(1);
    expect(costOf({ ...base, dkLen: 64 }).wasteRatio).toBeCloseTo(2, 2);
    expect(costOf({ ...base, dkLen: 128 }).wasteRatio).toBeCloseTo(4, 2);
  });

  it('reports no waste when dkLen matches the hash output', () => {
    expect(costOf({ ...base, hash: 'sha512', dkLen: 64 }).wasteRatio).toBe(1);
    expect(costOf({ ...base, hash: 'sha1', dkLen: 20 }).wasteRatio).toBe(1);
  });

  it('charges a second block for a single byte over the hash output', () => {
    // 33 bytes with SHA-256 costs the defender two full iteration loops.
    expect(costOf({ ...base, dkLen: 33 }).wasteRatio).toBeCloseTo(2, 2);
  });

  it('agrees with node:crypto that the first block does not depend on dkLen', () => {
    // The empirical basis for the whole claim: if the leading bytes were a
    // function of the total length, an attacker would have to derive the full
    // key and the extra blocks would be real cost.
    const long = pbkdf2Sync('correct horse', 'salt-value-16byt', 2048, 64, 'sha256');
    const short = pbkdf2Sync('correct horse', 'salt-value-16byt', 2048, 32, 'sha256');
    expect(long.subarray(0, 32).equals(short)).toBe(true);
  });

  it('scales the attacker figure with iterations, which is the parameter that works', () => {
    const slow = costOf({ ...base, iterations: 2000 });
    const fast = costOf({ ...base, iterations: 1000 });
    expect(slow.attackerOps / fast.attackerOps).toBeCloseTo(2, 2);
  });

  it('reports pbkdf2 as not memory hard with a fixed memory figure', () => {
    const a = costOf({ ...base, iterations: 1000 });
    const b = costOf({ ...base, iterations: 1_000_000 });
    expect(a.memoryHard).toBe(false);
    expect(a.attackerBytesPerGuess).toBe(b.attackerBytesPerGuess);
  });
});

// ---------------------------------------------------------------------------
// The scrypt parallelism trap
// ---------------------------------------------------------------------------

describe('scrypt parallelism', () => {
  it('leaves attacker memory per guess untouched as p rises', () => {
    const memories = [1, 2, 4, 16].map(
      (p) => costOf({ kdf: 'scrypt', N: 2 ** 14, r: 8, p, dkLen: 32 }).attackerBytesPerGuess,
    );
    expect(new Set(memories).size).toBe(1);
    expect(memories[0]).toBe(128 * 8 * 2 ** 14);
  });

  it('multiplies the defender critical path as p rises', () => {
    const one = costOf({ kdf: 'scrypt', N: 2 ** 14, r: 8, p: 1, dkLen: 32 });
    const sixteen = costOf(EQUAL_TIME_CHEAP);
    expect(sixteen.defenderCriticalPathOps / one.defenderCriticalPathOps).toBe(16);
  });

  it('gives the two headline configurations an identical operation count', () => {
    const cheap = costOf(EQUAL_TIME_CHEAP);
    const strong = costOf(EQUAL_TIME_STRONG);
    expect(cheap.defenderCriticalPathOps).toBe(strong.defenderCriticalPathOps);
    expect(cheap.attackerOps).toBe(strong.attackerOps);
  });

  it('separates them by sixteen times on attacker memory', () => {
    const cheap = costOf(EQUAL_TIME_CHEAP);
    const strong = costOf(EQUAL_TIME_STRONG);
    expect(strong.attackerBytesPerGuess / cheap.attackerBytesPerGuess).toBe(16);
  });

  it('separates them by sixteen times on area-time', () => {
    // Throughput on memory-bound hardware tracks the inverse of this product,
    // so this ratio is the honest statement of how much weaker the cheap
    // configuration is.
    const cheap = costOf(EQUAL_TIME_CHEAP);
    const strong = costOf(EQUAL_TIME_STRONG);
    expect(strong.attackerAreaTime / cheap.attackerAreaTime).toBe(16n);
  });

  it('reports no defender waste, because scrypt emits nothing until mixing finishes', () => {
    expect(costOf(EQUAL_TIME_CHEAP).wasteRatio).toBe(1);
    expect(costOf({ ...EQUAL_TIME_STRONG, dkLen: 64 }).wasteRatio).toBe(1);
  });

  it('scales attacker memory with r exactly as it scales with N', () => {
    const byN = costOf({ kdf: 'scrypt', N: 2 ** 15, r: 8, p: 1, dkLen: 32 });
    const byR = costOf({ kdf: 'scrypt', N: 2 ** 14, r: 16, p: 1, dkLen: 32 });
    expect(byN.attackerBytesPerGuess).toBe(byR.attackerBytesPerGuess);
  });

  it('reports defender memory above attacker memory, because the defender does not optimize', () => {
    // OpenSSL materializes all p blocks of B up front. An attacker regenerates
    // them per lane instead, so the two figures legitimately differ.
    const cost = costOf(EQUAL_TIME_CHEAP);
    expect(cost.defenderBytes).toBeGreaterThan(cost.attackerBytesPerGuess);
    expect(cost.defenderBytes).toBe(scryptRequiredBytes(2 ** 14, 8, 16));
  });
});

// ---------------------------------------------------------------------------
// The runtime ceiling
// ---------------------------------------------------------------------------

describe('scrypt runtime memory', () => {
  it('predicts the OpenSSL allocation exactly, verified against node:crypto', () => {
    // maxmem exactly equal to the prediction must work and one byte less must
    // throw. If the formula were the round 128*r*N figure, both halves of this
    // would fail.
    for (const [N, r, p] of [
      [1024, 8, 1],
      [256, 4, 2],
      [2048, 1, 3],
    ] as const) {
      const required = scryptRequiredBytes(N, r, p);
      expect(() =>
        scryptSync('pw', 'salt-value-16byt', 32, { N, r, p, maxmem: required }),
      ).not.toThrow();
      expect(() =>
        scryptSync('pw', 'salt-value-16byt', 32, { N, r, p, maxmem: required - 1 }),
      ).toThrow();
    }
  });

  it('flags the configuration that misses Node default maxmem by three kilobytes', () => {
    // N=2^15, r=8, p=1 needs 33,557,504 bytes against a 33,554,432 default.
    const required = scryptRequiredBytes(2 ** 15, 8, 1);
    expect(required).toBe(33_557_504);
    expect(required - NODE_DEFAULT_SCRYPT_MAXMEM).toBe(3072);

    const cost = costOf({ kdf: 'scrypt', N: 2 ** 15, r: 8, p: 1, dkLen: 32 });
    expect(cost.runtime.status).toBe('exceedsLimits');
    expect(cost.runtime.detail).toMatch(/ERR_CRYPTO_INVALID_SCRYPT_PARAMS/);
  });

  it('agrees with node:crypto that that configuration throws', () => {
    expect(() => scryptSync('pw', 'salt-value-16byt', 32, { N: 2 ** 15, r: 8, p: 1 })).toThrow(
      /memory limit exceeded/,
    );
  });

  it('flags the widely recommended N=2^17 configuration as unrunnable by default', () => {
    const cost = costOf({ kdf: 'scrypt', N: 2 ** 17, r: 8, p: 1, dkLen: 32 });
    expect(cost.runtime.requiredBytes).toBe(134_220_800);
    expect(cost.runtime.status).toBe('exceedsLimits');
  });

  it('accepts the same configuration once maxmem is raised', () => {
    const config: ScryptConfig = { kdf: 'scrypt', N: 2 ** 17, r: 8, p: 1, dkLen: 32 };
    const cost = costOf(config, { scryptMaxmem: scryptMaxmemFor(config) });
    expect(cost.runtime.status).toBe('withinLimits');
  });

  it('reports a maxmem that node:crypto actually accepts', () => {
    const config: ScryptConfig = { kdf: 'scrypt', N: 4096, r: 8, p: 2, dkLen: 32 };
    const maxmem = scryptMaxmemFor(config);
    expect(() =>
      scryptSync('pw', 'salt-value-16byt', 32, { N: 4096, r: 8, p: 2, maxmem }),
    ).not.toThrow();
  });

  it('rates the low-N high-p configuration as fitting the default ceiling', () => {
    // This is why the weak trade is available at all: it runs where the strong
    // one throws.
    const cheap = costOf(EQUAL_TIME_CHEAP);
    const strong = costOf(EQUAL_TIME_STRONG);
    expect(cheap.runtime.status).toBe('withinLimits');
    expect(strong.runtime.status).toBe('exceedsLimits');
  });

  it('refuses to compute a maxmem for a non-scrypt configuration', () => {
    const config = { kdf: 'pbkdf2', hash: 'sha256', iterations: 1, dkLen: 32 } as ScryptConfig &
      Pbkdf2Config;
    expect(() => scryptMaxmemFor(config)).toThrow(/expects a scrypt configuration/);
  });

  it('reports pbkdf2 as having no runtime memory gate', () => {
    const cost = costOf({ kdf: 'pbkdf2', hash: 'sha256', iterations: 600_000, dkLen: 32 });
    expect(cost.runtime.status).toBe('withinLimits');
    expect(cost.runtime.ceilingBytes).toBeNull();
  });

  it('reports argon2id runtime as unverifiable when no ceiling is stated', () => {
    // node:crypto has no Argon2, so this module says it cannot check rather
    // than assuming the parameters fit.
    const cost = costOf({
      kdf: 'argon2id',
      memoryKiB: 65536,
      iterations: 3,
      parallelism: 1,
      dkLen: 32,
    });
    expect(cost.runtime.status).toBe('notVerifiable');
  });

  it('checks argon2id against a stated ceiling', () => {
    const config: Argon2idConfig = {
      kdf: 'argon2id',
      memoryKiB: 65536,
      iterations: 3,
      parallelism: 1,
      dkLen: 32,
    };
    expect(costOf(config, { maxAllocationBytes: 64 * 1024 * 1024 }).runtime.status).toBe(
      'withinLimits',
    );
    expect(costOf(config, { maxAllocationBytes: 32 * 1024 * 1024 }).runtime.status).toBe(
      'exceedsLimits',
    );
  });
});

// ---------------------------------------------------------------------------
// Argon2id
// ---------------------------------------------------------------------------

describe('argon2id cost', () => {
  const base: Argon2idConfig = {
    kdf: 'argon2id',
    memoryKiB: 65536,
    iterations: 3,
    parallelism: 1,
    dkLen: 32,
  };

  it('counts t passes over m blocks', () => {
    const cost = costOf(base);
    expect(cost.defenderOps).toBe(3 * 65536);
    expect(cost.attackerBytesPerGuess).toBe(65536 * 1024);
  });

  it('leaves attacker cost unchanged as parallelism rises', () => {
    const one = costOf(base);
    const four = costOf({ ...base, parallelism: 4 });
    expect(four.attackerAreaTime).toBe(one.attackerAreaTime);
    expect(four.attackerOps).toBe(one.attackerOps);
  });

  it('shortens the defender critical path as parallelism rises', () => {
    const four = costOf({ ...base, parallelism: 4 });
    expect(four.defenderCriticalPathOps).toBe(four.defenderOps / 4);
  });

  it('rounds requested memory down to a multiple of 4*p and reports the real figure', () => {
    // Asking for memory that does not divide evenly gets you less than you
    // asked for, in every conforming implementation.
    const cost = costOf({ ...base, memoryKiB: 65538, parallelism: 4 });
    expect(cost.attackerBytesPerGuess).toBe(65536 * 1024);
  });

  it('carries area-time as bigint so large parameters stay exact', () => {
    const cost = costOf({
      kdf: 'argon2id',
      memoryKiB: 4_194_303,
      iterations: 4_194_303,
      parallelism: 1,
      dkLen: 32,
    });
    const blocks = 4_194_300;
    expect(cost.attackerAreaTime).toBe(BigInt(4_194_303 * blocks) * BigInt(blocks * 1024));
    // The same product as a float loses the low digits, which is why the
    // floor comparison is not done in floating point.
    expect(BigInt(Number(cost.attackerAreaTime))).not.toBe(cost.attackerAreaTime);
  });

  it('refuses parameters whose operation count leaves exact integer arithmetic', () => {
    expect(() =>
      costOf({
        kdf: 'argon2id',
        memoryKiB: 2 ** 32 - 1,
        iterations: 2 ** 32 - 1,
        parallelism: 1,
        dkLen: 32,
      }),
    ).toThrow(/past the largest integer/);
  });
});

// ---------------------------------------------------------------------------
// Descriptions and notes
// ---------------------------------------------------------------------------

describe('descriptions', () => {
  it('names every parameter that moves the cost', () => {
    expect(describeConfig(EQUAL_TIME_CHEAP)).toBe('scrypt with N=16384, r=8, p=16');
    expect(describeConfig({ kdf: 'pbkdf2', hash: 'sha256', iterations: 600_000, dkLen: 64 })).toBe(
      'PBKDF2-HMAC-SHA256 with 600000 iterations and dkLen=64',
    );
  });

  it('states what the operation count excludes', () => {
    const notes = costOf(EQUAL_TIME_CHEAP).notes.join(' ');
    expect(notes).toMatch(/Salsa20\/8/);
    expect(notes).toMatch(/excludes the PBKDF2-HMAC-SHA256 passes/);
  });

  it('states that the pbkdf2 memory figure is not a cost an attacker can be made to pay', () => {
    const notes = costOf({ kdf: 'pbkdf2', hash: 'sha256', iterations: 1000, dkLen: 32 }).notes.join(
      ' ',
    );
    expect(notes).toMatch(/Treat it as zero/);
  });
});
