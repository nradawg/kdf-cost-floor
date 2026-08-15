/**
 * The verdict.
 *
 * `check` reports every reason a configuration falls short, not the first
 * one. A validator that stops at the first failure turns tuning into a series
 * of single-parameter nudges, and the nudge that clears one threshold is
 * usually the nudge that quietly breaks another: raising p to clear a work
 * floor is free memory-wise, and lowering N to clear a runtime ceiling is
 * free latency-wise, and doing both leaves a configuration that passes every
 * check it is shown one at a time.
 */

import { KdfCostError, requirePositiveFinite } from './errors.js';
import { validateFloor, type CostFloor, type NormalizedFloor } from './floor.js';
import {
  costOf,
  describeConfig,
  validateConfig,
  type CostModel,
  type KdfConfig,
  type NormalizedConfig,
  type OpUnit,
  type RuntimeLimits,
} from './model.js';

export type FindingCode =
  | 'attackerOpsBelowFloor'
  | 'attackerMemoryBelowFloor'
  | 'attackerAreaTimeBelowFloor'
  | 'defenderWasteAboveLimit'
  | 'defenderBytesAboveBudget'
  | 'defenderLatencyAboveBudget'
  | 'runtimeCeilingExceeded'
  | 'runtimeUnverifiable'
  | 'memoryFloorIsZero'
  | 'parallelismBuysNoAttackerMemory'
  | 'notMemoryHard'
  | 'saltTooShort'
  | 'memoryRoundedDown';

export interface Finding {
  code: FindingCode;
  severity: 'fail' | 'warn';
  /** What went wrong, why it matters, and what to do, in full sentences. */
  message: string;
}

export interface Verdict {
  ok: boolean;
  config: NormalizedConfig;
  cost: CostModel;
  floor: NormalizedFloor;
  /** Failures first, then warnings. */
  findings: Finding[];
  summary: string;
}

export interface CheckOptions {
  limits?: RuntimeLimits;
  /**
   * Accept a configuration whose runtime feasibility this module cannot
   * verify. Off by default: an unverified runtime is how an approved
   * configuration becomes an exception in production.
   */
  allowUnverifiableRuntime?: boolean;
  /**
   * Relative cost of each operation unit, in whatever common unit you choose.
   *
   * Needed only when the floor and the configuration are measured in
   * different primitives. There is no built-in table, because the ratio
   * between a Salsa20/8 core and a SHA-256 compression is a fact about the
   * attacker's silicon, and a table shipped in a library would be a guess
   * about hardware nobody in this process has seen.
   */
  opUnitEquivalence?: Partial<Record<OpUnit, number>>;
}

/** Score a configuration against a floor. Never throws for being below the floor. */
export function check(
  config: KdfConfig,
  floor: CostFloor,
  options: CheckOptions = {},
): Verdict {
  const normalizedConfig = validateConfig(config);
  const normalizedFloor = validateFloor(floor);
  const cost = costOf(config, options.limits ?? {});

  const scale = unitScale(cost.opUnit, normalizedFloor.opUnit, options.opUnitEquivalence);

  const fails: Finding[] = [];
  const warns: Finding[] = [];

  // --- attacker work ------------------------------------------------------

  const attackerOpsScaled = cost.attackerOps * scale.config;
  const floorOpsScaled = normalizedFloor.minAttackerOps * scale.floor;
  if (attackerOpsScaled < floorOpsScaled) {
    fails.push({
      code: 'attackerOpsBelowFloor',
      severity: 'fail',
      message:
        `An attacker rejects a wrong guess after ${cost.attackerOps} ${cost.opUnit} ` +
        `invocations, below the floor of ${normalizedFloor.minAttackerOps} ` +
        `${normalizedFloor.opUnit}${scale.described}. Note that this counts the work ` +
        `to reject a guess, which is less than the work to complete a derivation ` +
        `whenever the derived key spans more than one output block. Raise the ` +
        `work parameter (iterations for PBKDF2, N for scrypt, t for Argon2id) ` +
        `rather than the output length.`,
    });
  }

  // --- attacker memory ----------------------------------------------------

  if (cost.attackerBytesPerGuess < normalizedFloor.minAttackerBytesPerGuess) {
    fails.push({
      code: 'attackerMemoryBelowFloor',
      severity: 'fail',
      message:
        `An attacker holds ${cost.attackerBytesPerGuess} bytes per in-flight ` +
        `guess, below the floor of ${normalizedFloor.minAttackerBytesPerGuess}. ` +
        `Memory per guess divides an attacker's parallelism directly: a cracking ` +
        `device with a fixed pool runs pool/bytes guesses at once, so this figure ` +
        `sets throughput more sharply than the work count does. ` +
        `${memoryAdvice(normalizedConfig)}`,
    });
  }

  if (normalizedFloor.minAttackerBytesPerGuess === 0) {
    warns.push({
      code: 'memoryFloorIsZero',
      severity: 'warn',
      message:
        `This floor requires no attacker memory at all, so it cannot tell a ` +
        `memory-hard configuration from a fast one that happens to run for the ` +
        `same length of time. That is a coherent policy only if you have decided ` +
        `that your attacker is compute-bound rather than memory-bound. If you ` +
        `have not decided, build the floor from a reference configuration with ` +
        `floorFrom() so the memory dimension comes from something real.`,
    });
  }

  if (!cost.memoryHard && normalizedFloor.minAttackerBytesPerGuess > 0) {
    warns.push({
      code: 'notMemoryHard',
      severity: 'warn',
      message:
        `${describeConfig(normalizedConfig)} has no memory parameter, so no ` +
        `setting of it will ever meet a memory floor. Its ` +
        `${cost.attackerBytesPerGuess} bytes are fixed hash state, not a cost an ` +
        `attacker can be made to pay more of. If a memory floor is part of your ` +
        `threat model, this algorithm cannot satisfy it and tuning will not help.`,
    });
  }

  // --- area-time ----------------------------------------------------------

  if (normalizedFloor.minAttackerAreaTime !== null) {
    // Scaling a bigint by a fractional factor would round, so the comparison
    // is done in floating point only when a conversion is actually in play.
    const below =
      scale.identity
        ? cost.attackerAreaTime < normalizedFloor.minAttackerAreaTime
        : Number(cost.attackerAreaTime) * scale.config <
          Number(normalizedFloor.minAttackerAreaTime) * scale.floor;

    if (below) {
      fails.push({
        code: 'attackerAreaTimeBelowFloor',
        severity: 'fail',
        message:
          `The attacker's area-time product is ${cost.attackerAreaTime}, below the ` +
          `floor of ${normalizedFloor.minAttackerAreaTime}${scale.described}. ` +
          `Throughput on memory-bound hardware is proportional to the inverse of ` +
          `this product, so a shortfall here means guesses per second that the ` +
          `separate work and memory figures did not predict. This check is the one ` +
          `that catches cost moved out of memory and into work at a constant wall ` +
          `clock, which is the cheapest weakening available and the hardest to see.`,
      });
    }
  }

  // --- defender waste -----------------------------------------------------

  if (cost.wasteRatio > normalizedFloor.maxWasteRatio) {
    fails.push({
      code: 'defenderWasteAboveLimit',
      severity: 'fail',
      message:
        `The defender performs ${cost.defenderOps} ${cost.opUnit} invocations per ` +
        `derivation while an attacker performs ${cost.attackerOps} per guess, a ` +
        `ratio of ${formatRatio(cost.wasteRatio)} against a limit of ` +
        `${formatRatio(normalizedFloor.maxWasteRatio)}. ${wasteAdvice(normalizedConfig, cost)}`,
    });
  }

  // --- defender budgets ---------------------------------------------------

  if (
    normalizedFloor.maxDefenderBytes !== null &&
    cost.defenderBytes > normalizedFloor.maxDefenderBytes
  ) {
    fails.push({
      code: 'defenderBytesAboveBudget',
      severity: 'fail',
      message:
        `One derivation allocates ${cost.defenderBytes} bytes against a budget of ` +
        `${normalizedFloor.maxDefenderBytes}. Multiply this by the number of ` +
        `logins you serve concurrently before deciding it is affordable: memory ` +
        `hardness is a cost you pay per simultaneous authentication, and a login ` +
        `stampede is the moment it lands.`,
    });
  }

  if (
    normalizedFloor.maxDefenderCriticalPathOps !== null &&
    cost.defenderCriticalPathOps > normalizedFloor.maxDefenderCriticalPathOps
  ) {
    fails.push({
      code: 'defenderLatencyAboveBudget',
      severity: 'fail',
      message:
        `The defender's critical path is ${cost.defenderCriticalPathOps} ` +
        `${cost.opUnit} invocations against a budget of ` +
        `${normalizedFloor.maxDefenderCriticalPathOps}. Reduce the work parameter ` +
        `and accept the lower attacker cost, or reduce waste if the ratio above is ` +
        `greater than 1, which buys latency back at no cost to security.`,
    });
  }

  // --- runtime ------------------------------------------------------------

  if (cost.runtime.status === 'exceedsLimits') {
    fails.push({
      code: 'runtimeCeilingExceeded',
      severity: 'fail',
      message:
        `${cost.runtime.detail} This is a deployment failure rather than a ` +
        `strength problem: the parameters are strong and the ceiling is too low. ` +
        `Raise the ceiling. Do not lower the cost parameter until the exception ` +
        `stops, which is the repair that presents itself at three in the morning ` +
        `and weakens every password in the database by the same factor, with no ` +
        `record that a security decision was made.`,
    });
  }

  if (cost.runtime.status === 'notVerifiable') {
    if (options.allowUnverifiableRuntime === true) {
      warns.push({
        code: 'runtimeUnverifiable',
        severity: 'warn',
        message:
          `${cost.runtime.detail} You passed allowUnverifiableRuntime, so this is ` +
          `recorded rather than enforced. Verify against the implementation you ` +
          `deploy before trusting the verdict.`,
      });
    } else {
      fails.push({
        code: 'runtimeUnverifiable',
        severity: 'fail',
        message:
          `${cost.runtime.detail} A verdict that skips the runtime check is a ` +
          `verdict about a configuration that may never run, and the version that ` +
          `does run is whatever someone edited it into after the first exception.`,
      });
    }
  }

  // --- shape warnings -----------------------------------------------------

  warns.push(...shapeWarnings(normalizedConfig, cost));

  const findings = [...fails, ...warns];
  const ok = fails.length === 0;

  return {
    ok,
    config: normalizedConfig,
    cost,
    floor: normalizedFloor,
    findings,
    summary: summarize(normalizedConfig, normalizedFloor, ok, fails.length, warns.length),
  };
}

/** `check`, but throws a KdfCostError listing every failure. For startup guards. */
export function assertFloor(
  config: KdfConfig,
  floor: CostFloor,
  options: CheckOptions = {},
): Verdict {
  const verdict = check(config, floor, options);
  if (!verdict.ok) {
    const reasons = verdict.findings
      .filter((f) => f.severity === 'fail')
      .map((f, i) => `${i + 1}. [${f.code}] ${f.message}`)
      .join('\n');
    throw new KdfCostError(
      `${describeConfig(config)} does not meet the stated cost floor` +
        `${verdict.floor.label === null ? '' : ` (${verdict.floor.label})`}.\n${reasons}`,
      'floorNotMet',
    );
  }
  return verdict;
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

export interface Comparison {
  /** Above 1 when A costs the defender more wall clock than B. */
  criticalPathRatio: number;
  /** Above 1 when A costs an attacker more than B. */
  areaTimeRatio: number;
  /**
   * True when ranking by defender wall clock disagrees with ranking by
   * attacker cost, which is the condition under which a timing-based
   * validator approves the weaker of two configurations.
   */
  scalarDisagreement: boolean;
  message: string;
}

/**
 * Compare two configurations on both scalars at once.
 *
 * The interesting output is `scalarDisagreement`. Two scrypt configurations
 * can sit at the same wall clock while one costs an attacker sixteen times
 * less, and every validator that measures "how long does a derivation take"
 * rates them as equal.
 */
export function compare(
  a: KdfConfig,
  b: KdfConfig,
  options: { limits?: RuntimeLimits; opUnitEquivalence?: Partial<Record<OpUnit, number>> } = {},
): Comparison {
  const costA = costOf(a, options.limits ?? {});
  const costB = costOf(b, options.limits ?? {});
  const scale = unitScale(costA.opUnit, costB.opUnit, options.opUnitEquivalence);

  const criticalPathRatio =
    (costA.defenderCriticalPathOps * scale.config) / (costB.defenderCriticalPathOps * scale.floor);
  const areaTimeRatio =
    (Number(costA.attackerAreaTime) * scale.config) /
    (Number(costB.attackerAreaTime) * scale.floor);

  const timeRank = rank(criticalPathRatio);
  const costRank = rank(areaTimeRatio);
  const scalarDisagreement = timeRank !== costRank;

  const labelA = describeConfig(a);
  const labelB = describeConfig(b);

  let message: string;
  if (!scalarDisagreement) {
    message =
      `${labelA} and ${labelB} are ranked the same way by defender wall clock ` +
      `(ratio ${formatRatio(criticalPathRatio)}) and by attacker area-time ` +
      `(ratio ${formatRatio(areaTimeRatio)}), so a timing-based check would reach ` +
      `the same conclusion this one does.`;
  } else {
    const cheaper = areaTimeRatio < 1 ? labelA : labelB;
    const factor = areaTimeRatio < 1 ? 1 / areaTimeRatio : areaTimeRatio;
    message =
      `These two configurations rank differently on the two scalars. The defender ` +
      `wall clock ratio is ${formatRatio(criticalPathRatio)} while the attacker ` +
      `area-time ratio is ${formatRatio(areaTimeRatio)}, so ${cheaper} is about ` +
      `${formatRatio(factor)} times cheaper to attack than the other while costing ` +
      `the defender no more. A validator that scores configurations by how long a ` +
      `derivation takes would rate these as equivalent, or would prefer the weaker ` +
      `one. Compare on attacker area-time instead.`;
  }

  return { criticalPathRatio, areaTimeRatio, scalarDisagreement, message };
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/** A plain-text report, for CI output and for pasting into a review. */
export function formatVerdict(verdict: Verdict): string {
  const { cost } = verdict;
  const lines: string[] = [
    `${verdict.ok ? 'PASS' : 'FAIL'}: ${describeConfig(verdict.config)}`,
    verdict.floor.label === null ? 'Floor: stated directly' : `Floor: ${verdict.floor.label}`,
    '',
    `Defender  work ${cost.defenderOps} ${cost.opUnit}, critical path ` +
      `${cost.defenderCriticalPathOps}, memory ${cost.defenderBytes} bytes`,
    `Attacker  work ${cost.attackerOps} per guess, memory ${cost.attackerBytesPerGuess} ` +
      `bytes per guess, area-time ${cost.attackerAreaTime}`,
    `Waste     ${formatRatio(cost.wasteRatio)} (defender work divided by attacker work)`,
    `Runtime   ${cost.runtime.status}: ${cost.runtime.detail}`,
    '',
  ];

  if (verdict.findings.length === 0) {
    lines.push('No findings.');
  } else {
    for (const finding of verdict.findings) {
      lines.push(`[${finding.severity}] ${finding.code}`);
      lines.push(`  ${finding.message}`);
    }
  }

  lines.push('', 'Notes:');
  for (const note of cost.notes) lines.push(`  ${note}`);

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

interface UnitScale {
  /** Multiplier applied to the configuration's operation counts. */
  config: number;
  /** Multiplier applied to the floor's operation counts. */
  floor: number;
  /** True when both sides are already in the same unit. */
  identity: boolean;
  /** A clause naming the conversion, empty when none was needed. */
  described: string;
}

function unitScale(
  configUnit: OpUnit,
  floorUnit: OpUnit,
  equivalence: Partial<Record<OpUnit, number>> | undefined,
): UnitScale {
  if (configUnit === floorUnit) {
    return { config: 1, floor: 1, identity: true, described: '' };
  }

  const configFactor = equivalence?.[configUnit];
  const floorFactor = equivalence?.[floorUnit];

  if (configFactor === undefined || floorFactor === undefined) {
    const missing = [
      configFactor === undefined ? configUnit : null,
      floorFactor === undefined ? floorUnit : null,
    ].filter((unit): unit is OpUnit => unit !== null);

    throw new KdfCostError(
      `This configuration's cost is measured in ${configUnit} invocations and the ` +
        `floor is stated in ${floorUnit} invocations, which are different amounts ` +
        `of work. The ratio between them depends on the hardware the attacker ` +
        `owns, so this module will not assume one: a factor guessed here would ` +
        `move a verdict across the pass line without anyone choosing it. Supply ` +
        `opUnitEquivalence with a relative cost for ${missing.join(' and ')}, ` +
        `measured on hardware you consider representative, or state the floor in ` +
        `the same unit by building it from a reference configuration using the ` +
        `same algorithm family.`,
      'incomparableUnits',
    );
  }

  return {
    config: requirePositiveFinite(
      configFactor,
      `opUnitEquivalence.${configUnit}`,
      'incomparableUnits',
    ),
    floor: requirePositiveFinite(
      floorFactor,
      `opUnitEquivalence.${floorUnit}`,
      'incomparableUnits',
    ),
    identity: false,
    described: ` (converted using the stated ${configUnit} to ${floorUnit} equivalence)`,
  };
}

function shapeWarnings(config: NormalizedConfig, cost: CostModel): Finding[] {
  const findings: Finding[] = [];

  if (config.saltLen < 16) {
    findings.push({
      code: 'saltTooShort',
      severity: 'warn',
      message:
        `The salt is ${config.saltLen} bytes. Salts do not need to be secret but ` +
        `they do need to be unique across every stored credential, and at ` +
        `${config.saltLen} bytes a collision within a large user table stops being ` +
        `negligible, which lets one cracking run cover several accounts. Use 16 ` +
        `random bytes.`,
    });
  }

  if (config.kdf === 'scrypt' && config.p > 1) {
    const alternative = config.N * config.p;
    findings.push({
      code: 'parallelismBuysNoAttackerMemory',
      severity: 'warn',
      message:
        `p is ${config.p}, so this configuration costs the defender ${config.p} ` +
        `times the wall clock of the same N at p=1 while an attacker still holds ` +
        `only ${cost.attackerBytesPerGuess} bytes per guess. Setting N=${alternative} ` +
        `with p=1 costs the defender the same number of operations and raises ` +
        `attacker memory per guess by ${config.p} times, so it is the better trade ` +
        `whenever the defender can afford the memory. Use p above 1 only when a ` +
        `deliberate memory ceiling forces it, and record that the ceiling, not the ` +
        `cost target, is what set p.`,
    });
  }

  if (config.kdf === 'argon2id') {
    if (config.parallelism > 1) {
      findings.push({
        code: 'parallelismBuysNoAttackerMemory',
        severity: 'warn',
        message:
          `p is ${config.parallelism}, which lets the defender finish in about ` +
          `${cost.defenderCriticalPathOps} sequential block compressions instead of ` +
          `${cost.defenderOps}. An attacker pays the full ${cost.defenderOps} either ` +
          `way, so parallelism is a latency discount for the defender and nothing ` +
          `for the attacker. It is a good trade, but do not count it as cost: ` +
          `m*t*p overstates attacker cost by a factor of p.`,
      });
    }

    const granularity = 4 * config.parallelism;
    const used = Math.floor(config.memoryKiB / granularity) * granularity;
    if (used !== config.memoryKiB) {
      findings.push({
        code: 'memoryRoundedDown',
        severity: 'warn',
        message:
          `Argon2 rounds memory down to a multiple of 4*p blocks, so m=${config.memoryKiB} ` +
          `KiB with p=${config.parallelism} actually allocates ${used} KiB and the ` +
          `remaining ${config.memoryKiB - used} KiB are neither allocated nor charged ` +
          `to the attacker. Every figure here reflects the ${used} KiB that is really ` +
          `used. Set m to a multiple of ${granularity} to get what you asked for.`,
      });
    }
  }

  return findings;
}

function memoryAdvice(config: NormalizedConfig): string {
  switch (config.kdf) {
    case 'scrypt':
      return (
        `For scrypt, attacker memory is 128*r*N bytes and does not depend on p, ` +
        `so raise N or r. Raising p raises cost figures that are not this one.`
      );
    case 'argon2id':
      return 'For Argon2id, raise m. Raising t or p leaves memory per guess unchanged.';
    case 'pbkdf2':
      return (
        `PBKDF2 has no memory parameter, so no change to this configuration will ` +
        `meet a memory floor. Move to scrypt or Argon2id.`
      );
  }
}

function wasteAdvice(config: NormalizedConfig, cost: CostModel): string {
  if (config.kdf === 'pbkdf2') {
    const hashBytes = config.hash === 'sha1' ? 20 : config.hash === 'sha256' ? 32 : 64;
    return (
      `PBKDF2 derives its output in ${hashBytes} byte blocks, each costing a full ` +
      `run of the iteration loop, and an attacker computes only the first one ` +
      `because a wrong guess disagrees with the stored key there. A dkLen of ` +
      `${config.dkLen} with ${config.hash.toUpperCase()} therefore charges the ` +
      `defender for ${Math.ceil(config.dkLen / hashBytes)} loops and the attacker ` +
      `for one. Set dkLen to ${hashBytes} and raise iterations to ` +
      `${Math.round(config.iterations * cost.wasteRatio)} to spend the same defender ` +
      `budget on cost an attacker actually pays.`
    );
  }
  return (
    `Defender work above attacker work is budget spent on nothing. Find the ` +
    `parameter driving the difference and move that spending into the work ` +
    `parameter instead.`
  );
}

function summarize(
  config: NormalizedConfig,
  floor: NormalizedFloor,
  ok: boolean,
  fails: number,
  warns: number,
): string {
  const subject = describeConfig(config);
  const against =
    floor.label === null ? 'the stated cost floor' : `the stated cost floor (${floor.label})`;
  if (ok) {
    return warns === 0
      ? `${subject} meets ${against}.`
      : `${subject} meets ${against}, with ${warns} warning${warns === 1 ? '' : 's'} worth reading before you ship it.`;
  }
  return (
    `${subject} does not meet ${against}: ${fails} failure${fails === 1 ? '' : 's'}` +
    `${warns === 0 ? '' : ` and ${warns} warning${warns === 1 ? '' : 's'}`}.`
  );
}

/** Rank a ratio against 1, with a tolerance band so float noise is not a disagreement. */
function rank(ratio: number, tolerance = 0.02): -1 | 0 | 1 {
  if (ratio > 1 + tolerance) return 1;
  if (ratio < 1 - tolerance) return -1;
  return 0;
}

function formatRatio(value: number): string {
  if (Number.isInteger(value)) return String(value);
  if (value >= 100) return value.toFixed(0);
  if (value >= 10) return value.toFixed(1);
  return value.toFixed(3).replace(/0+$/, '').replace(/\.$/, '');
}
