/**
 * The floor: what an attacker must be made to pay.
 *
 * A floor in this module is deliberately not one number. The whole failure
 * this library exists to catch is a real cost surface being flattened into a
 * scalar that happens to be the wrong one, and a single-number floor API
 * would reintroduce the flattening at the point where the policy is written
 * rather than at the point where it is checked.
 *
 * So the floor states work and memory separately, and both are required.
 * There is no default for either, because the defaults would be the guess.
 */

import { KdfCostError, requireInteger, requirePositiveFinite } from './errors.js';
import { costOf, describeConfig, type CostModel, type KdfConfig, type OpUnit } from './model.js';

export interface CostFloor {
  /**
   * The primitive the operation counts below are measured in.
   *
   * Required, and checked against the configuration under test. Comparing a
   * Salsa20/8 core count against a SHA-256 compression count is comparing two
   * different amounts of work, and the conversion between them depends on the
   * hardware the attacker owns rather than on anything in the algorithms.
   */
  opUnit: OpUnit;

  /** Minimum primitive invocations an attacker must spend to reject one wrong guess. */
  minAttackerOps: number;

  /**
   * Minimum bytes an attacker must hold concurrently per in-flight guess.
   *
   * Required even when the answer is zero. Writing `0` states that memory is
   * not part of your threat model, which is a defensible position for some
   * systems and a catastrophic accident for others, and the difference is
   * whether anyone decided it. A floor that omitted this field would rate a
   * configuration using 16 MiB per guess as equal to one using 256 MiB, which
   * is the exact mistake this module was written to catch.
   */
  minAttackerBytesPerGuess: number;

  /**
   * Optional minimum for `attackerOps * attackerBytesPerGuess`.
   *
   * Throughput on memory-bound cracking hardware is proportional to the
   * inverse of this product, so it is the closest thing to an honest single
   * number, and it catches the trade that keeps both individual dimensions
   * above their floors while moving cost from the expensive one to the cheap
   * one.
   */
  minAttackerAreaTime?: number | bigint;

  /**
   * Maximum tolerated `defenderOps / attackerOps`. Defaults to 1.
   *
   * The default admits no waste at all, because waste is defender cost that
   * buys nothing, and a KDF configuration is the one place in a system where
   * spending is the entire point and spending on nothing is therefore the
   * entire failure.
   */
  maxWasteRatio?: number;

  /** Optional ceiling on bytes one defender derivation may allocate. */
  maxDefenderBytes?: number;

  /**
   * Optional ceiling on the defender's critical path, in the same op unit.
   *
   * This is a latency budget. It is stated in operations rather than
   * milliseconds because milliseconds are a property of the host, and a floor
   * that changes meaning when the deployment moves to a different instance
   * type is not a floor.
   */
  maxDefenderCriticalPathOps?: number;

  /** Optional human label, carried into verdict summaries. */
  label?: string;
}

/** A floor with defaults resolved, as `validateFloor` returns it. */
export interface NormalizedFloor {
  opUnit: OpUnit;
  minAttackerOps: number;
  minAttackerBytesPerGuess: number;
  minAttackerAreaTime: bigint | null;
  maxWasteRatio: number;
  maxDefenderBytes: number | null;
  maxDefenderCriticalPathOps: number | null;
  label: string | null;
}

const OP_UNITS: readonly OpUnit[] = [
  'sha1-compression',
  'sha256-compression',
  'sha512-compression',
  'salsa20-8-core',
  'argon2-block',
];

const FLOOR = 'invalidFloor' as const;

/**
 * Check a floor before anything is compared against it.
 *
 * Validating the floor matters more than validating the configuration. A bad
 * configuration throws at derivation time and somebody notices. A bad floor
 * passes everything quietly forever.
 */
export function validateFloor(floor: CostFloor): NormalizedFloor {
  if (floor === null || typeof floor !== 'object') {
    throw new KdfCostError(
      `A cost floor must be an object stating at minimum opUnit, ` +
        `minAttackerOps and minAttackerBytesPerGuess, but received ` +
        `${floor === null ? 'null' : typeof floor}.`,
      FLOOR,
    );
  }

  if (!OP_UNITS.includes(floor.opUnit)) {
    throw new KdfCostError(
      `opUnit is ${JSON.stringify(floor.opUnit)}, which is not one of ` +
        `${OP_UNITS.join(', ')}. An operation count without a unit cannot be ` +
        `compared against anything, so this field has no default. If you are ` +
        `unsure which unit your floor is in, build it from a reference ` +
        `configuration with floorFrom() instead of writing the numbers by hand.`,
      FLOOR,
    );
  }

  const minAttackerOps = requireInteger(floor.minAttackerOps, 'minAttackerOps', FLOOR, {
    min: 0,
    because:
      'This is a count of primitive invocations an attacker must perform per guess.',
  });

  if (floor.minAttackerBytesPerGuess === undefined) {
    throw new KdfCostError(
      `minAttackerBytesPerGuess is missing. It is required even when the value ` +
        `is zero, and that is not pedantry: a floor that omits attacker memory ` +
        `scores a scrypt configuration with N=2^14, r=8, p=16 exactly as highly ` +
        `as one with N=2^18, r=8, p=1, because the two do the same amount of ` +
        `work. The first costs an attacker 16 MiB per guess and the second costs ` +
        `256 MiB, so on memory-bound hardware the first is cracked sixteen times ` +
        `faster. State a byte count, or state 0 to record that memory is ` +
        `deliberately outside your threat model.`,
      FLOOR,
    );
  }

  const minAttackerBytesPerGuess = requireInteger(
    floor.minAttackerBytesPerGuess,
    'minAttackerBytesPerGuess',
    FLOOR,
    { min: 0, because: 'This is a byte count an attacker holds per in-flight guess.' },
  );

  const minAttackerAreaTime =
    floor.minAttackerAreaTime === undefined
      ? null
      : toAreaTime(floor.minAttackerAreaTime, 'minAttackerAreaTime');

  const maxWasteRatio =
    floor.maxWasteRatio === undefined
      ? 1
      : requirePositiveFinite(floor.maxWasteRatio, 'maxWasteRatio', FLOOR);

  if (maxWasteRatio < 1) {
    throw new KdfCostError(
      `maxWasteRatio is ${maxWasteRatio}, below 1. A ratio below 1 would mean ` +
        `the attacker performs more work than the defender, which no ` +
        `configuration achieves: the attacker runs the defender's program and ` +
        `stops early where it can. Use 1 to admit no wasted defender work, or a ` +
        `larger value to tolerate some.`,
      FLOOR,
    );
  }

  const maxDefenderBytes =
    floor.maxDefenderBytes === undefined
      ? null
      : requireInteger(floor.maxDefenderBytes, 'maxDefenderBytes', FLOOR, {
          min: 1,
          because: 'This is a ceiling on bytes one derivation may allocate.',
        });

  const maxDefenderCriticalPathOps =
    floor.maxDefenderCriticalPathOps === undefined
      ? null
      : requireInteger(
          floor.maxDefenderCriticalPathOps,
          'maxDefenderCriticalPathOps',
          FLOOR,
          { min: 1, because: 'This is a latency budget in primitive invocations.' },
        );

  // A latency budget below the work floor is deliberately NOT rejected here.
  // It looks unsatisfiable, and for scrypt and PBKDF2 it is, but Argon2id runs
  // its lanes concurrently: with p=4 the defender's critical path is a quarter
  // of the work an attacker pays for, so the combination is satisfiable by
  // exactly the configurations worth recommending. Refusing it would be this
  // module making the scalar mistake it exists to catch.

  return {
    opUnit: floor.opUnit,
    minAttackerOps,
    minAttackerBytesPerGuess,
    minAttackerAreaTime,
    maxWasteRatio,
    maxDefenderBytes,
    maxDefenderCriticalPathOps,
    label: floor.label ?? null,
  };
}

function toAreaTime(value: number | bigint, label: string): bigint {
  if (typeof value === 'bigint') {
    if (value < 0n) {
      throw new KdfCostError(`${label} must not be negative, but received ${value}n.`, FLOOR);
    }
    return value;
  }
  const asNumber = requireInteger(value, label, FLOOR, {
    min: 0,
    because:
      'Area-time is a product of operations and bytes. Pass a bigint if the ' +
      'value is above 2^53, because a rounded floor is not a floor.',
  });
  return BigInt(asNumber);
}

/**
 * Build a floor from a reference configuration: "at least as expensive to
 * attack as this".
 *
 * This is the recommended way to state a floor, because the alternative is
 * writing operation counts by hand and the hand-written numbers are where the
 * unit confusion enters.
 *
 * Note what it does with a wasteful reference. Given PBKDF2-HMAC-SHA256 with
 * 600,000 iterations and dkLen=64, the floor it produces is identical to the
 * one for dkLen=32, because it copies the reference's ATTACKER cost and the
 * two references cost an attacker the same. A floor built from the defender's
 * cost would demand 1.2 million iterations of anything measured against it,
 * enshrining the reference's own wasted work as a requirement.
 */
export function floorFrom(
  reference: KdfConfig,
  options: { maxWasteRatio?: number } = {},
): CostFloor {
  const cost: CostModel = costOf(reference);
  const floor: CostFloor = {
    opUnit: cost.opUnit,
    minAttackerOps: cost.attackerOps,
    minAttackerBytesPerGuess: cost.attackerBytesPerGuess,
    minAttackerAreaTime: cost.attackerAreaTime,
    label: `at least as expensive to attack as ${describeConfig(reference)}`,
  };
  if (options.maxWasteRatio !== undefined) {
    floor.maxWasteRatio = options.maxWasteRatio;
  }
  return floor;
}
