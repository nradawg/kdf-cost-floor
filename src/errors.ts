/**
 * Errors and numeric guards.
 *
 * Every number that crosses this module's API boundary is checked before it
 * is used in a comparison. That is not defensive habit, it is the difference
 * between a floor and a decoration: `NaN < 1e9` is `false`, and so is
 * `NaN > 1e9`, so a single NaN reaching a threshold check makes the
 * configuration pass every test in this module without a word of complaint.
 * A tokenizer bug, a `parseInt` on an empty environment variable, or a
 * division by a zero-valued default all produce one, and the failure mode is
 * a green validator over a weakened deployment.
 */

export type KdfErrorCode =
  /** The KDF parameters are not a configuration any implementation will run. */
  | 'invalidConfig'
  /** The stated floor is not a floor that can be checked against. */
  | 'invalidFloor'
  /** Two cost figures were measured in different units and no conversion was given. */
  | 'incomparableUnits'
  /** `assertFloor` found the configuration below the stated floor. */
  | 'floorNotMet';

export class KdfCostError extends Error {
  readonly code: KdfErrorCode;

  constructor(message: string, code: KdfErrorCode) {
    super(message);
    this.name = 'KdfCostError';
    this.code = code;
  }
}

export interface IntegerRange {
  min: number;
  max?: number;
  /** Appended to the error, saying why the bound exists and what to do. */
  because?: string;
}

/**
 * Accept a value only if it is an exact, finite, in-range integer.
 *
 * The NaN and Infinity cases get their own branches on purpose. Folding them
 * into the range check would produce "expected at least 1, received NaN",
 * which reads as an ordinary out-of-range value and sends the caller looking
 * for a small number instead of for the arithmetic that produced a
 * non-number.
 */
export function requireInteger(
  value: unknown,
  label: string,
  code: KdfErrorCode,
  range: IntegerRange,
): number {
  const why = range.because === undefined ? '' : ` ${range.because}`;

  if (typeof value !== 'number') {
    throw new KdfCostError(
      `${label} must be a number, but received ${describeType(value)}. ` +
        `Cost thresholds are compared numerically, and a non-number silently ` +
        `fails every comparison rather than raising one, so it is rejected here ` +
        `instead of being coerced. Supply ${label} as a number.${why}`,
      code,
    );
  }

  if (Number.isNaN(value)) {
    throw new KdfCostError(
      `${label} is NaN. This matters more than an ordinary bad value: every ` +
        `comparison against NaN is false, so a NaN threshold would report the ` +
        `configuration as meeting the floor no matter how weak it is. NaN ` +
        `usually arrives from a division by an absent value or from parsing an ` +
        `empty string, so check where ${label} was computed rather than ` +
        `clamping it.`,
      code,
    );
  }

  if (!Number.isFinite(value)) {
    throw new KdfCostError(
      `${label} is ${value === Infinity ? 'Infinity' : '-Infinity'}, which is ` +
        `not a cost any real machine pays. An infinite threshold rejects every ` +
        `configuration and an infinite parameter describes a derivation that ` +
        `never returns. State a finite value for ${label}.${why}`,
      code,
    );
  }

  if (!Number.isInteger(value)) {
    throw new KdfCostError(
      `${label} must be a whole number, but received ${value}. Iteration ` +
        `counts, block sizes and byte counts are integers in every KDF ` +
        `specification, and rounding one here would mean this module scores a ` +
        `configuration that differs from the one the runtime will execute. ` +
        `Round ${label} yourself so the rounding is visible in your code.${why}`,
      code,
    );
  }

  if (value < range.min) {
    throw new KdfCostError(
      `${label} must be at least ${range.min}, but received ${value}.${why}`,
      code,
    );
  }

  if (range.max !== undefined && value > range.max) {
    throw new KdfCostError(
      `${label} must be at most ${range.max}, but received ${value}.${why}`,
      code,
    );
  }

  return value;
}

/**
 * Reject a computed quantity that has grown past exact integer arithmetic.
 *
 * Above 2^53 a JavaScript number silently rounds, and the rounding is not
 * conservative in any particular direction. A cost model that reports a
 * rounded operation count is reporting a configuration nobody asked for, so
 * this refuses rather than returns an approximation. Area-time products,
 * which overflow at ordinary parameter sizes, are carried as bigint instead
 * of being guarded this way.
 */
export function requireExactInteger(value: number, label: string, code: KdfErrorCode): number {
  if (!Number.isSafeInteger(value)) {
    throw new KdfCostError(
      `${label} computes to ${value}, which is past the largest integer a ` +
        `JavaScript number represents exactly (${Number.MAX_SAFE_INTEGER}). ` +
        `Beyond that point arithmetic rounds silently, so this module would be ` +
        `scoring a configuration slightly different from the one you passed. ` +
        `These parameters describe a derivation far beyond any practical ` +
        `runtime, so reduce them rather than working around this.`,
      code,
    );
  }
  return value;
}

/** A positive, finite, possibly fractional number: used for ratios and scale factors. */
export function requirePositiveFinite(value: unknown, label: string, code: KdfErrorCode): number {
  if (typeof value !== 'number') {
    throw new KdfCostError(
      `${label} must be a number, but received ${describeType(value)}. ` +
        `Supply ${label} as a positive number.`,
      code,
    );
  }
  if (Number.isNaN(value)) {
    throw new KdfCostError(
      `${label} is NaN, and every comparison against NaN is false, so it would ` +
        `disable the check it participates in rather than tighten or loosen it. ` +
        `Check where ${label} was computed.`,
      code,
    );
  }
  if (!Number.isFinite(value) || value <= 0) {
    throw new KdfCostError(
      `${label} must be a finite number greater than zero, but received ${value}.`,
      code,
    );
  }
  return value;
}

function describeType(value: unknown): string {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  if (typeof value === 'string') return `the string ${JSON.stringify(value)}`;
  if (typeof value === 'bigint') return `the bigint ${value}n`;
  return `a value of type ${typeof value}`;
}
