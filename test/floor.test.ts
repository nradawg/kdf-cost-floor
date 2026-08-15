import { describe, expect, it } from 'vitest';
import {
  KdfCostError,
  assertFloor,
  check,
  compare,
  costOf,
  floorFrom,
  formatVerdict,
  scryptMaxmemFor,
  validateFloor,
  type CostFloor,
  type FindingCode,
  type Pbkdf2Config,
  type ScryptConfig,
  type Verdict,
} from '../src/index.js';

const EQUAL_TIME_CHEAP: ScryptConfig = { kdf: 'scrypt', N: 2 ** 14, r: 8, p: 16, dkLen: 32 };
const EQUAL_TIME_STRONG: ScryptConfig = { kdf: 'scrypt', N: 2 ** 18, r: 8, p: 1, dkLen: 32 };

/** A floor stated the way a wall-clock-based validator would state it. */
const TIME_ONLY_FLOOR: CostFloor = {
  opUnit: 'salsa20-8-core',
  minAttackerOps: 8_388_608,
  minAttackerBytesPerGuess: 0,
  label: 'work only, no memory requirement',
};

function codes(verdict: Verdict): FindingCode[] {
  return verdict.findings.map((f) => f.code);
}

function failures(verdict: Verdict): FindingCode[] {
  return verdict.findings.filter((f) => f.severity === 'fail').map((f) => f.code);
}

function errorCode(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    if (error instanceof KdfCostError) return error.code;
    throw error;
  }
  throw new Error('expected the call to throw a KdfCostError, but it returned');
}

// ---------------------------------------------------------------------------
// The headline: a time-based floor approves the cheaper attack
// ---------------------------------------------------------------------------

describe('a work-only floor cannot separate the two configurations', () => {
  it('passes the configuration that is sixteen times cheaper to attack', () => {
    // The naive validator's verdict, reproduced. Both configurations clear a
    // floor stated purely in work, because they perform identical work.
    expect(check(EQUAL_TIME_CHEAP, TIME_ONLY_FLOOR).ok).toBe(true);
  });

  it('passes the strong one too, once its runtime ceiling is raised', () => {
    const verdict = check(EQUAL_TIME_STRONG, TIME_ONLY_FLOOR, {
      limits: { scryptMaxmem: scryptMaxmemFor(EQUAL_TIME_STRONG) },
    });
    expect(verdict.ok).toBe(true);
  });

  it('warns that a zero memory floor cannot tell them apart', () => {
    expect(codes(check(EQUAL_TIME_CHEAP, TIME_ONLY_FLOOR))).toContain('memoryFloorIsZero');
  });

  it('rejects the cheap configuration once the floor states memory', () => {
    const verdict = check(EQUAL_TIME_CHEAP, floorFrom(EQUAL_TIME_STRONG));
    expect(verdict.ok).toBe(false);
    expect(failures(verdict)).toContain('attackerMemoryBelowFloor');
  });

  it('rejects it on area-time as well, which is the throughput-relevant figure', () => {
    expect(failures(check(EQUAL_TIME_CHEAP, floorFrom(EQUAL_TIME_STRONG)))).toContain(
      'attackerAreaTimeBelowFloor',
    );
  });

  it('does not reject it on work, because the work really is equal', () => {
    // The finding set has to be honest about which dimension is short. Saying
    // the work is too low would send someone to raise p again.
    expect(failures(check(EQUAL_TIME_CHEAP, floorFrom(EQUAL_TIME_STRONG)))).not.toContain(
      'attackerOpsBelowFloor',
    );
  });

  it('warns that p buys no attacker memory, and names the better trade', () => {
    const verdict = check(EQUAL_TIME_CHEAP, TIME_ONLY_FLOOR);
    const warning = verdict.findings.find(
      (f) => f.code === 'parallelismBuysNoAttackerMemory',
    );
    expect(warning?.message).toMatch(/N=262144 with p=1/);
  });
});

describe('compare', () => {
  it('detects that the two scalars rank the configurations differently', () => {
    const result = compare(EQUAL_TIME_CHEAP, EQUAL_TIME_STRONG);
    expect(result.criticalPathRatio).toBe(1);
    expect(result.areaTimeRatio).toBeCloseTo(1 / 16, 6);
    expect(result.scalarDisagreement).toBe(true);
  });

  it('says plainly that a timing-based check would rate them as equivalent', () => {
    expect(compare(EQUAL_TIME_CHEAP, EQUAL_TIME_STRONG).message).toMatch(
      /would rate these as equivalent/,
    );
  });

  it('reports no disagreement when comparing a configuration with itself', () => {
    const result = compare(EQUAL_TIME_CHEAP, EQUAL_TIME_CHEAP);
    expect(result.scalarDisagreement).toBe(false);
    expect(result.areaTimeRatio).toBe(1);
  });

  it('reports no disagreement when one configuration is stronger on both scalars', () => {
    const result = compare(
      { kdf: 'scrypt', N: 2 ** 16, r: 8, p: 1, dkLen: 32 },
      { kdf: 'scrypt', N: 2 ** 14, r: 8, p: 1, dkLen: 32 },
    );
    expect(result.scalarDisagreement).toBe(false);
    expect(result.areaTimeRatio).toBeGreaterThan(1);
  });

  it('detects the same disagreement for pbkdf2 output length', () => {
    // Doubling dkLen doubles the defender's wall clock and moves attacker cost
    // not at all.
    const result = compare(
      { kdf: 'pbkdf2', hash: 'sha256', iterations: 600_000, dkLen: 64 },
      { kdf: 'pbkdf2', hash: 'sha256', iterations: 600_000, dkLen: 32 },
    );
    expect(result.criticalPathRatio).toBeCloseTo(2, 2);
    expect(result.areaTimeRatio).toBe(1);
    expect(result.scalarDisagreement).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// PBKDF2 waste
// ---------------------------------------------------------------------------

describe('defender waste', () => {
  const wasteful: Pbkdf2Config = {
    kdf: 'pbkdf2',
    hash: 'sha256',
    iterations: 600_000,
    dkLen: 64,
  };
  const lean: Pbkdf2Config = { ...wasteful, dkLen: 32 };

  it('rejects a 64 byte SHA-256 derived key by default', () => {
    expect(failures(check(wasteful, floorFrom(lean)))).toContain('defenderWasteAboveLimit');
  });

  it('accepts the same iterations at dkLen 32', () => {
    expect(check(lean, floorFrom(lean)).ok).toBe(true);
  });

  it('tells the caller what to change and by how much', () => {
    const finding = check(wasteful, floorFrom(lean)).findings.find(
      (f) => f.code === 'defenderWasteAboveLimit',
    );
    expect(finding?.message).toMatch(/Set dkLen to 32/);
    // Spend the same defender budget on work an attacker actually performs.
    expect(finding?.message).toMatch(/raise iterations to 1199999/);
  });

  it('accepts waste when the caller states a tolerance for it', () => {
    const floor = floorFrom(lean, { maxWasteRatio: 2 });
    expect(check(wasteful, floor).ok).toBe(true);
  });

  it('builds an identical floor from a wasteful reference and a lean one', () => {
    // floorFrom copies the reference's ATTACKER cost. A floor built from the
    // defender's cost would demand twice the iterations of everything measured
    // against it, enshrining the reference's own wasted work.
    const fromWasteful = floorFrom(wasteful);
    const fromLean = floorFrom(lean);
    expect(fromWasteful.minAttackerOps).toBe(fromLean.minAttackerOps);
    expect(fromWasteful.minAttackerAreaTime).toBe(fromLean.minAttackerAreaTime);
  });

  it('does not report waste for scrypt with a long derived key', () => {
    // scrypt emits no output until mixing finishes, so there is no early
    // rejection for an attacker to exploit.
    expect(costOf({ ...EQUAL_TIME_CHEAP, dkLen: 64 }).wasteRatio).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Floor validation
// ---------------------------------------------------------------------------

describe('floor validation', () => {
  it('requires an attacker memory figure even when it is zero', () => {
    const floor = { opUnit: 'salsa20-8-core', minAttackerOps: 1000 } as unknown as CostFloor;
    expect(() => validateFloor(floor)).toThrow(/minAttackerBytesPerGuess is missing/);
  });

  it('explains the omission with the configurations it would fail to separate', () => {
    const floor = { opUnit: 'salsa20-8-core', minAttackerOps: 1000 } as unknown as CostFloor;
    expect(() => validateFloor(floor)).toThrow(/sixteen times faster/);
  });

  it('accepts an explicit zero, which records a decision', () => {
    expect(() => validateFloor(TIME_ONLY_FLOOR)).not.toThrow();
  });

  it('rejects a NaN threshold, which would otherwise pass everything', () => {
    const floor: CostFloor = {
      opUnit: 'salsa20-8-core',
      minAttackerOps: Number.NaN,
      minAttackerBytesPerGuess: 0,
    };
    expect(() => validateFloor(floor)).toThrow(/every comparison against NaN is false/i);
  });

  it('would have passed a weak configuration had the NaN been admitted', () => {
    // The reason the guard exists, stated as a test: NaN comparisons are all
    // false, so the threshold check below never fires.
    const weak = costOf({ kdf: 'scrypt', N: 2, r: 1, p: 1, dkLen: 32 });
    expect(weak.attackerOps < Number.NaN).toBe(false);
  });

  it('rejects an unknown operation unit', () => {
    const floor = {
      opUnit: 'md5-compression',
      minAttackerOps: 1,
      minAttackerBytesPerGuess: 0,
    } as unknown as CostFloor;
    expect(() => validateFloor(floor)).toThrow(/is not one of/);
  });

  it('rejects a waste tolerance below 1 as describing nothing real', () => {
    const floor: CostFloor = {
      opUnit: 'salsa20-8-core',
      minAttackerOps: 1,
      minAttackerBytesPerGuess: 0,
      maxWasteRatio: 0.5,
    };
    expect(() => validateFloor(floor)).toThrow(/no configuration achieves/);
  });

  it('accepts a bigint area-time floor', () => {
    const floor: CostFloor = {
      opUnit: 'salsa20-8-core',
      minAttackerOps: 1,
      minAttackerBytesPerGuess: 0,
      minAttackerAreaTime: 2n ** 60n,
    };
    expect(validateFloor(floor).minAttackerAreaTime).toBe(2n ** 60n);
  });

  it('tags floor errors with invalidFloor', () => {
    const floor = { opUnit: 'salsa20-8-core', minAttackerOps: 1 } as unknown as CostFloor;
    expect(errorCode(() => validateFloor(floor))).toBe('invalidFloor');
  });

  it('rejects a non-object floor', () => {
    expect(() => validateFloor(null as unknown as CostFloor)).toThrow(/must be an object/);
  });

  it('defaults the waste tolerance to 1', () => {
    expect(validateFloor(TIME_ONLY_FLOOR).maxWasteRatio).toBe(1);
  });

  it('allows a latency budget below the work floor, which Argon2id can satisfy', () => {
    // Rejecting this as unsatisfiable would be the scalar mistake again: with
    // lanes running concurrently the defender's path is shorter than the work
    // an attacker pays for.
    const floor: CostFloor = {
      opUnit: 'argon2-block',
      minAttackerOps: 196_608,
      minAttackerBytesPerGuess: 67_108_864,
      maxDefenderCriticalPathOps: 50_000,
    };
    expect(() => validateFloor(floor)).not.toThrow();
    const verdict = check(
      { kdf: 'argon2id', memoryKiB: 65_536, iterations: 3, parallelism: 4, dkLen: 32 },
      floor,
      { limits: { maxAllocationBytes: 128 * 1024 * 1024 } },
    );
    expect(verdict.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Unit safety
// ---------------------------------------------------------------------------

describe('operation units', () => {
  const pbkdf2Floor = floorFrom({
    kdf: 'pbkdf2',
    hash: 'sha256',
    iterations: 1000,
    dkLen: 32,
  });

  it('refuses to compare a Salsa20/8 count against a SHA-256 count', () => {
    expect(() => check({ kdf: 'scrypt', N: 2 ** 14, r: 8, p: 1, dkLen: 32 }, pbkdf2Floor)).toThrow(
      /different amounts of work/,
    );
  });

  it('tags the refusal with incomparableUnits', () => {
    expect(
      errorCode(() => check({ kdf: 'scrypt', N: 2 ** 14, r: 8, p: 1, dkLen: 32 }, pbkdf2Floor)),
    ).toBe('incomparableUnits');
  });

  it('names both units the caller must price', () => {
    expect(() => check({ kdf: 'scrypt', N: 2 ** 14, r: 8, p: 1, dkLen: 32 }, pbkdf2Floor)).toThrow(
      /salsa20-8-core and sha256-compression/,
    );
  });

  it('compares once the caller states an equivalence', () => {
    const verdict = check({ kdf: 'scrypt', N: 2 ** 14, r: 8, p: 1, dkLen: 32 }, pbkdf2Floor, {
      opUnitEquivalence: { 'salsa20-8-core': 1, 'sha256-compression': 4 },
    });
    expect(verdict.ok).toBe(true);
  });

  it('still refuses when only one of the two units is priced', () => {
    expect(() =>
      check({ kdf: 'scrypt', N: 2 ** 14, r: 8, p: 1, dkLen: 32 }, pbkdf2Floor, {
        opUnitEquivalence: { 'salsa20-8-core': 1 },
      }),
    ).toThrow(/sha256-compression/);
  });

  it('rejects a non-positive equivalence factor', () => {
    expect(() =>
      check({ kdf: 'scrypt', N: 2 ** 14, r: 8, p: 1, dkLen: 32 }, pbkdf2Floor, {
        opUnitEquivalence: { 'salsa20-8-core': 0, 'sha256-compression': 4 },
      }),
    ).toThrow(/greater than zero/);
  });

  it('treats sha256 and sha512 as different units too', () => {
    const shaFloor = floorFrom({ kdf: 'pbkdf2', hash: 'sha512', iterations: 1000, dkLen: 64 });
    expect(() =>
      check({ kdf: 'pbkdf2', hash: 'sha256', iterations: 1000, dkLen: 32 }, shaFloor),
    ).toThrow(/different amounts of work/);
  });

  it('refuses cross-unit comparison in compare() as well', () => {
    expect(() =>
      compare(EQUAL_TIME_CHEAP, { kdf: 'pbkdf2', hash: 'sha256', iterations: 1000, dkLen: 32 }),
    ).toThrow(/different amounts of work/);
  });
});

// ---------------------------------------------------------------------------
// Runtime enforcement in the verdict
// ---------------------------------------------------------------------------

describe('runtime findings', () => {
  it('fails a configuration that will throw under the maxmem it will be called with', () => {
    const verdict = check(EQUAL_TIME_STRONG, floorFrom(EQUAL_TIME_STRONG));
    expect(verdict.ok).toBe(false);
    expect(failures(verdict)).toContain('runtimeCeilingExceeded');
  });

  it('tells the caller to raise maxmem rather than lower the cost parameter', () => {
    const finding = check(EQUAL_TIME_STRONG, floorFrom(EQUAL_TIME_STRONG)).findings.find(
      (f) => f.code === 'runtimeCeilingExceeded',
    );
    expect(finding?.message).toMatch(/Do not lower the cost parameter/);
  });

  it('passes the same configuration once maxmem is stated', () => {
    const verdict = check(EQUAL_TIME_STRONG, floorFrom(EQUAL_TIME_STRONG), {
      limits: { scryptMaxmem: scryptMaxmemFor(EQUAL_TIME_STRONG) },
    });
    expect(verdict.ok).toBe(true);
  });

  it('fails an unverifiable runtime by default', () => {
    const config = {
      kdf: 'argon2id' as const,
      memoryKiB: 65_536,
      iterations: 3,
      parallelism: 1,
      dkLen: 32,
    };
    const verdict = check(config, floorFrom(config));
    expect(failures(verdict)).toContain('runtimeUnverifiable');
  });

  it('downgrades it to a warning when the caller opts in', () => {
    const config = {
      kdf: 'argon2id' as const,
      memoryKiB: 65_536,
      iterations: 3,
      parallelism: 1,
      dkLen: 32,
    };
    const verdict = check(config, floorFrom(config), { allowUnverifiableRuntime: true });
    expect(verdict.ok).toBe(true);
    expect(codes(verdict)).toContain('runtimeUnverifiable');
  });

  it('resolves it entirely when a ceiling is stated', () => {
    const config = {
      kdf: 'argon2id' as const,
      memoryKiB: 65_536,
      iterations: 3,
      parallelism: 1,
      dkLen: 32,
    };
    const verdict = check(config, floorFrom(config), {
      limits: { maxAllocationBytes: 128 * 1024 * 1024 },
    });
    expect(verdict.ok).toBe(true);
    expect(codes(verdict)).not.toContain('runtimeUnverifiable');
  });
});

// ---------------------------------------------------------------------------
// Budgets, warnings, reporting
// ---------------------------------------------------------------------------

describe('defender budgets', () => {
  it('fails a configuration that allocates more than the budget allows', () => {
    const floor: CostFloor = {
      ...floorFrom(EQUAL_TIME_CHEAP),
      maxDefenderBytes: 1024 * 1024,
    };
    expect(failures(check(EQUAL_TIME_CHEAP, floor))).toContain('defenderBytesAboveBudget');
  });

  it('fails a configuration that exceeds the latency budget', () => {
    const floor: CostFloor = {
      ...floorFrom(EQUAL_TIME_CHEAP),
      maxDefenderCriticalPathOps: 1000,
    };
    expect(failures(check(EQUAL_TIME_CHEAP, floor))).toContain('defenderLatencyAboveBudget');
  });

  it('reports every failure at once rather than stopping at the first', () => {
    const floor: CostFloor = {
      opUnit: 'salsa20-8-core',
      minAttackerOps: 2 ** 40,
      minAttackerBytesPerGuess: 2 ** 32,
      maxDefenderBytes: 1024,
    };
    const found = failures(check({ kdf: 'scrypt', N: 1024, r: 8, p: 1, dkLen: 32 }, floor));
    expect(found).toContain('attackerOpsBelowFloor');
    expect(found).toContain('attackerMemoryBelowFloor');
    expect(found.length).toBeGreaterThanOrEqual(2);
  });
});

describe('shape warnings', () => {
  it('warns about a short salt', () => {
    const config: ScryptConfig = { ...EQUAL_TIME_CHEAP, saltLen: 8 };
    expect(codes(check(config, TIME_ONLY_FLOOR))).toContain('saltTooShort');
  });

  it('does not warn at 16 bytes', () => {
    expect(codes(check(EQUAL_TIME_CHEAP, TIME_ONLY_FLOOR))).not.toContain('saltTooShort');
  });

  it('warns that pbkdf2 can never satisfy a memory floor', () => {
    const config: Pbkdf2Config = {
      kdf: 'pbkdf2',
      hash: 'sha256',
      iterations: 600_000,
      dkLen: 32,
    };
    const floor: CostFloor = {
      opUnit: 'sha256-compression',
      minAttackerOps: 1000,
      minAttackerBytesPerGuess: 1024 * 1024,
    };
    const verdict = check(config, floor);
    expect(codes(verdict)).toContain('notMemoryHard');
    expect(failures(verdict)).toContain('attackerMemoryBelowFloor');
  });

  it('warns that argon2 rounded the requested memory down', () => {
    const verdict = check(
      { kdf: 'argon2id', memoryKiB: 65_538, iterations: 3, parallelism: 4, dkLen: 32 },
      floorFrom({ kdf: 'argon2id', memoryKiB: 65_536, iterations: 3, parallelism: 4, dkLen: 32 }),
      { limits: { maxAllocationBytes: 128 * 1024 * 1024 } },
    );
    expect(codes(verdict)).toContain('memoryRoundedDown');
  });

  it('warns that argon2 parallelism overstates cost when multiplied in', () => {
    const config = {
      kdf: 'argon2id' as const,
      memoryKiB: 65_536,
      iterations: 3,
      parallelism: 4,
      dkLen: 32,
    };
    const finding = check(config, floorFrom(config), {
      limits: { maxAllocationBytes: 128 * 1024 * 1024 },
    }).findings.find((f) => f.code === 'parallelismBuysNoAttackerMemory');
    expect(finding?.message).toMatch(/m\*t\*p overstates attacker cost/);
  });

  it('orders failures ahead of warnings', () => {
    const verdict = check(EQUAL_TIME_CHEAP, floorFrom(EQUAL_TIME_STRONG));
    const firstWarning = verdict.findings.findIndex((f) => f.severity === 'warn');
    const lastFailure = verdict.findings.map((f) => f.severity).lastIndexOf('fail');
    expect(lastFailure).toBeLessThan(firstWarning);
  });
});

describe('assertFloor', () => {
  it('returns the verdict when the floor is met', () => {
    expect(assertFloor(EQUAL_TIME_CHEAP, TIME_ONLY_FLOOR).ok).toBe(true);
  });

  it('throws with every reason listed', () => {
    let message = '';
    try {
      assertFloor(EQUAL_TIME_CHEAP, floorFrom(EQUAL_TIME_STRONG));
    } catch (error) {
      message = (error as KdfCostError).message;
    }
    expect(message).toMatch(/attackerMemoryBelowFloor/);
    expect(message).toMatch(/attackerAreaTimeBelowFloor/);
  });

  it('tags the throw with floorNotMet', () => {
    expect(errorCode(() => assertFloor(EQUAL_TIME_CHEAP, floorFrom(EQUAL_TIME_STRONG)))).toBe(
      'floorNotMet',
    );
  });

  it('names the reference the floor came from', () => {
    let message = '';
    try {
      assertFloor(EQUAL_TIME_CHEAP, floorFrom(EQUAL_TIME_STRONG));
    } catch (error) {
      message = (error as KdfCostError).message;
    }
    expect(message).toMatch(/scrypt with N=262144, r=8, p=1/);
  });
});

describe('reporting', () => {
  it('summarizes a pass with the warning count', () => {
    const verdict = check(EQUAL_TIME_CHEAP, TIME_ONLY_FLOOR);
    expect(verdict.summary).toMatch(/meets the stated cost floor/);
    expect(verdict.summary).toMatch(/warnings worth reading/);
  });

  it('summarizes a failure with the failure count', () => {
    const verdict = check(EQUAL_TIME_CHEAP, floorFrom(EQUAL_TIME_STRONG));
    expect(verdict.summary).toMatch(/does not meet/);
    expect(verdict.summary).toMatch(/2 failures/);
  });

  it('formats a report carrying both cost dimensions', () => {
    const text = formatVerdict(check(EQUAL_TIME_CHEAP, floorFrom(EQUAL_TIME_STRONG)));
    expect(text).toMatch(/^FAIL: scrypt with N=16384, r=8, p=16/);
    expect(text).toMatch(/memory 16777216 bytes per guess/);
    expect(text).toMatch(/area-time 140737488355328/);
  });

  it('formats a passing report', () => {
    expect(formatVerdict(check(EQUAL_TIME_CHEAP, TIME_ONLY_FLOOR))).toMatch(/^PASS:/);
  });
});
