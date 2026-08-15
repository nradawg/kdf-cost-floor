# kdf-cost-floor

Score password KDF parameters against a stated attacker-cost floor, and refuse the configurations that are expensive for you and cheap for whoever stole your database.

```ts
import { check, floorFrom, formatVerdict, scryptMaxmemFor } from 'kdf-cost-floor';

const config = { kdf: 'scrypt', N: 2 ** 14, r: 8, p: 16, dkLen: 32 } as const;

const verdict = check(config, floorFrom({ kdf: 'scrypt', N: 2 ** 18, r: 8, p: 1, dkLen: 32 }), {
  limits: { scryptMaxmem: scryptMaxmemFor(config) },
});

verdict.ok;        // false
console.log(formatVerdict(verdict));
```

Zero runtime dependencies. It reads parameters and derives nothing.

## Cost is not one number, and every available number is wrong differently

A validator has to reduce a configuration to something comparable. The three obvious reductions each fail, and they fail in opposite directions, so no single one of them can be patched into correctness.

### Measure time, and scrypt's `p` reads as strength

Two configurations:

```
A: N=2^14, r=8, p=16     B: N=2^18, r=8, p=1
```

Both run 4*N*r*p = 8,388,608 Salsa20/8 core invocations. Node runs the `p` passes serially inside one `scrypt` call, so both take the same wall clock, and a validator that times a derivation rates them as identical.

They are not identical. scrypt's large allocation is the V array, 128*r*N bytes. The `p` passes are independent, so an attacker runs them one after another through a single V array and never holds more than one. Memory per guess is 16 MiB for A and 256 MiB for B, and `p` does not appear in that figure at all.

That matters because memory is the binding constraint on the hardware that cracks passwords. A card with a fixed pool runs pool/bytes guesses at once, so throughput is proportional to the inverse of memory multiplied by work, the area-time product. A costs 2^47 and B costs 2^51. A is sixteen times cheaper to attack, at the same wall clock, and a time-based floor passes it.

This module reports the dimensions separately and refuses a floor that omits either one. `minAttackerBytesPerGuess` is required even when the answer is zero, because writing `0` records a decision that memory is outside your threat model, and omitting the field records nothing while producing the same verdict.

```ts
compare(A, B).criticalPathRatio;    // 1
compare(A, B).areaTimeRatio;        // 0.0625
compare(A, B).scalarDisagreement;   // true
```

### Measure the defender's work, and PBKDF2 reads as twice its real strength

PBKDF2 produces the derived key in blocks the size of the hash output, and each block costs a full run of the iteration loop. Raising `dkLen` from 32 to 64 with SHA-256 therefore doubles what the defender pays.

An attacker pays nothing for the second block. Testing a candidate password means computing T1 and comparing it against the first 32 bytes of the stored key: a wrong guess disagrees there and is discarded. Block two is computed only for a candidate that already matched, which is to say never during a search.

The claim is checkable in four lines, and the test suite checks it:

```ts
pbkdf2Sync(pw, salt, 2048, 64, 'sha256').subarray(0, 32)
  .equals(pbkdf2Sync(pw, salt, 2048, 32, 'sha256'));   // true
```

The leading bytes do not depend on the total length, so there is nothing forcing an attacker to derive the rest. A validator that credits iterations scaled by output blocks reports twice the security that exists. This module tracks `defenderOps` and `attackerOps` as separate figures and exposes their ratio as `wasteRatio`, which defaults to a hard limit of 1:

```ts
costOf({ kdf: 'pbkdf2', hash: 'sha256', iterations: 600_000, dkLen: 64 });
// defenderOps 2400002, attackerOps 1200002, wasteRatio ~2
```

The finding names the repair: set `dkLen` to 32 and raise iterations to 1,199,999, which spends the same defender budget on work an attacker actually performs.

The same logic runs the other way through `floorFrom`. A floor built from a reference configuration copies the reference's attacker cost, not its defender cost, so `floorFrom` on the wasteful PBKDF2 above produces exactly the floor it produces on the lean one. Copying the defender figure would demand 1.2 million iterations of everything measured against it, enshrining the reference's own wasted work as a requirement.

### Measure strength alone, and the verdict is fiction

A configuration that throws is not a configuration. `crypto.scrypt` takes a `maxmem` that defaults to 33,554,432 bytes, and OpenSSL compares it against 128*r*(N+p+2).

OWASP recommends scrypt at N=2^17, r=8, p=1. That needs 134,220,800 bytes, so the recommended configuration throws `ERR_CRYPTO_INVALID_SCRYPT_PARAMS` on a default Node call before deriving anything. The margin can be much thinner: N=2^15, r=8, p=1 needs 33,557,504 bytes and misses the default by 3,072. A model that reported the round 128*r*N figure would predict that one fits by exactly the amount that makes it throw, which is why the `+p+2` term is carried and why the test suite pins the formula against the real runtime at the boundary, one byte either side.

What happens after the exception is the actual risk. It arrives in production, and the repair that requires no argument with anyone is to lower N until it stops. Nobody records that a security decision was made. A green validator and a weakened deployment are the same event.

So the runtime ceiling is part of the verdict rather than a separate concern, the finding says to raise `maxmem` and not to lower N, and `scryptMaxmemFor(config)` returns the number to pass. Argon2id has no implementation in `node:crypto`, so its runtime is reported as `notVerifiable` and that fails the check by default. State `limits.maxAllocationBytes` for the implementation you actually deploy, or pass `allowUnverifiableRuntime` to accept the gap on the record.

## Defender figures and attacker figures are computed differently

One convention runs through every number here. Defender figures are what the defender pays as the deployed implementation is written. Attacker figures are lower bounds that assume the attacker optimizes: skips work the defender cannot skip, reuses buffers the defender allocates separately, and recomputes anything cheaper to recompute than to store.

The two sides do not run the same program, so they do not get the same number. scrypt's `defenderBytes` is larger than its `attackerBytesPerGuess` because OpenSSL materializes all `p` blocks of B up front while an attacker regenerates them per lane. Applying the defender's accounting to the attacker is the most common way an estimate comes out too high, and it comes out too high in exactly the cases where the gap decides the verdict.

## Operation counts carry their unit

A Salsa20/8 core and a SHA-256 compression are not the same amount of work, and the ratio between them is a property of the attacker's silicon rather than of the algorithms. Comparing a count of one against a count of the other produces a number in no unit at all, so `check` refuses:

```ts
check(scryptConfig, floorFrom(pbkdf2Config));
// KdfCostError [incomparableUnits]: ... Supply opUnitEquivalence with a
// relative cost for salsa20-8-core and sha256-compression ...
```

There is no built-in conversion table. A table shipped in a library would be a guess about hardware nobody in this process has seen, and the guess would move verdicts across the pass line without anyone choosing it. Supply `opUnitEquivalence` measured on hardware you consider representative, or state the floor in the same unit by building it from a reference in the same algorithm family.

## Everything numeric is guarded before it is compared

`NaN < 1e9` is false, and so is `NaN > 1e9`. A single NaN reaching a threshold check makes the configuration pass every test in this module without a word of complaint, which is the worst available failure for a validator. NaN gets its own error branch rather than being folded into the range check, because "expected at least 1, received NaN" reads as an ordinary out-of-range value and sends the reader looking for a small number instead of for the arithmetic that produced a non-number.

Area-time is carried as a `bigint`. The product of operations and bytes passes 2^53 at ordinary parameter sizes, and above that point a JavaScript number rounds silently in no particular direction. A rounded floor is not a floor.

## Known limitations

**Area-time is a proxy, not a cost in dollars.** It captures that a memory-bound cracker's throughput scales with the inverse of memory multiplied by work. It does not model time-memory tradeoff attacks, which let an attacker spend more computation to hold less memory, so a real attacker's cost sits somewhere below the figure reported here. Use it to compare configurations, not to predict a cracking budget.

**Operation counts are analytical, not measured.** They come from the structure of each algorithm, not from running it. They are exact in the sense that they count the right invocations, and they say nothing about how long an invocation takes on your hardware. Latency budgets are therefore stated in operations rather than milliseconds, since milliseconds change meaning when the deployment moves to a different instance type.

**The scrypt operation count excludes the PBKDF2 passes that bracket the mixing.** They are a few hundred HMAC calls next to millions of Salsa20/8 cores, and they are measured in a different unit, so adding them would produce a number in no unit. This is stated in `cost.notes` rather than buried.

**The Argon2id model rounds the first pass up.** It treats every block of every pass as one compression, and the first two blocks of each lane actually come from the initial hash. The overstatement is two blocks per lane out of `t*m`.

**`CostModel` contains a bigint, so `JSON.stringify` throws on it.** Use a replacer: `JSON.stringify(cost, (k, v) => typeof v === 'bigint' ? v.toString() : v)`.

**bcrypt is not modelled.** Its cost surface is a different shape, since its memory is a fixed 4 KiB and the interesting parameter is a work factor with a well-known input truncation, and a generic cost model applied to it would be the mistake this library exists to catch. `validateConfig` refuses unknown algorithms rather than scoring them approximately.

**This is a parameter validator, not a security review.** It says nothing about how the derived key is compared, whether the salt is unique per credential, whether a pepper is in use, or how the value reached the process.

## Test

```bash
npm install
npm test   # 118 tests
```

The tests are adversarial about the three failures above. The scrypt memory formula is pinned against `node:crypto` at the exact byte boundary, `maxmem` equal to the prediction and one byte below. The PBKDF2 claim is checked against `pbkdf2Sync` output rather than asserted. The two headline scrypt configurations are checked to have identical work and sixteen times different area-time, and a work-only floor is shown passing the weaker one, which is the naive validator's verdict reproduced as a test.

## License

MIT
