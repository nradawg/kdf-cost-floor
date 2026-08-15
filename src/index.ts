/**
 * kdf-cost-floor: validate password KDF parameters against a stated
 * attacker-cost floor, and refuse configurations that are expensive for the
 * defender and cheap for the attacker.
 *
 * Cost wants to be one number, and every available number is wrong in a
 * different direction.
 *
 * MEASURE TIME and scrypt's p parameter reads as strength. It multiplies the
 * defender's serial work and the attacker's work per guess, and leaves the
 * attacker's memory per guess exactly where it was. N=2^14, r=8, p=16 and
 * N=2^18, r=8, p=1 run the same 8,388,608 Salsa20/8 cores, so they take the
 * same wall clock. The first costs an attacker 16 MiB per guess and the
 * second costs 256 MiB. On hardware where memory is the binding constraint,
 * and on cracking hardware it always is, the first is sixteen times cheaper
 * to attack. A time-based floor passes both.
 *
 * MEASURE THE DEFENDER'S WORK and PBKDF2 reads as twice its real strength.
 * An attacker testing a candidate computes the first output block and
 * compares it against the first 32 bytes of the stored key: a wrong guess
 * disagrees there and is discarded. Blocks two and beyond are never computed
 * during a search. So raising dkLen from 32 to 64 with SHA-256 doubles the
 * defender's cost and adds exactly zero to the cost of a guess, and a
 * validator crediting iterations scaled by output blocks reports twice the
 * security that exists.
 *
 * MEASURE STRENGTH ALONE and the verdict is fiction, because it says nothing
 * about whether the configuration runs. OWASP's scrypt recommendation of
 * N=2^17, r=8, p=1 needs 134,220,800 bytes and node:crypto defaults maxmem to
 * 33,554,432, so the recommended configuration throws before deriving
 * anything. What happens next is the actual risk. The exception arrives in
 * production, and the repair that needs no argument with anyone is to lower N
 * until it stops. A green validator and a weakened deployment are the same
 * event here, which is why the runtime ceiling is checked as part of the
 * verdict rather than left to whoever is on call.
 *
 * So this module keeps the dimensions apart. Attacker work, attacker memory
 * per guess, their product, defender work, defender critical path, defender
 * memory, and runtime feasibility are seven separate figures, a floor must
 * state work and memory independently, and operation counts carry the
 * primitive they count so that a Salsa20/8 core is never quietly compared
 * against a SHA-256 compression.
 *
 * One convention runs through all of it: defender figures are what the
 * defender pays as written, attacker figures are lower bounds that assume the
 * attacker skips, reuses and recomputes wherever that is cheaper. The two
 * sides do not run the same program, so they do not get the same number.
 *
 * This is defensive tooling. It scores parameters and derives nothing.
 */

export { KdfCostError, type KdfErrorCode } from './errors.js';

export {
  MAX_SCRYPT_ALLOCATION,
  MAX_SCRYPT_RP,
  NODE_DEFAULT_SCRYPT_MAXMEM,
  costOf,
  describeConfig,
  scryptMaxmemFor,
  scryptRequiredBytes,
  validateConfig,
  type Argon2idConfig,
  type CostModel,
  type KdfConfig,
  type NormalizedConfig,
  type OpUnit,
  type Pbkdf2Config,
  type Pbkdf2Hash,
  type RuntimeAssessment,
  type RuntimeLimits,
  type RuntimeStatus,
  type ScryptConfig,
} from './model.js';

export {
  floorFrom,
  validateFloor,
  type CostFloor,
  type NormalizedFloor,
} from './floor.js';

export {
  assertFloor,
  check,
  compare,
  formatVerdict,
  type CheckOptions,
  type Comparison,
  type Finding,
  type FindingCode,
  type Verdict,
} from './check.js';
