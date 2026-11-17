/**
 * Age floor for the "age_gate:N" claims (N = 13..21, chosen by the app). Pure and tested.
 * The date of birth is read only to compute whole years at this moment, capped at AGE_FLOOR_CAP;
 * the date itself is never returned, stored or logged. Ages only grow, so a stored floor can only
 * under-state the age later: an "over N" answer from an old attestation fails closed.
 */
export const AGE_GATE_MIN = 13;
export const AGE_FLOOR_CAP = 21;

const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** Whole years between an ISO date of birth (YYYY-MM-DD) and `now` (UTC), capped at 21; null when unusable. */
export function ageFloorFromBirthDate(dob: unknown, now: Date = new Date()): number | null {
  if (typeof dob !== "string") return null;
  const m = ISO_DATE.exec(dob.trim());
  if (!m) return null;
  const y = Number(m[1]);
  const mo = Number(m[2]);
  const d = Number(m[3]);
  const birth = new Date(Date.UTC(y, mo - 1, d));
  // Reject impossible calendar dates such as 2001-02-30.
  if (birth.getUTCFullYear() !== y || birth.getUTCMonth() !== mo - 1 || birth.getUTCDate() !== d) return null;
  if (birth.getTime() > now.getTime()) return null;
  let years = now.getUTCFullYear() - y;
  const beforeBirthday = now.getUTCMonth() < mo - 1 || (now.getUTCMonth() === mo - 1 && now.getUTCDate() < d);
  if (beforeBirthday) years -= 1;
  if (years < 0 || years > 130) return null;
  return Math.min(years, AGE_FLOOR_CAP);
}

/** True only when the attested floor proves the member is at least `min` years old. */
export function ageGatePasses(ageFloor: number | null | undefined, min: number): boolean {
  if (!Number.isInteger(min) || min < AGE_GATE_MIN || min > AGE_FLOOR_CAP) return false;
  return typeof ageFloor === "number" && Number.isInteger(ageFloor) && ageFloor >= min;
}
