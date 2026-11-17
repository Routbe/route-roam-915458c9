import { describe, expect, it } from "vitest";
import { ageFloorFromBirthDate, ageGatePasses } from "./age-floor";

const NOW = new Date(Date.UTC(2026, 10, 17)); // 2026-11-17

describe("ageFloorFromBirthDate", () => {
  it("counts whole years and turns a year older on the birthday itself", () => {
    expect(ageFloorFromBirthDate("2008-11-17", NOW)).toBe(18);
    expect(ageFloorFromBirthDate("2008-11-18", NOW)).toBe(17);
    expect(ageFloorFromBirthDate("2013-01-01", NOW)).toBe(13);
  });
  it("caps at 21 so older ages reveal nothing more", () => {
    expect(ageFloorFromBirthDate("1980-01-01", NOW)).toBe(21);
    expect(ageFloorFromBirthDate("2005-11-17", NOW)).toBe(21);
  });
  it("refuses unusable input", () => {
    for (const v of [null, 19800101, "1980/01/01", "2001-02-30", "2027-01-01", "1800-01-01", ""]) {
      expect(ageFloorFromBirthDate(v, NOW)).toBeNull();
    }
  });
});

describe("ageGatePasses", () => {
  it("passes only when the floor reaches the app's minimum", () => {
    expect(ageGatePasses(18, 18)).toBe(true);
    expect(ageGatePasses(17, 18)).toBe(false);
    expect(ageGatePasses(21, 21)).toBe(true);
  });
  it("fails closed without a floor or with a minimum outside 13..21", () => {
    expect(ageGatePasses(null, 18)).toBe(false);
    expect(ageGatePasses(21, 12)).toBe(false);
    expect(ageGatePasses(21, 22)).toBe(false);
  });
});
