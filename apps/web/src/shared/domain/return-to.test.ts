import { describe, expect, it } from "vitest";

import { safeReturnTo } from "./return-to";

describe("safeReturnTo", () => {
  it("keeps a same-origin relative route", () => {
    expect(safeReturnTo("/services/nginx?view=all#site")).toBe(
      "/services/nginx?view=all#site",
    );
  });

  it.each([
    "https://attacker.example/path",
    "//attacker.example/path",
    "\\attacker.example",
    "javascript:alert(1)",
    "/login",
    "/login?returnTo=%2Fintegrations",
    null,
    undefined,
  ])("rejects unsafe return target %s", (value) => {
    expect(safeReturnTo(value)).toBe("/overview");
  });
});
