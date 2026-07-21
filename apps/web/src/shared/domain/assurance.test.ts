import { describe, expect, it } from "vitest";

import { ASSURANCE_COPY } from "./assurance";

describe("assurance copy", () => {
  it("never collapses distinct guarantee levels", () => {
    const labels = Object.values(ASSURANCE_COPY).map((entry) => entry.label);
    expect(new Set(labels).size).toBe(4);
    expect(ASSURANCE_COPY.g1_verified_action.label).toContain("원복 보장 없음");
    expect(ASSURANCE_COPY.g2_reversible_config.label).toContain("제한된 설정");
  });
});
