import { describe, expect, it } from "vitest";

import {
  isPolicyDowngrade,
  providerCanApproveMutations,
  RECOMMENDED_ADDITIONAL_AUTH_POLICY,
} from "./additional-auth";

describe("additional authentication policy", () => {
  it("keeps risky operations as the UI recommendation", () => {
    expect(RECOMMENDED_ADDITIONAL_AUTH_POLICY).toBe("risky_operations");
  });

  it("detects only weaker target policies as downgrade", () => {
    expect(isPolicyDowngrade("all_mutations", "risky_operations")).toBe(true);
    expect(isPolicyDowngrade("risky_operations", "disabled")).toBe(true);
    expect(isPolicyDowngrade("disabled", "all_mutations")).toBe(false);
  });

  it("does not claim protection before provider readiness", () => {
    expect(providerCanApproveMutations("not_implemented")).toBe(false);
    expect(providerCanApproveMutations("not_configured")).toBe(false);
    expect(providerCanApproveMutations("ready")).toBe(true);
  });
});
