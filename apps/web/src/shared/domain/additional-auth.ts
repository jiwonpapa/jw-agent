import type { AdditionalAuthPolicy, AdditionalAuthProviderStatus } from "../api/types";

const policyRank: Record<AdditionalAuthPolicy, number> = {
  disabled: 0,
  risky_operations: 1,
  all_mutations: 2,
};

export const RECOMMENDED_ADDITIONAL_AUTH_POLICY: AdditionalAuthPolicy = "risky_operations";

export function isPolicyDowngrade(
  current: AdditionalAuthPolicy,
  target: AdditionalAuthPolicy,
): boolean {
  return policyRank[target] < policyRank[current];
}

export function providerCanApproveMutations(status: AdditionalAuthProviderStatus): boolean {
  return status === "ready";
}
