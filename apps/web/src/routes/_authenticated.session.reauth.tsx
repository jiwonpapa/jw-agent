import { createFileRoute, Navigate } from "@tanstack/react-router";

import { ReauthScreen } from "../features/auth/reauth-screen";
import type { AdditionalAuthPolicy } from "../shared/api/types";
import { safeReturnTo } from "../shared/domain/return-to";

const policies: AdditionalAuthPolicy[] = ["disabled", "risky_operations", "all_mutations"];

interface ReauthSearch {
  targetPolicy: AdditionalAuthPolicy | null;
  returnTo: string;
}

export const Route = createFileRoute("/_authenticated/session/reauth")({
  validateSearch: (search: Record<string, unknown>): ReauthSearch => ({
    targetPolicy: policies.includes(search.targetPolicy as AdditionalAuthPolicy)
      ? (search.targetPolicy as AdditionalAuthPolicy)
      : null,
    returnTo: safeReturnTo(search.returnTo, "/settings/access"),
  }),
  component: ReauthRoute,
});

function ReauthRoute() {
  const search = Route.useSearch();
  if (search.targetPolicy === null) return <Navigate to="/settings/access" replace />;
  return <ReauthScreen targetPolicy={search.targetPolicy} returnTo={search.returnTo} />;
}
