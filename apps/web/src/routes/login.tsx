import { createFileRoute } from "@tanstack/react-router";

import { LoginScreen } from "../features/auth/login-screen";
import { safeReturnTo } from "../shared/domain/return-to";

interface LoginSearch {
  returnTo: string;
}

export const Route = createFileRoute("/login")({
  validateSearch: (search: Record<string, unknown>): LoginSearch => ({
    returnTo: safeReturnTo(search.returnTo),
  }),
  component: LoginRoute,
});

function LoginRoute() {
  const { returnTo } = Route.useSearch();
  return <LoginScreen returnTo={returnTo} />;
}
