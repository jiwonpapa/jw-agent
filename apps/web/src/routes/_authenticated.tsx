import { createFileRoute, Outlet } from "@tanstack/react-router";

import { AppShell } from "../app/app-shell";
import { AuthenticatedBoundary } from "../app/authenticated-boundary";

export const Route = createFileRoute("/_authenticated")({
  component: AuthenticatedRoute,
});

function AuthenticatedRoute() {
  return (
    <AuthenticatedBoundary>
      <AppShell>
        <Outlet />
      </AppShell>
    </AuthenticatedBoundary>
  );
}
