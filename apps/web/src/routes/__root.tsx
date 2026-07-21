import { createRootRouteWithContext, Outlet } from "@tanstack/react-router";

import { RouteError } from "../app/error-boundary";
import type { RouterContext } from "../app/router";
import { SurfaceState } from "../shared/ui/surface-state";

export const Route = createRootRouteWithContext<RouterContext>()({
  component: Outlet,
  errorComponent: RouteError,
  notFoundComponent: () => (
    <main className="mx-auto max-w-3xl px-4 py-16">
      <SurfaceState
        kind="empty"
        title="화면을 찾을 수 없습니다"
        description="요청한 경로는 JW Agent MVP 지원 범위에 없습니다."
      />
    </main>
  ),
});
