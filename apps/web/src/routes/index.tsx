import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Navigate } from "@tanstack/react-router";

import { ApiError } from "../shared/api/client";
import { sessionQueryOptions } from "../shared/api/queries";
import { Skeleton } from "../shared/ui/skeleton";
import { SurfaceState } from "../shared/ui/surface-state";

export const Route = createFileRoute("/")({
  component: LandingRoute,
});

function LandingRoute() {
  const session = useQuery(sessionQueryOptions);

  if (session.data !== undefined) return <Navigate to="/overview" replace />;
  if (session.error instanceof ApiError && session.error.status === 401) {
    return <Navigate to="/login" search={{ returnTo: "/overview" }} replace />;
  }
  if (session.isError) {
    return (
      <main className="mx-auto max-w-3xl px-4 py-16">
        <SurfaceState
          kind="offline"
          title="Agent에 연결할 수 없습니다"
          description="agentd 상태와 현재 접속 경로를 확인해 주세요."
          action={{ label: "다시 확인", onClick: () => void session.refetch() }}
        />
      </main>
    );
  }
  return (
    <main className="mx-auto max-w-3xl px-4 py-16" aria-label="세션 확인 중">
      <Skeleton className="h-8 w-48" />
      <Skeleton className="mt-8 h-24 w-full" />
    </main>
  );
}
