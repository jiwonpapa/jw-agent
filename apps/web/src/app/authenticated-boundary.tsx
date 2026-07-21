import { useQuery } from "@tanstack/react-query";
import { useLocation, useNavigate } from "@tanstack/react-router";
import { useEffect, type ReactNode } from "react";

import { ApiError } from "../shared/api/client";
import { sessionQueryOptions } from "../shared/api/queries";
import { Skeleton } from "../shared/ui/skeleton";
import { SurfaceState } from "../shared/ui/surface-state";

export function AuthenticatedBoundary({ children }: { children: ReactNode }) {
  const sessionQuery = useQuery(sessionQueryOptions);
  const navigate = useNavigate();
  const location = useLocation();
  const isAnonymous = sessionQuery.error instanceof ApiError && sessionQuery.error.status === 401;

  useEffect(() => {
    if (!isAnonymous || location.pathname === "/login") return;
    const returnTo = `${location.pathname}${location.searchStr}${location.hash}`;
    void navigate({ to: "/login", search: { returnTo }, replace: true });
  }, [isAnonymous, location.hash, location.pathname, location.searchStr, navigate]);

  if (sessionQuery.isPending || isAnonymous) {
    return (
      <main className="mx-auto w-full max-w-5xl px-4 py-8" aria-label="세션 확인 중">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="mt-8 h-20 w-full" />
        <Skeleton className="mt-3 h-20 w-full" />
      </main>
    );
  }

  if (sessionQuery.isError) {
    return (
      <main className="mx-auto w-full max-w-5xl px-4 py-8">
        <SurfaceState
          kind="offline"
          title="세션을 확인할 수 없습니다"
          description="agentd 연결 상태를 확인한 뒤 다시 시도해 주세요. SSH 복구 접속은 별도로 유지됩니다."
          action={{ label: "다시 확인", onClick: () => void sessionQuery.refetch() }}
        />
      </main>
    );
  }

  return children;
}
