import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ArrowRight, CheckCircle2, ServerCog } from "lucide-react";

import { servicesQueryOptions } from "../../shared/api/queries";
import { Button } from "../../shared/ui/button";
import { Skeleton } from "../../shared/ui/skeleton";
import { SurfaceState } from "../../shared/ui/surface-state";
import { PrimaryServiceGrid } from "./service-list";

export function ServiceOverview() {
  const inventory = useQuery(servicesQueryOptions);
  const primary = inventory.data?.services.filter((service) => service.visibility === "primary") ?? [];
  const failed = inventory.data?.services.filter((service) => service.runtimeState === "failed") ?? [];
  return (
    <section className="border-t border-border py-7" aria-labelledby="overview-services-heading">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div className="flex items-start gap-3">
          <ServerCog aria-hidden="true" className="mt-0.5 size-5 text-muted" />
          <div>
            <h2 id="overview-services-heading" className="text-sm font-semibold text-text">주요 서비스</h2>
            <p className="mt-1 text-sm text-muted">설치된 서비스의 역할과 실제 systemd 상태입니다.</p>
          </div>
        </div>
        <Button asChild variant="secondary" size="compact">
          <Link to="/services">전체 서비스<ArrowRight aria-hidden="true" className="size-4" /></Link>
        </Button>
      </div>
      {inventory.isPending ? (
        <div className="mt-5 space-y-2">
          <Skeleton className="h-14 w-full" />
          <Skeleton className="h-14 w-full" />
        </div>
      ) : inventory.isError ? (
        <SurfaceState
          kind="error"
          title="서비스 상태를 불러오지 못했습니다"
          description="호스트 자원 상태와 별개로 서비스 관찰이 실패했습니다."
          action={{ label: "다시 관찰", onClick: () => void inventory.refetch() }}
        />
      ) : primary.length === 0 ? (
        <p className="mt-5 border-y border-border py-5 text-sm text-muted">발견된 주요 서비스가 없습니다.</p>
      ) : (
        <PrimaryServiceGrid services={primary.slice(0, 6)} />
      )}
      {failed.length > 0 ? (
        <p className="mt-4 text-sm font-medium text-danger">실패한 서비스 {failed.length}개가 확인됐습니다.</p>
      ) : inventory.data ? (
        <div className="mt-4 flex items-center gap-2 text-sm text-muted">
          <CheckCircle2 aria-hidden="true" className="size-4 text-success" />
          실패한 서비스가 없습니다.
        </div>
      ) : null}
    </section>
  );
}
