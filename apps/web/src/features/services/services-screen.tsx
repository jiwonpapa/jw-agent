import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, ListFilter, ServerCog } from "lucide-react";
import { useState } from "react";

import type { ServiceSummary } from "../../shared/api/types";
import { servicesQueryOptions } from "../../shared/api/queries";
import { formatDateTime } from "../../shared/domain/format";
import { Button } from "../../shared/ui/button";
import { cn } from "../../shared/ui/cn";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";
import { ServiceList, ServiceRow } from "./service-list";
import { SERVICE_FILTERS, matchesFilter, type ServiceFilter } from "./service-presenter";

export function ServicesScreen() {
  const inventory = useQuery(servicesQueryOptions);
  const [filter, setFilter] = useState<ServiceFilter>("all");
  const services = inventory.data?.services ?? [];
  const filtered = services.filter((service) => matchesFilter(service, filter));
  const primary = filtered.filter((service) => service.visibility === "primary");
  const discovered = filtered.filter((service) => service.visibility === "discovered");
  const system = filtered.filter((service) => service.visibility === "system");
  const failed = services.filter((service) => service.runtimeState === "failed");

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Services"
        title="서비스"
        description="Ubuntu가 실제로 보고한 주요 서비스와 역할을 읽기 전용으로 확인합니다."
        action={inventory.data ? (
          <div className="text-left sm:text-right">
            <p className="text-xs text-muted">마지막 관찰</p>
            <p className="mt-1 text-sm font-medium text-text">{formatDateTime(inventory.data.observedAt)}</p>
          </div>
        ) : null}
      />

      {inventory.isPending ? (
        <LoadingState />
      ) : inventory.isError ? (
        <SurfaceState
          kind="offline"
          title="서비스 목록을 불러오지 못했습니다"
          description="이 화면은 이전 서비스 상태를 현재 상태로 대신 표시하지 않습니다."
          action={{ label: "다시 관찰", onClick: () => void inventory.refetch() }}
        />
      ) : inventory.data.status === "unsupported_platform" ? (
        <SurfaceState
          kind="unsupported"
          title="지원하지 않는 서비스 관리자입니다"
          description="Ubuntu 24.04 systemd 환경에서만 서비스 인벤토리를 제공합니다."
        />
      ) : (
        <>
          <InventorySummary services={services} partial={inventory.data.status === "partial"} />
          {failed.length > 0 ? <FailureNotice services={failed} /> : null}
          <FilterBar value={filter} onChange={setFilter} />
          <ServiceList
            title="주요 서비스"
            description="템플릿으로 역할과 지원 범위를 확인한 운영 대상입니다."
            services={primary}
            emptyLabel="현재 필터에 해당하는 주요 서비스가 없습니다."
          />
          <ServiceList
            title="발견된 서비스"
            description="서버 관리자가 추가한 systemd unit이며 JW Agent는 역할을 추측하지 않습니다."
            services={discovered}
            emptyLabel="발견된 사용자 정의 서비스가 없습니다."
          />
          <SystemServices services={system} />
          <p className="border-t border-border pt-5 text-xs text-muted">
            템플릿 {inventory.data.templateProfile} · 최대 512개 · 모든 항목은 G0 읽기 전용
          </p>
        </>
      )}
    </div>
  );
}

function InventorySummary({ services, partial }: { services: ServiceSummary[]; partial: boolean }) {
  const running = services.filter(
    (service) => service.runtimeState === "running" || service.runtimeState === "active",
  ).length;
  const failed = services.filter((service) => service.runtimeState === "failed").length;
  const stopped = services.filter((service) => service.runtimeState === "stopped").length;
  return (
    <section className="py-7" aria-labelledby="service-summary-heading">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 id="service-summary-heading" className="text-sm font-semibold text-text">관찰 요약</h2>
          <p className="mt-1 text-sm text-muted">설치된 unit만 집계하며 미설치를 중지로 만들지 않습니다.</p>
        </div>
        <StatusMark label={partial ? "부분 관찰" : "관찰 완료"} tone={partial ? "warning" : "success"} />
      </div>
      <dl className="mt-5 grid divide-y divide-border border-y border-border sm:grid-cols-4 sm:divide-x sm:divide-y-0">
        <SummaryValue label="전체" value={services.length} />
        <SummaryValue label="실행·활성" value={running} />
        <SummaryValue label="실패" value={failed} danger={failed > 0} />
        <SummaryValue label="중지" value={stopped} />
      </dl>
    </section>
  );
}

function SummaryValue({ label, value, danger = false }: { label: string; value: number; danger?: boolean }) {
  return (
    <div className="px-1 py-4 sm:px-5">
      <dt className="text-xs text-muted">{label}</dt>
      <dd className={cn("mt-1 text-2xl font-semibold text-text", danger && "text-danger")}>{value}</dd>
    </div>
  );
}

function FailureNotice({ services }: { services: ServiceSummary[] }) {
  return (
    <section className="border-t border-danger/40 py-6" aria-labelledby="failed-services-heading">
      <div className="flex items-start gap-3">
        <AlertTriangle aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-danger" />
        <div>
          <h2 id="failed-services-heading" className="text-sm font-semibold text-text">실패한 서비스 {services.length}개</h2>
          <p className="mt-1 text-sm text-muted">시스템 내부 unit도 실패하면 숨기지 않습니다. 행을 열어 실제 unit 상태를 확인하세요.</p>
          <p className="mt-3 text-sm font-medium text-danger">{services.map((service) => service.displayName).join(" · ")}</p>
        </div>
      </div>
    </section>
  );
}

function FilterBar({ value, onChange }: { value: ServiceFilter; onChange: (value: ServiceFilter) => void }) {
  return (
    <section className="border-t border-border py-5" aria-label="서비스 상태 필터">
      <div className="flex flex-wrap items-center gap-2">
        <ListFilter aria-hidden="true" className="mr-1 size-4 text-muted" />
        {SERVICE_FILTERS.map((filter) => (
          <Button
            key={filter.value}
            type="button"
            size="compact"
            variant={value === filter.value ? "primary" : "secondary"}
            aria-pressed={value === filter.value}
            onClick={() => onChange(filter.value)}
          >
            {filter.label}
          </Button>
        ))}
      </div>
    </section>
  );
}

function SystemServices({ services }: { services: ServiceSummary[] }) {
  return (
    <section className="border-t border-border py-7" aria-labelledby="system-services-heading">
      <details className="group">
        <summary className="flex min-h-12 cursor-pointer list-none items-center justify-between gap-4 [&::-webkit-details-marker]:hidden">
          <div className="flex items-start gap-3">
            <ServerCog aria-hidden="true" className="mt-0.5 size-5 text-muted" />
            <div>
              <h2 id="system-services-heading" className="text-sm font-semibold text-text">시스템 서비스 {services.length}개</h2>
              <p className="mt-1 text-sm text-muted">Ubuntu와 JW Agent 내부 unit은 기본으로 접어 둡니다.</p>
            </div>
          </div>
          <span className="text-sm font-medium text-action group-open:hidden">펼치기</span>
          <span className="hidden text-sm font-medium text-action group-open:inline">접기</span>
        </summary>
        {services.length === 0 ? (
          <p className="mt-4 border-y border-border py-5 text-sm text-muted">현재 필터에 해당하는 시스템 서비스가 없습니다.</p>
        ) : (
          <ul className="mt-5 divide-y divide-border border-y border-border">
            {services.map((service) => (
              <li key={service.serviceId}><ServiceRow service={service} /></li>
            ))}
          </ul>
        )}
      </details>
    </section>
  );
}

function LoadingState() {
  return (
    <div className="space-y-7 py-7" aria-label="서비스 목록 불러오는 중">
      <div className="grid gap-3 sm:grid-cols-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <Skeleton key={index} className="h-16 w-full" />
        ))}
      </div>
      <div className="space-y-2">
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-16 w-full" />
      </div>
    </div>
  );
}
