import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ArrowRight, Clock3, HardDrive, MemoryStick, Server, Timer, TriangleAlert } from "lucide-react";

import { hostQueryOptions, nginxSitesQueryOptions } from "../../shared/api/queries";
import { OBSERVATION_LABELS } from "../../shared/content/copy";
import { formatBytes, formatDateTime, formatDuration, formatPercent } from "../../shared/domain/format";
import { AssuranceMark } from "../../shared/ui/assurance";
import { Button } from "../../shared/ui/button";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark, type StatusTone } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";

const observationTone = {
  observed: "success",
  partial: "warning",
  not_installed: "neutral",
  unsupported_platform: "stale",
} as const satisfies Record<string, StatusTone>;

export function OverviewScreen() {
  const host = useQuery(hostQueryOptions);
  const nginx = useQuery(nginxSitesQueryOptions);

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Overview"
        title="서버 개요"
        description="관찰된 값과 지원 상태만 표시합니다. 추측한 값은 정상으로 처리하지 않습니다."
        action={
          host.data ? (
            <div className="text-left sm:text-right">
              <p className="text-xs text-muted">마지막 관찰</p>
              <p className="mt-1 text-sm font-medium text-text">{formatDateTime(host.data.observedAt)}</p>
            </div>
          ) : null
        }
      />

      <section className="py-7" aria-labelledby="identity-heading">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 id="identity-heading" className="text-sm font-semibold text-text">
              서버 상태
            </h2>
            <p className="mt-1 text-sm text-muted">호스트 identity와 관찰 완전성입니다.</p>
          </div>
          {host.data ? (
            <StatusMark
              label={OBSERVATION_LABELS[host.data.status]}
              tone={observationTone[host.data.status]}
            />
          ) : null}
        </div>

        {host.isPending ? (
          <div className="mt-5 grid gap-px overflow-hidden rounded-panel border border-border bg-border sm:grid-cols-2 lg:grid-cols-4">
            {Array.from({ length: 4 }).map((_, index) => (
              <div key={index} className="bg-surface p-4">
                <Skeleton className="h-4 w-20" />
                <Skeleton className="mt-3 h-6 w-28" />
              </div>
            ))}
          </div>
        ) : host.isError ? (
          <SurfaceState
            kind="offline"
            title="호스트 관찰을 불러오지 못했습니다"
            description="이 화면은 이전 값을 정상값으로 대체하지 않습니다."
            action={{ label: "다시 관찰", onClick: () => void host.refetch() }}
          />
        ) : (
          <dl className="mt-5 grid gap-px overflow-hidden rounded-panel border border-border bg-border sm:grid-cols-2 lg:grid-cols-4">
            <Metric
              icon={Server}
              label="호스트"
              value={host.data.hostname ?? "알 수 없음"}
              detail={host.data.osPrettyName ?? host.data.osId ?? "OS 정보 없음"}
            />
            <Metric
              icon={MemoryStick}
              label="메모리"
              value={
                host.data.memory
                  ? formatPercent(host.data.memory.availableBytes, host.data.memory.totalBytes)
                  : "알 수 없음"
              }
              detail={
                host.data.memory
                  ? `${formatBytes(host.data.memory.availableBytes)} 사용 가능`
                  : "관찰값 없음"
              }
            />
            <Metric
              icon={HardDrive}
              label="루트 디스크"
              value={
                host.data.rootDisk
                  ? formatPercent(host.data.rootDisk.availableBytes, host.data.rootDisk.totalBytes)
                  : "알 수 없음"
              }
              detail={
                host.data.rootDisk
                  ? `${formatBytes(host.data.rootDisk.availableBytes)} 사용 가능`
                  : "관찰값 없음"
              }
            />
            <Metric
              icon={Timer}
              label="업타임"
              value={formatDuration(host.data.uptimeSeconds)}
              detail={
                host.data.loadAverageOne === null || host.data.loadAverageOne === undefined
                  ? "부하 관찰값 없음"
                  : `1분 부하 ${host.data.loadAverageOne.toFixed(2)}`
              }
            />
          </dl>
        )}
      </section>

      <section className="border-t border-border py-7" aria-labelledby="attention-heading">
        <div className="flex items-center gap-3">
          <TriangleAlert aria-hidden="true" className="size-5 text-muted" />
          <div>
            <h2 id="attention-heading" className="text-sm font-semibold text-text">
              확인할 항목
            </h2>
            <p className="mt-1 text-sm text-muted">지원 상태와 부분 관찰을 우선 표시합니다.</p>
          </div>
        </div>

        {host.data?.status === "partial" ? (
          <div className="mt-5 flex flex-col gap-4 border-y border-warning/35 py-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-sm font-semibold text-text">호스트 정보가 일부만 관찰되었습니다</p>
              <p className="mt-1 text-sm text-muted">누락된 항목을 0 또는 정상으로 해석하지 않습니다.</p>
            </div>
            <StatusMark label="부분 관찰" tone="warning" />
          </div>
        ) : host.data?.status === "unsupported_platform" ? (
          <div className="mt-5">
            <SurfaceState
              kind="unsupported"
              title="지원하지 않는 플랫폼입니다"
              description="Ubuntu 24.04 LTS 지원 프로필과 일치하지 않아 변경 기능을 제공하지 않습니다."
            />
          </div>
        ) : (
          <div className="mt-5 border-y border-border py-5">
            <StatusMark label="현재 우선 확인할 항목이 없습니다" tone="success" />
          </div>
        )}
      </section>

      <section className="border-t border-border py-7" aria-labelledby="nginx-heading">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h2 id="nginx-heading" className="text-sm font-semibold text-text">
              Nginx 사이트
            </h2>
            <p className="mt-1 text-sm text-muted">발견된 site 목록의 읽기 전용 요약입니다.</p>
          </div>
          <Button asChild variant="secondary" size="compact">
            <Link to="/services/nginx">
              전체 보기
              <ArrowRight aria-hidden="true" className="size-4" />
            </Link>
          </Button>
        </div>

        {nginx.isPending ? (
          <div className="mt-5 space-y-2">
            <Skeleton className="h-12 w-full" />
            <Skeleton className="h-12 w-full" />
          </div>
        ) : nginx.isError ? (
          <SurfaceState
            kind="error"
            title="Nginx 상태를 불러오지 못했습니다"
            description="호스트 상태와 별개로 Nginx 관찰 요청이 실패했습니다."
            action={{ label: "다시 불러오기", onClick: () => void nginx.refetch() }}
          />
        ) : nginx.data.status === "not_installed" ? (
          <SurfaceState
            kind="empty"
            title="Nginx가 설치되지 않았습니다"
            description="설치 작업은 P1 읽기 전용 범위에 포함되지 않습니다."
          />
        ) : nginx.data.status === "unsupported_platform" ? (
          <SurfaceState
            kind="unsupported"
            title="이 Nginx 구성을 지원하지 않습니다"
            description="사이트 경로를 추측하지 않고 관찰을 중단했습니다."
          />
        ) : nginx.data.sites.length === 0 ? (
          <SurfaceState kind="empty" title="발견된 사이트가 없습니다" description="Nginx는 관찰됐지만 site 항목이 비어 있습니다." />
        ) : (
          <div className="mt-5 divide-y divide-border border-y border-border">
            {nginx.data.sites.slice(0, 4).map((site) => (
              <div key={site.name} className="flex min-h-14 items-center justify-between gap-4 py-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-text">{site.name}</p>
                  <p className="mt-0.5 text-xs text-muted">
                    {site.protected ? "JW Agent 보호 리소스" : "일반 Nginx 사이트"}
                  </p>
                </div>
                <div className="flex shrink-0 flex-col items-end gap-1.5">
                  <StatusMark label={site.enabled ? "활성" : "비활성"} tone={site.enabled ? "success" : "neutral"} />
                  <AssuranceMark assurance={site.assurance} />
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="border-t border-border py-7" aria-labelledby="ledger-heading">
        <div className="flex items-center gap-3">
          <Clock3 aria-hidden="true" className="size-5 text-muted" />
          <div>
            <h2 id="ledger-heading" className="text-sm font-semibold text-text">
              최근 작업
            </h2>
            <p className="mt-1 text-sm text-muted">P1은 읽기 전용이므로 실행된 변경 작업이 없습니다.</p>
          </div>
        </div>
        <div className="mt-5 border-y border-border py-5 text-sm text-muted">표시할 작업 기록이 없습니다.</div>
      </section>
    </div>
  );
}

function Metric({
  icon: Icon,
  label,
  value,
  detail,
}: {
  icon: typeof Server;
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="bg-surface p-4">
      <dt className="flex items-center gap-2 text-xs font-medium text-muted">
        <Icon aria-hidden="true" className="size-4" />
        {label}
      </dt>
      <dd className="mt-3 truncate text-lg font-semibold text-text">{value}</dd>
      <p className="mt-1 truncate text-xs text-muted">{detail}</p>
    </div>
  );
}
