import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { FileCode2, Globe2, ShieldAlert } from "lucide-react";

import { nginxSitesQueryOptions } from "../../shared/api/queries";
import type { NginxSiteObservation } from "../../shared/api/types";
import { formatDateTime } from "../../shared/domain/format";
import { Button } from "../../shared/ui/button";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";

export function NginxScreen() {
  const sitesQuery = useQuery(nginxSitesQueryOptions);
  const sites = sitesQuery.data?.sites ?? [];

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Services / Web server"
        title="Nginx"
        description="사이트 상태를 확인하고 /etc/nginx 아래 설정 파일을 전체 화면 workspace에서 편집합니다."
        action={
          <Button asChild>
            <Link to="/services/nginx/configurations">
              <FileCode2 aria-hidden="true" className="size-4" />
              설정 파일 열기
            </Link>
          </Button>
        }
      />

      <section
        className="my-6 overflow-hidden rounded-panel border border-border bg-surface"
        aria-labelledby="nginx-sites-heading"
      >
        <header className="flex flex-col gap-3 border-b border-border p-5 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 id="nginx-sites-heading" className="text-sm font-semibold text-text">
              발견된 사이트
            </h2>
            <p className="mt-1 text-sm text-muted">
              {sitesQuery.data
                ? `관찰 ${formatDateTime(sitesQuery.data.observedAt)}`
                : "실제 Nginx layout을 확인하고 있습니다."}
            </p>
          </div>
          {sitesQuery.data?.truncated ? (
            <StatusMark label="일부 표시" tone="warning" />
          ) : (
            <StatusMark label={`${String(sites.length)}개`} tone="neutral" />
          )}
        </header>

        {sitesQuery.isPending ? (
          <div className="grid gap-3 p-5 md:grid-cols-2 xl:grid-cols-3">
            {Array.from({ length: 6 }).map((_, index) => (
              <Skeleton key={index} className="h-32 w-full" />
            ))}
          </div>
        ) : sitesQuery.isError ? (
          <SurfaceState
            kind="error"
            title="Nginx 상태를 불러오지 못했습니다"
            description="이전 결과를 현재 상태처럼 표시하지 않습니다."
            action={{ label: "다시 관찰", onClick: () => void sitesQuery.refetch() }}
          />
        ) : sitesQuery.data.status === "not_installed" ? (
          <SurfaceState
            kind="empty"
            title="Nginx가 설치되지 않았습니다"
            description="Nginx가 설치되면 실제 사이트와 설정 파일을 표시합니다."
          />
        ) : sitesQuery.data.status === "unsupported_platform" ? (
          <SurfaceState
            kind="unsupported"
            title="지원하지 않는 Nginx layout입니다"
            description="Ubuntu 24.04 표준 패키지 layout만 지원합니다."
          />
        ) : sites.length === 0 ? (
          <SurfaceState
            kind="empty"
            title="발견된 사이트가 없습니다"
            description="/etc/nginx/sites-available에 설정이 생기면 표시합니다."
          />
        ) : (
          <SiteCards sites={sites} />
        )}
      </section>

      {sitesQuery.data?.status === "partial" ? (
        <section className="mb-6 rounded-panel border border-warning/35 bg-warning/5 p-4">
          <div className="flex items-start gap-3">
            <ShieldAlert aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-warning" />
            <div>
              <p className="text-sm font-semibold text-text">일부 사이트만 관찰되었습니다</p>
              <p className="mt-1 text-sm text-muted">
                설정 파일 workspace에서 차단 사유와 실제 파일 목록을 다시 확인해 주세요.
              </p>
            </div>
          </div>
        </section>
      ) : null}
    </div>
  );
}

function SiteCards({ sites }: { sites: NginxSiteObservation[] }) {
  return (
    <ul className="grid gap-3 p-5 md:grid-cols-2 xl:grid-cols-3">
      {sites.map((site) => (
        <li
          key={site.siteId ?? site.name}
          className="rounded-panel border border-border bg-subtle/30 p-4"
        >
          <div className="flex items-start justify-between gap-3">
            <span className="grid size-10 shrink-0 place-items-center rounded-control bg-surface text-action">
              <Globe2 aria-hidden="true" className="size-5" />
            </span>
            <StatusMark
              label={site.enabled ? "활성" : "비활성"}
              tone={site.enabled ? "success" : "neutral"}
            />
          </div>
          <h3 className="mt-4 truncate text-sm font-semibold text-text">{site.name}</h3>
          <p className="mt-1 text-xs text-muted">
            {site.available ? "설정 원본 발견" : "설정 원본을 찾지 못함"}
            {site.protected ? " · 관리 edge 보호" : ""}
          </p>
        </li>
      ))}
    </ul>
  );
}
