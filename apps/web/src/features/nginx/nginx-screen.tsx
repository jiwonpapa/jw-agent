import { useQuery } from "@tanstack/react-query";
import { FileLock2, Info, Server, ShieldAlert } from "lucide-react";
import { useMemo, useState } from "react";

import { nginxSitesQueryOptions } from "../../shared/api/queries";
import type { NginxSiteObservation } from "../../shared/api/types";
import { formatDateTime } from "../../shared/domain/format";
import { Button } from "../../shared/ui/button";
import { AssuranceDetails, AssuranceMark } from "../../shared/ui/assurance";
import { Sheet } from "../../shared/ui/sheet";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";

interface NginxRowView {
  id: string;
  name: string;
  sourceState: string;
  enabledLabel: string;
  protectedLabel: string;
  enabled: boolean;
  protected: boolean;
  sourceAvailable: boolean;
  assurance: NginxSiteObservation["assurance"];
}

function toRow(site: NginxSiteObservation): NginxRowView {
  return {
    id: site.name,
    name: site.name,
    sourceState: site.available ? "설정 발견" : "원본 없음",
    enabledLabel: site.enabled ? "활성" : "비활성",
    protectedLabel: site.protected ? "제품 보호" : "일반 리소스",
    enabled: site.enabled,
    protected: site.protected,
    sourceAvailable: site.available,
    assurance: site.assurance,
  };
}

export function NginxScreen() {
  const sitesQuery = useQuery(nginxSitesQueryOptions);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const rows = useMemo(() => sitesQuery.data?.sites.map(toRow) ?? [], [sitesQuery.data?.sites]);
  const selected = rows.find((row) => row.id === selectedId) ?? null;

  function inspect(row: NginxRowView): void {
    setSelectedId(row.id);
    setInspectorOpen(true);
  }

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Services / Nginx"
        title="Nginx 사이트"
        description="Ubuntu 표준 layout에서 발견한 설정만 표시합니다. P1에서는 변경하지 않습니다."
        action={<StatusMark label="읽기 전용" tone="info" />}
      />

      <section className="py-6" aria-labelledby="inventory-heading">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 id="inventory-heading" className="text-sm font-semibold text-text">
              사이트 inventory
            </h2>
            <p className="mt-1 text-sm text-muted">
              {sitesQuery.data ? `관찰 시각 ${formatDateTime(sitesQuery.data.observedAt)}` : "canonical 상태 조회 중"}
            </p>
          </div>
          {sitesQuery.data?.truncated ? <StatusMark label="일부 결과만 표시" tone="warning" /> : null}
        </div>

        {sitesQuery.isPending ? (
          <div className="mt-6 space-y-2" aria-label="Nginx 사이트 불러오는 중">
            {Array.from({ length: 5 }).map((_, index) => (
              <Skeleton key={index} className="h-14 w-full" />
            ))}
          </div>
        ) : sitesQuery.isError ? (
          <SurfaceState
            kind="error"
            title="Nginx inventory를 불러오지 못했습니다"
            description="추측한 설정 경로나 이전 결과를 대신 표시하지 않습니다."
            action={{ label: "다시 관찰", onClick: () => void sitesQuery.refetch() }}
          />
        ) : sitesQuery.data.status === "not_installed" ? (
          <SurfaceState
            kind="empty"
            title="Nginx가 설치되지 않았습니다"
            description="Nginx 설치는 현재 MVP 읽기 전용 범위에 포함되지 않습니다."
          />
        ) : sitesQuery.data.status === "unsupported_platform" ? (
          <SurfaceState
            kind="unsupported"
            title="지원하지 않는 Nginx layout입니다"
            description="지원 프로필에 없는 경로는 탐색하거나 변경하지 않습니다."
          />
        ) : rows.length === 0 ? (
          <SurfaceState
            kind="empty"
            title="발견된 사이트가 없습니다"
            description="Nginx는 관찰됐지만 지원 경로에 site 설정이 없습니다."
          />
        ) : (
          <>
            <div className="mt-6 hidden overflow-hidden rounded-panel border border-border md:block">
              <table className="w-full border-collapse text-left text-sm">
                <thead className="bg-subtle text-xs font-semibold text-muted">
                  <tr>
                    <th scope="col" className="px-4 py-3">사이트</th>
                    <th scope="col" className="px-4 py-3">원본</th>
                    <th scope="col" className="px-4 py-3">상태</th>
                    <th scope="col" className="px-4 py-3">소유권</th>
                    <th scope="col" className="px-4 py-3">원복 보장</th>
                    <th scope="col" className="px-4 py-3 text-right">다음 행동</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border bg-surface">
                  {rows.map((row) => (
                    <tr key={row.id} className="transition-colors hover:bg-subtle/55">
                      <th scope="row" className="max-w-xs px-4 py-3 font-medium text-text">
                        <span className="block truncate">{row.name}</span>
                      </th>
                      <td className="px-4 py-3 text-muted">{row.sourceState}</td>
                      <td className="px-4 py-3">
                        <StatusMark label={row.enabledLabel} tone={row.enabled ? "success" : "neutral"} />
                      </td>
                      <td className="px-4 py-3">
                        <StatusMark label={row.protectedLabel} tone={row.protected ? "warning" : "neutral"} />
                      </td>
                      <td className="px-4 py-3">
                        <AssuranceMark assurance={row.assurance} />
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Button variant="ghost" size="compact" onClick={() => inspect(row)}>
                          <Info aria-hidden="true" className="size-4" />
                          상세
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="mt-6 divide-y divide-border border-y border-border md:hidden">
              {rows.map((row) => (
                <article key={row.id} className="py-5">
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0">
                      <h3 className="break-words text-sm font-semibold text-text">{row.name}</h3>
                      <p className="mt-1 text-xs text-muted">{row.sourceState}</p>
                    </div>
                    <StatusMark label={row.enabledLabel} tone={row.enabled ? "success" : "neutral"} />
                  </div>
                  <dl className="mt-4 grid grid-cols-2 gap-3 text-sm">
                    <div>
                      <dt className="text-xs text-muted">소유권</dt>
                      <dd className="mt-1 text-text">{row.protectedLabel}</dd>
                    </div>
                    <div>
                      <dt className="text-xs text-muted">원복 보장</dt>
                      <dd className="mt-1"><AssuranceMark assurance={row.assurance} /></dd>
                    </div>
                  </dl>
                  <Button className="mt-4 w-full" variant="secondary" onClick={() => inspect(row)}>
                    <Info aria-hidden="true" className="size-4" />
                    상세 보기
                  </Button>
                </article>
              ))}
            </div>
          </>
        )}
      </section>

      {sitesQuery.data?.status === "partial" ? (
        <section className="border-y border-warning/35 py-4" aria-label="부분 관찰 경고">
          <div className="flex items-start gap-3">
            <ShieldAlert aria-hidden="true" className="mt-0.5 size-5 text-warning" />
            <div>
              <p className="text-sm font-semibold text-text">일부 사이트만 관찰되었습니다</p>
              <p className="mt-1 text-sm leading-6 text-muted">표시되지 않은 리소스를 없거나 비활성인 것으로 판단하지 마세요.</p>
            </div>
          </div>
        </section>
      ) : null}

      <Sheet
        open={inspectorOpen}
        onOpenChange={setInspectorOpen}
        title={selected?.name ?? "사이트 상세"}
        description="발견된 Nginx site 상태"
        side="right"
      >
        {selected ? <SiteInspector row={selected} /> : null}
      </Sheet>
    </div>
  );
}

function SiteInspector({ row }: { row: NginxRowView }) {
  return (
    <div>
      <div className="flex size-10 items-center justify-center rounded-control bg-subtle text-text">
        {row.protected ? <FileLock2 aria-hidden="true" className="size-5" /> : <Server aria-hidden="true" className="size-5" />}
      </div>
      <dl className="mt-6 divide-y divide-border border-y border-border text-sm">
        <div className="flex items-center justify-between gap-4 py-4">
          <dt className="text-muted">상태</dt>
          <dd className="font-medium text-text">{row.enabledLabel}</dd>
        </div>
        <div className="flex items-center justify-between gap-4 py-4">
          <dt className="text-muted">설정 원본</dt>
          <dd className="font-medium text-text">{row.sourceState}</dd>
        </div>
        <div className="flex items-center justify-between gap-4 py-4">
          <dt className="text-muted">소유권</dt>
          <dd className="font-medium text-text">{row.protectedLabel}</dd>
        </div>
        <div className="flex items-center justify-between gap-4 py-4">
          <dt className="text-muted">변경</dt>
          <dd className="font-medium text-text">지원 안 함</dd>
        </div>
      </dl>
      <div className="mt-5">
        <AssuranceDetails assurance={row.assurance} />
      </div>
      {row.protected ? (
        <p className="mt-5 text-sm leading-6 text-muted">
          공개 관리용 보호 리소스입니다. 일반 Nginx site 작업에서 변경할 수 없습니다.
        </p>
      ) : (
        <p className="mt-5 text-sm leading-6 text-muted">
          현재 단계는 관찰만 지원합니다. 변경 계획과 롤백 기능은 P2 승인 후 제공됩니다.
        </p>
      )}
    </div>
  );
}
