import { useQuery } from "@tanstack/react-query";
import {
  BellRing,
  ExternalLink,
  Images,
  Info,
  PackageSearch,
  ServerCog,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";
import { useMemo, useState } from "react";

import { integrationsQueryOptions } from "../../shared/api/queries";
import type {
  IntegrationCatalogView,
  IntegrationCategory,
  IntegrationLifecycleStatus,
  IntegrationView,
} from "../../shared/api/types";
import { formatDateTime } from "../../shared/domain/format";
import { AssuranceDetails, AssuranceMark } from "../../shared/ui/assurance";
import { Button } from "../../shared/ui/button";
import { Sheet } from "../../shared/ui/sheet";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark, type StatusTone } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";

const CATEGORY_COPY: Record<IntegrationCategory, { label: string; icon: LucideIcon }> = {
  security: { label: "보안·트래픽", icon: ShieldCheck },
  provisioning: { label: "서버 구축", icon: ServerCog },
  media: { label: "미디어 처리", icon: Images },
  notification: { label: "알림·관제", icon: BellRing },
};

const LIFECYCLE_COPY: Record<
  IntegrationLifecycleStatus,
  { label: string; tone: StatusTone }
> = {
  unknown: { label: "판정 불가", tone: "stale" },
  not_installed: { label: "설치되지 않음", tone: "neutral" },
  needs_setup: { label: "설정 필요", tone: "warning" },
  installed: { label: "설치 흔적 확인", tone: "success" },
  partial: { label: "부분 설치 흔적", tone: "warning" },
};

export function IntegrationsScreen() {
  const catalog = useQuery(integrationsQueryOptions);
  const [selectedId, setSelectedId] = useState<IntegrationView["id"] | null>(null);
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const selected = useMemo(
    () => catalog.data?.entries.find((entry) => entry.id === selectedId) ?? null,
    [catalog.data?.entries, selectedId],
  );

  function inspect(entry: IntegrationView): void {
    setSelectedId(entry.id);
    setInspectorOpen(true);
  }

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Integrations / Curated"
        title="통합 카탈로그"
        description="독립 제품의 설치 흔적과 준비 조건을 확인합니다. 서명과 VM 증거가 없는 설치 실행은 서버가 차단합니다."
        action={<StatusMark label="조회 전용" tone="info" />}
      />

      {catalog.isPending ? (
        <div className="space-y-3 py-7" aria-label="통합 카탈로그 불러오는 중">
          <Skeleton className="h-24 w-full" />
          {Array.from({ length: 4 }).map((_, index) => (
            <Skeleton key={index} className="h-24 w-full" />
          ))}
        </div>
      ) : catalog.isError ? (
        <SurfaceState
          kind="error"
          title="통합 카탈로그를 불러오지 못했습니다"
          description="이전 설치 상태를 대신 표시하지 않습니다. canonical 상태를 다시 조회해 주세요."
          action={{ label: "다시 조회", onClick: () => void catalog.refetch() }}
        />
      ) : (
        <>
          <CatalogSummary catalog={catalog.data} />
          <CatalogList entries={catalog.data.entries} onInspect={inspect} />
        </>
      )}

      <Sheet
        open={inspectorOpen}
        onOpenChange={setInspectorOpen}
        title={selected?.name ?? "통합 상세"}
        description="권한·자원·설치 차단·설정 안내"
        side="right"
      >
        {selected ? <IntegrationInspector entry={selected} /> : null}
      </Sheet>
    </div>
  );
}

function CatalogSummary({
  catalog,
}: {
  catalog: IntegrationCatalogView;
}) {
  const installed = catalog.entries.filter((entry) => entry.lifecycleStatus === "installed").length;
  const attention = catalog.entries.filter((entry) =>
    ["needs_setup", "partial"].includes(entry.lifecycleStatus),
  ).length;
  return (
    <section className="py-7" aria-labelledby="catalog-status-heading">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2 id="catalog-status-heading" className="text-sm font-semibold text-text">
            현재 서버 판정
          </h2>
          <p className="mt-1 text-sm text-muted">관찰 시각 {formatDateTime(catalog.observedAt)}</p>
        </div>
        <StatusMark
          label={catalog.status === "observed" ? "Ubuntu 관찰 완료" : "플랫폼 판정 불가"}
          tone={catalog.status === "observed" ? "success" : "stale"}
        />
      </div>
      <dl className="mt-5 grid gap-px overflow-hidden rounded-panel border border-border bg-border sm:grid-cols-3">
        <SummaryValue label="등록 제품" value={`${String(catalog.entries.length)}개`} />
        <SummaryValue label="설치 흔적 확인" value={`${String(installed)}개`} />
        <SummaryValue label="설정·정리 필요" value={`${String(attention)}개`} />
      </dl>
    </section>
  );
}

function CatalogList({
  entries,
  onInspect,
}: {
  entries: IntegrationView[];
  onInspect: (entry: IntegrationView) => void;
}) {
  return (
    <section className="border-t border-border py-7" aria-labelledby="catalog-list-heading">
      <div className="flex items-start gap-3">
        <PackageSearch aria-hidden="true" className="mt-0.5 size-5 text-muted" />
        <div>
          <h2 id="catalog-list-heading" className="text-sm font-semibold text-text">
            형님 제품 통합
          </h2>
          <p className="mt-1 text-sm leading-6 text-muted">
            제품 코드를 합치지 않고 설치 흔적과 안전한 handoff 경계만 관리합니다.
          </p>
        </div>
      </div>

      <div className="mt-6 hidden overflow-hidden rounded-panel border border-border lg:block">
        <table className="w-full table-fixed border-collapse text-left text-sm">
          <thead className="bg-subtle text-xs font-semibold text-muted">
            <tr>
              <th scope="col" className="w-[42%] px-4 py-3">제품</th>
              <th scope="col" className="w-[21%] px-4 py-3">현재 상태</th>
              <th scope="col" className="w-[25%] px-4 py-3">원복 보장</th>
              <th scope="col" className="w-[12%] px-4 py-3 text-right">다음 행동</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border bg-surface">
            {entries.map((entry) => (
              <IntegrationRow key={entry.id} entry={entry} onInspect={onInspect} />
            ))}
          </tbody>
        </table>
      </div>

      <div className="mt-6 divide-y divide-border border-y border-border lg:hidden">
        {entries.map((entry) => (
          <IntegrationMobileRow key={entry.id} entry={entry} onInspect={onInspect} />
        ))}
      </div>
    </section>
  );
}

function IntegrationRow({
  entry,
  onInspect,
}: {
  entry: IntegrationView;
  onInspect: (entry: IntegrationView) => void;
}) {
  const category = CATEGORY_COPY[entry.category];
  const lifecycle = LIFECYCLE_COPY[entry.lifecycleStatus];
  const Icon = category.icon;
  return (
    <tr
      data-testid={`integration-${entry.id}`}
      className="transition-colors hover:bg-subtle/55"
    >
      <th scope="row" className="max-w-sm px-4 py-4 font-medium text-text">
        <div className="flex items-start gap-3">
          <Icon aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted" />
          <div>
            <span className="block">{entry.name}</span>
            <span className="mt-1 block text-xs font-normal leading-5 text-muted">
              {category.label} · {entry.summary}
            </span>
          </div>
        </div>
      </th>
      <td className="px-4 py-4">
        <div className="space-y-2">
          <StatusMark label={lifecycle.label} tone={lifecycle.tone} />
          <StatusMark label="설치 실행 차단" tone="warning" />
        </div>
      </td>
      <td className="px-4 py-4"><AssuranceMark assurance={entry.assurance} /></td>
      <td className="px-4 py-4 text-right">
        <Button variant="ghost" size="compact" onClick={() => onInspect(entry)}>
          <Info aria-hidden="true" className="size-4" />
          조건 보기
        </Button>
      </td>
    </tr>
  );
}

function IntegrationMobileRow({
  entry,
  onInspect,
}: {
  entry: IntegrationView;
  onInspect: (entry: IntegrationView) => void;
}) {
  const category = CATEGORY_COPY[entry.category];
  const lifecycle = LIFECYCLE_COPY[entry.lifecycleStatus];
  const Icon = category.icon;
  return (
    <article data-testid={`integration-${entry.id}`} className="py-5">
      <div className="flex items-start gap-3">
        <Icon aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-muted" />
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-text">{entry.name}</h3>
          <p className="mt-1 text-sm leading-6 text-muted">{entry.summary}</p>
        </div>
      </div>
      <dl className="mt-4 grid grid-cols-2 gap-4 text-sm">
        <div>
          <dt className="text-xs text-muted">서버 상태</dt>
          <dd className="mt-1"><StatusMark label={lifecycle.label} tone={lifecycle.tone} /></dd>
        </div>
        <div>
          <dt className="text-xs text-muted">설치 실행</dt>
          <dd className="mt-1"><StatusMark label="차단" tone="warning" /></dd>
        </div>
        <div className="col-span-2">
          <dt className="text-xs text-muted">원복 보장</dt>
          <dd className="mt-1"><AssuranceMark assurance={entry.assurance} /></dd>
        </div>
      </dl>
      <Button className="mt-4 w-full" variant="secondary" onClick={() => onInspect(entry)}>
        <Info aria-hidden="true" className="size-4" />
        설치 조건과 실행 방법 보기
      </Button>
    </article>
  );
}

function IntegrationInspector({ entry }: { entry: IntegrationView }) {
  const lifecycle = LIFECYCLE_COPY[entry.lifecycleStatus];
  return (
    <div>
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
        <StatusMark label={lifecycle.label} tone={lifecycle.tone} />
        <StatusMark label="설치 실행 차단" tone="warning" />
      </div>
      <p className="mt-5 text-sm leading-6 text-muted">{entry.summary}</p>
      <div className="mt-6">
        <AssuranceDetails assurance={entry.assurance} />
      </div>
      <InspectorList title="필요한 자원과 권한" values={entry.resourceClaims} />
      <InspectorList title="현재 설치 차단 사유" values={entry.installBlockers} tone="warning" />
      <InspectorList title="설정·실행 순서" values={entry.setupSteps} ordered />
      {entry.detectedComponents.length > 0 ? (
        <InspectorList title="감지된 구성" values={entry.detectedComponents} />
      ) : null}
      <Button asChild className="mt-7 w-full" variant="secondary">
        <a href={entry.sourceUrl} target="_blank" rel="noreferrer">
          독립 제품 저장소 확인
          <ExternalLink aria-hidden="true" className="size-4" />
        </a>
      </Button>
      <p className="mt-3 text-xs leading-5 text-muted">
        이 링크는 설치 실행이 아닙니다. JW Agent는 외부 저장소의 명령을 자동 실행하지 않습니다.
      </p>
    </div>
  );
}

function InspectorList({
  title,
  values,
  ordered = false,
  tone = "neutral",
}: {
  title: string;
  values: string[];
  ordered?: boolean;
  tone?: "neutral" | "warning";
}) {
  const List = ordered ? "ol" : "ul";
  return (
    <section className="mt-7 border-t border-border pt-5">
      <h3 className="text-sm font-semibold text-text">{title}</h3>
      <List
        className={
          ordered
            ? "mt-3 list-decimal space-y-2 pl-5 text-sm leading-6 text-muted"
            : "mt-3 space-y-2 text-sm leading-6 text-muted"
        }
      >
        {values.map((value) => (
          <li key={value} className={tone === "warning" ? "font-medium text-text" : undefined}>
            {ordered ? value : `— ${value}`}
          </li>
        ))}
      </List>
    </section>
  );
}

function SummaryValue({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-surface p-4">
      <dt className="text-xs text-muted">{label}</dt>
      <dd className="mt-2 text-lg font-semibold text-text">{value}</dd>
    </div>
  );
}
