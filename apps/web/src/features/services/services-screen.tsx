import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, ListFilter, LoaderCircle, Play, Search, ServerCog, TriangleAlert } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { ApiError, approveServiceControl, getOperationReceipt, planServiceControl, watchOperationEvents } from "../../shared/api/client";
import type { ManagedServiceAction, OperationAcceptedView, OperationReceiptView, OperationStage, ServiceControlPlanView, ServiceSummary } from "../../shared/api/types";
import { queryKeys, servicesQueryOptions, sessionQueryOptions } from "../../shared/api/queries";
import { formatDateTime } from "../../shared/domain/format";
import { Button } from "../../shared/ui/button";
import { cn } from "../../shared/ui/cn";
import { Skeleton } from "../../shared/ui/skeleton";
import { Sheet } from "../../shared/ui/sheet";
import { StatusMark } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";
import { PrimaryServiceGrid, ServiceList, ServiceRow } from "./service-list";
import { SERVICE_FILTERS, matchesFilter, type ServiceFilter } from "./service-presenter";
import { useAdministrativeAccess } from "../auth/administrative-access";

export function ServicesScreen() {
  const inventory = useQuery(servicesQueryOptions);
  const queryClient = useQueryClient();
  const session = useQuery(sessionQueryOptions).data;
  const { requestAccess } = useAdministrativeAccess();
  const [filter, setFilter] = useState<ServiceFilter>("all");
  const [systemSearch, setSystemSearch] = useState("");
  const [controlTarget, setControlTarget] = useState<{ service: ServiceSummary; action: ManagedServiceAction } | null>(null);
  const [controlPlan, setControlPlan] = useState<ServiceControlPlanView | null>(null);
  const [controlAccepted, setControlAccepted] = useState<OperationAcceptedView | null>(null);
  const [controlReceipt, setControlReceipt] = useState<OperationReceiptView | null>(null);
  const [controlBusy, setControlBusy] = useState(false);
  const [controlError, setControlError] = useState<string | null>(null);
  const controlKey = useRef<string | null>(null);
  const services = inventory.data?.services ?? [];
  const filtered = services.filter((service) => matchesFilter(service, filter));
  const primary = filtered.filter((service) => service.visibility === "primary");
  const discovered = filtered.filter((service) => service.visibility === "discovered");
  const system = filtered.filter((service) => service.visibility === "system");
  const failed = services.filter((service) => service.runtimeState === "failed");

  useEffect(() => {
    if (controlAccepted === null) return;
    const operation = controlAccepted;
    const controller = new AbortController();
    let closeStream: () => void = () => undefined;
    async function refresh(): Promise<void> {
      try {
        const receipt = await getOperationReceipt(operation.operationId, controller.signal);
        setControlReceipt(receipt);
        if (isTerminal(receipt.terminalState)) {
          closeStream();
          setControlAccepted(null);
          await queryClient.invalidateQueries({ queryKey: queryKeys.services });
        }
      } catch (error) {
        if (!(error instanceof DOMException && error.name === "AbortError")) setControlError(controlErrorCopy(error));
      }
    }
    closeStream = watchOperationEvents(operation.eventStream, () => void refresh(), () => void refresh());
    void refresh();
    return () => { controller.abort(); closeStream(); };
  }, [controlAccepted, queryClient]);

  async function beginControl(service: ServiceSummary, action: ManagedServiceAction, administrativeConfirmed = false): Promise<void> {
    if (!administrativeConfirmed && session?.administrativeAccess !== "administrative") {
      requestAccess(() => void beginControl(service, action, true));
      return;
    }
    if (service.operationType !== "service.lifecycle.set/v1" || service.operationSchemaVersion == null) return;
    setControlTarget({ service, action });
    setControlPlan(null);
    setControlReceipt(null);
    setControlError(null);
    setControlBusy(true);
    const idempotencyKey = `web_${crypto.randomUUID()}`;
    controlKey.current = idempotencyKey;
    try {
      setControlPlan(await planServiceControl({
        schemaVersion: service.operationSchemaVersion,
        operationType: service.operationType,
        serviceId: service.serviceId,
        action,
        expectedStateDigest: service.stateDigest,
        idempotencyKey,
      }));
    } catch (error) {
      setControlError(controlErrorCopy(error));
    } finally {
      setControlBusy(false);
    }
  }

  async function approveControl(): Promise<void> {
    if (controlPlan === null || controlKey.current === null || controlBusy) return;
    setControlBusy(true);
    setControlError(null);
    try {
      setControlAccepted(await approveServiceControl({
        schemaVersion: controlPlan.schemaVersion,
        planId: controlPlan.planId,
        planHash: controlPlan.planHash,
        idempotencyKey: controlKey.current,
        impactConfirmed: true,
      }));
    } catch (error) {
      setControlError(controlErrorCopy(error));
    } finally {
      setControlBusy(false);
    }
  }

  function closeControl(): void {
    if (controlAccepted !== null) return;
    setControlTarget(null);
    setControlPlan(null);
    setControlReceipt(null);
    setControlError(null);
    controlKey.current = null;
  }

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Services"
        title="서비스"
        description="Ubuntu가 실제로 보고한 서비스를 확인하고 지원 대상은 안전 절차로 제어합니다."
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
          <section className="mt-6 rounded-panel border border-border bg-surface p-5" aria-labelledby="primary-services-heading">
            <h2 id="primary-services-heading" className="text-sm font-semibold text-text">주요 서비스</h2>
            <p className="mt-1 text-sm text-muted">같은 서비스의 timer·instance는 한 카드 안에서 확인합니다.</p>
            <PrimaryServiceGrid services={primary} onAction={(service, action) => void beginControl(service, action)} />
          </section>
          <ServiceList
            title="발견된 서비스"
            description="서버 관리자가 추가한 systemd unit이며 JW Agent는 역할을 추측하지 않습니다."
            services={discovered}
            emptyLabel="발견된 사용자 정의 서비스가 없습니다."
            onAction={(service, action) => void beginControl(service, action)}
          />
          <SystemServices services={system} search={systemSearch} onSearch={setSystemSearch} />
          <p className="border-t border-border pt-5 text-xs text-muted">
            템플릿 {inventory.data.templateProfile} · 최대 512개 · Nginx와 PHP 8.3 FPM만 lifecycle 제어 지원
          </p>
        </>
      )}

      <Sheet open={controlTarget !== null} onOpenChange={(open) => { if (!open) closeControl(); }} title={controlTarget === null ? "서비스 작업" : `${controlTarget.service.displayName} ${actionLabel(controlTarget.action)}`} description="계획 → 실행 → 상태 확인 → 실패 시 이전 active 상태 복구" side="right" size="wide">
        <ServiceControlPanel target={controlTarget} plan={controlPlan} accepted={controlAccepted} receipt={controlReceipt} busy={controlBusy} error={controlError} onApprove={() => void approveControl()} />
      </Sheet>
    </div>
  );
}

function ServiceControlPanel({ target, plan, accepted, receipt, busy, error, onApprove }: {
  target: { service: ServiceSummary; action: ManagedServiceAction } | null;
  plan: ServiceControlPlanView | null;
  accepted: OperationAcceptedView | null;
  receipt: OperationReceiptView | null;
  busy: boolean;
  error: string | null;
  onApprove: () => void;
}) {
  if (target === null) return null;
  if (busy && plan === null) return <div className="flex items-center gap-3 text-sm text-muted"><LoaderCircle aria-hidden="true" className="size-5 animate-spin" />현재 서비스 상태와 작업 가능 여부를 확인합니다.</div>;
  if (receipt !== null && isTerminal(receipt.terminalState)) {
    const success = receipt.terminalState === "SUCCEEDED";
    return <section className={success ? "rounded-panel border border-success/35 bg-success/5 p-5" : "rounded-panel border border-warning/35 bg-warning/5 p-5"}><div className="flex items-start gap-3"><CheckCircle2 aria-hidden="true" className={success ? "size-6 text-success" : "size-6 text-warning"} /><div><h3 className="font-semibold text-text">{success ? "서비스 작업 완료" : receipt.terminalState === "ROLLED_BACK" ? "실패 후 이전 상태 복구 완료" : "수동 확인 필요"}</h3><p className="mt-1 text-sm text-muted">{receipt.displayName} · {receipt.terminalState}</p></div></div></section>;
  }
  if (accepted !== null) return <div className="flex min-h-48 items-center justify-center gap-3"><LoaderCircle aria-hidden="true" className="size-6 animate-spin text-action" /><p className="text-sm text-muted">작업 실행 후 systemd 상태를 다시 확인하고 있습니다.</p></div>;
  if (plan === null) return <p role="alert" className="text-sm text-danger">{error ?? "서비스 계획을 만들지 못했습니다."}</p>;
  return (
    <div>
      <section className={target.action === "stop" ? "rounded-panel border border-danger/35 bg-danger/5 p-5" : "rounded-panel border border-border bg-subtle/40 p-5"}>
        <div className="flex items-start gap-3"><TriangleAlert aria-hidden="true" className={target.action === "stop" ? "size-5 text-danger" : "size-5 text-warning"} /><div><h3 className="font-semibold text-text">{actionLabel(target.action)} 작업을 적용하시겠습니까?</h3><p className="mt-1 text-sm leading-6 text-muted">{target.action === "stop" ? "서비스가 중지되며 연결된 웹 요청이 즉시 실패할 수 있습니다." : "작업 후 active 상태를 읽어 확인하고 실패하면 이전 상태 복구를 시도합니다."}</p></div></div>
      </section>
      <dl className="mt-4 grid gap-3 rounded-panel border border-border p-4 text-sm sm:grid-cols-2"><div><dt className="text-xs text-muted">unit</dt><dd className="mt-1 font-mono text-text">{plan.unitName}</dd></div><div><dt className="text-xs text-muted">현재 상태</dt><dd className="mt-1 font-medium text-text">{plan.currentActive ? "실행 중" : "중지"}</dd></div></dl>
      <details className="mt-4 rounded-panel border border-border p-4"><summary className="cursor-pointer text-sm font-semibold text-text">영향과 복구 경로 보기</summary><ul className="mt-3 space-y-1 text-sm text-muted">{[...plan.impact, ...plan.recoveryPath].map((item) => <li key={item}>· {item}</li>)}</ul></details>
      {error ? <p role="alert" className="mt-4 text-sm font-medium text-danger">{error}</p> : null}
      <Button className="mt-5 w-full" variant={target.action === "stop" ? "danger" : "primary"} disabled={busy} onClick={onApprove}>{busy ? <LoaderCircle aria-hidden="true" className="size-4 animate-spin" /> : <Play aria-hidden="true" className="size-4" />}{busy ? "승인 중" : `${actionLabel(target.action)} 적용`}</Button>
    </div>
  );
}

function actionLabel(action: ManagedServiceAction): string {
  if (action === "start") return "시작";
  if (action === "stop") return "중지";
  if (action === "restart") return "재시작";
  return "reload";
}

function isTerminal(stage: OperationStage): boolean {
  return ["SUCCEEDED", "ROLLED_BACK", "RECOVERY_REQUIRED", "REJECTED", "EXPIRED", "CANCELLED_BEFORE_APPLY"].includes(stage);
}

function controlErrorCopy(error: unknown): string {
  if (!(error instanceof ApiError)) return "서비스 작업을 완료하지 못했습니다.";
  if (error.message.includes("management_ingress_dependency")) {
    return "독립 관리 접속 경로가 준비되지 않아 Nginx 중지를 차단했습니다. JW Edge 상태를 먼저 확인하세요.";
  }
  if (error.status === 409) return "서비스 상태가 바뀌었거나 다른 작업이 진행 중입니다. 새로 관찰한 뒤 다시 시도하세요.";
  if (error.status === 423) return "감사 원장 무결성 잠금으로 변경이 차단되었습니다.";
  return error.message;
}

function InventorySummary({ services, partial }: { services: ServiceSummary[]; partial: boolean }) {
  const running = services.filter(
    (service) => service.runtimeState === "running" || service.runtimeState === "active",
  ).length;
  const failed = services.filter((service) => service.runtimeState === "failed").length;
  const stopped = services.filter((service) => service.runtimeState === "stopped").length;
  return (
    <section className="mt-6 rounded-panel border border-border bg-surface p-5" aria-labelledby="service-summary-heading">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 id="service-summary-heading" className="text-sm font-semibold text-text">관찰 요약</h2>
          <p className="mt-1 text-sm text-muted">설치된 unit만 집계하며 미설치를 중지로 만들지 않습니다.</p>
        </div>
        <StatusMark label={partial ? "부분 관찰" : "관찰 완료"} tone={partial ? "warning" : "success"} />
      </div>
      <dl className="mt-5 grid gap-px overflow-hidden rounded-control border border-border bg-border sm:grid-cols-4">
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
    <div className="bg-subtle/35 px-4 py-4">
      <dt className="text-xs text-muted">{label}</dt>
      <dd className={cn("mt-1 text-2xl font-semibold text-text", danger && "text-danger")}>{value}</dd>
    </div>
  );
}

function FailureNotice({ services }: { services: ServiceSummary[] }) {
  return (
    <section className="mt-5 rounded-panel border border-danger/35 bg-danger/5 p-5" aria-labelledby="failed-services-heading">
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
    <section className="mt-5 rounded-panel border border-border bg-surface p-4" aria-label="서비스 상태 필터">
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

function SystemServices({ services, search, onSearch }: {
  services: ServiceSummary[];
  search: string;
  onSearch: (value: string) => void;
}) {
  const normalized = search.trim().toLocaleLowerCase("ko-KR");
  const visible = normalized.length === 0
    ? services
    : services.filter((service) => `${service.displayName} ${service.unitName} ${service.purpose}`.toLocaleLowerCase("ko-KR").includes(normalized));
  return (
    <section className="mt-6 rounded-panel border border-border bg-surface p-5" aria-labelledby="system-services-heading">
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
        <label className="mt-4 flex max-w-md items-center gap-2 rounded-control border border-border bg-surface px-3">
          <Search aria-hidden="true" className="size-4 text-muted" />
          <span className="sr-only">시스템 서비스 검색</span>
          <input
            type="search"
            value={search}
            onChange={(event) => onSearch(event.target.value)}
            placeholder="unit 이름 검색"
            className="min-h-11 min-w-0 flex-1 bg-transparent text-sm text-text placeholder:text-muted"
          />
        </label>
        {visible.length === 0 ? (
          <p className="mt-4 border-y border-border py-5 text-sm text-muted">현재 필터에 해당하는 시스템 서비스가 없습니다.</p>
        ) : (
          <ul className="mt-5 grid gap-px overflow-hidden rounded-panel border border-border bg-border md:grid-cols-2 2xl:grid-cols-3">
            {visible.map((service) => (
              <li key={service.serviceId} className="min-w-0 bg-surface"><ServiceRow service={service} compact /></li>
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
