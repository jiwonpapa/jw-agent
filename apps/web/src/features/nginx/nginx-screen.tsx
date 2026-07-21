import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowRight,
  CheckCircle2,
  CircleDot,
  FileLock2,
  Info,
  KeyRound,
  LoaderCircle,
  RotateCcw,
  Server,
  ShieldAlert,
  TriangleAlert,
  XCircle,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState, type SyntheticEvent } from "react";

import {
  ApiError,
  approveNginxSiteState,
  getOperationReceipt,
  planNginxSiteState,
  reauthenticateForOperation,
  watchOperationEvents,
} from "../../shared/api/client";
import { nginxSitesQueryOptions, queryKeys } from "../../shared/api/queries";
import type {
  NginxSiteObservation,
  NginxSiteState,
  NginxSiteStatePlanView,
  OperationAcceptedView,
  OperationReceiptView,
  OperationStage,
} from "../../shared/api/types";
import { formatDateTime } from "../../shared/domain/format";
import { AssuranceDetails, AssuranceMark } from "../../shared/ui/assurance";
import { Button } from "../../shared/ui/button";
import { Input } from "../../shared/ui/input";
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
  siteId: string | null;
  availableDigest: string | null;
  enabledStateDigest: string | null;
  operationType: string | null;
  operationSchemaVersion: number | null;
  assurance: NginxSiteObservation["assurance"];
}

const STAGE_LABELS: Record<OperationStage, string> = {
  PLANNED: "계획 생성",
  APPROVED: "승인 완료",
  SNAPSHOTTED: "이전 상태 저장",
  APPLYING: "설정 적용",
  VALIDATING: "문법 검사",
  RELOADING: "서비스 reload",
  VERIFYING: "적용 상태 확인",
  ROLLING_BACK: "이전 상태 원복",
  SUCCEEDED: "적용 완료",
  ROLLED_BACK: "실패 · 원복 완료",
  RECOVERY_REQUIRED: "실패 · 수동 복구 필요",
  REJECTED: "실행 거부",
  EXPIRED: "계획 만료",
  CANCELLED_BEFORE_APPLY: "적용 전 취소",
};

function toRow(site: NginxSiteObservation): NginxRowView {
  return {
    id: site.siteId ?? site.name,
    name: site.name,
    sourceState: site.available ? "설정 발견" : "원본 없음",
    enabledLabel: site.enabled ? "활성" : "비활성",
    protectedLabel: site.protected ? "제품 보호" : "일반 리소스",
    enabled: site.enabled,
    protected: site.protected,
    sourceAvailable: site.available,
    siteId: site.siteId ?? null,
    availableDigest: site.availableDigest ?? null,
    enabledStateDigest: site.enabledStateDigest ?? null,
    operationType: site.operationType ?? null,
    operationSchemaVersion: site.operationSchemaVersion ?? null,
    assurance: site.assurance,
  };
}

function operationKey(): string {
  return `web_${crypto.randomUUID()}`;
}

export function NginxScreen() {
  const sitesQuery = useQuery(nginxSitesQueryOptions);
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const [plan, setPlan] = useState<NginxSiteStatePlanView | null>(null);
  const [accepted, setAccepted] = useState<OperationAcceptedView | null>(null);
  const [receipt, setReceipt] = useState<OperationReceiptView | null>(null);
  const [planning, setPlanning] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const requestInFlight = useRef(false);
  const approvalKey = useRef<string | null>(null);
  const rows = useMemo(() => sitesQuery.data?.sites.map(toRow) ?? [], [sitesQuery.data?.sites]);
  const selected = rows.find((row) => row.id === selectedId) ?? null;
  const operationReady = rows.some(canPlan);

  useEffect(() => {
    if (accepted === null) return;
    const operation = accepted;
    const controller = new AbortController();
    let closeStream: () => void = () => undefined;
    let refreshQueue = Promise.resolve();

    function refreshReceipt(): void {
      refreshQueue = refreshQueue.then(async () => {
        try {
          const current = await getOperationReceipt(operation.operationId, controller.signal);
          setReceipt(current);
          if (isTerminalStage(current.terminalState)) {
            closeStream();
            setAccepted(null);
            await queryClient.invalidateQueries({ queryKey: queryKeys.nginxSites });
          }
        } catch (error) {
          if (!(error instanceof DOMException && error.name === "AbortError")) {
            setErrorMessage(operationErrorCopy(error, "작업 진행 영수증을 불러오지 못했습니다."));
          }
        }
      });
    }

    closeStream = watchOperationEvents(
      operation.eventStream,
      refreshReceipt,
      refreshReceipt,
    );
    refreshReceipt();
    return () => {
      controller.abort();
      closeStream();
    };
  }, [accepted, queryClient]);

  function inspect(row: NginxRowView): void {
    setSelectedId(row.id);
    setPlan(null);
    setAccepted(null);
    setReceipt(null);
    setErrorMessage(null);
    approvalKey.current = null;
    requestInFlight.current = false;
    setInspectorOpen(true);
  }

  async function createPlan(row: NginxRowView): Promise<void> {
    if (requestInFlight.current || !canPlan(row)) return;
    requestInFlight.current = true;
    setPlanning(true);
    setErrorMessage(null);
    setAccepted(null);
    setReceipt(null);
    try {
      const idempotencyKey = operationKey();
      const nextPlan = await planNginxSiteState({
        schemaVersion: row.operationSchemaVersion,
        operationType: row.operationType,
        siteId: row.siteId,
        targetState: row.enabled ? "disabled" : "enabled",
        expectedAvailableDigest: row.availableDigest,
        expectedEnabledStateDigest: row.enabledStateDigest,
        idempotencyKey,
      });
      approvalKey.current = idempotencyKey;
      setPlan(nextPlan);
    } catch (error) {
      setErrorMessage(operationErrorCopy(error, "변경 계획을 만들지 못했습니다."));
      await queryClient.invalidateQueries({ queryKey: queryKeys.nginxSites });
    } finally {
      requestInFlight.current = false;
      setPlanning(false);
    }
  }

  async function approvePlan(password: string): Promise<void> {
    if (requestInFlight.current || plan === null || approvalKey.current === null) return;
    requestInFlight.current = true;
    setExecuting(true);
    setErrorMessage(null);
    try {
      const reauth = await reauthenticateForOperation({ password, planHash: plan.planHash });
      queryClient.setQueryData(queryKeys.session, reauth.session);
      const operation = await approveNginxSiteState({
        schemaVersion: plan.schemaVersion,
        planId: plan.planId,
        planHash: plan.planHash,
        idempotencyKey: approvalKey.current,
        reauthToken: reauth.reauthToken,
      });
      setAccepted(operation);
    } catch (error) {
      setErrorMessage(operationErrorCopy(error, "승인한 작업을 완료하지 못했습니다."));
    } finally {
      requestInFlight.current = false;
      setExecuting(false);
    }
  }

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Services / Nginx"
        title="Nginx 사이트"
        description="Ubuntu 표준 layout의 site 상태를 확인하고, 지원되는 항목만 계획·재인증·자동 원복 절차로 변경합니다."
        action={
          sitesQuery.isPending ? (
            <StatusMark label="보장 확인 중" tone="neutral" />
          ) : operationReady ? (
            <StatusMark label="G2 제한 작업 가능" tone="info" />
          ) : (
            <StatusMark label="변경 차단" tone="warning" />
          )
        }
      />

      <section className="py-6" aria-labelledby="inventory-heading">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 id="inventory-heading" className="text-sm font-semibold text-text">
              사이트 inventory
            </h2>
            <p className="mt-1 text-sm text-muted">
              {sitesQuery.data
                ? `관찰 시각 ${formatDateTime(sitesQuery.data.observedAt)}`
                : "canonical 상태 조회 중"}
            </p>
          </div>
          {sitesQuery.data?.truncated ? (
            <StatusMark label="일부 결과만 표시" tone="warning" />
          ) : null}
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
            description="설치는 지원 범위가 확정된 typed operation에서만 제공합니다."
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
          <SiteInventory rows={rows} onInspect={inspect} />
        )}
      </section>

      {sitesQuery.data?.status === "partial" ? (
        <section className="border-y border-warning/35 py-4" aria-label="부분 관찰 경고">
          <div className="flex items-start gap-3">
            <ShieldAlert aria-hidden="true" className="mt-0.5 size-5 text-warning" />
            <div>
              <p className="text-sm font-semibold text-text">일부 사이트만 관찰되었습니다</p>
              <p className="mt-1 text-sm leading-6 text-muted">
                표시되지 않은 리소스를 없거나 비활성인 것으로 판단하지 마세요.
              </p>
            </div>
          </div>
        </section>
      ) : null}

      <Sheet
        open={inspectorOpen}
        onOpenChange={setInspectorOpen}
        title={selected?.name ?? "사이트 상세"}
        description={plan ? "변경 계획과 자동 원복 범위" : "발견된 Nginx site 상태"}
        side="right"
      >
        {selected ? (
          <SiteInspector
            row={selected}
            plan={plan}
            accepted={accepted}
            receipt={receipt}
            planning={planning}
            executing={executing}
            errorMessage={errorMessage}
            onCreatePlan={() => void createPlan(selected)}
            onApprove={(password) => approvePlan(password)}
          />
        ) : null}
      </Sheet>
    </div>
  );
}

function SiteInventory({
  rows,
  onInspect,
}: {
  rows: NginxRowView[];
  onInspect: (row: NginxRowView) => void;
}) {
  return (
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
                  <StatusMark
                    label={row.enabledLabel}
                    tone={row.enabled ? "success" : "neutral"}
                  />
                </td>
                <td className="px-4 py-3">
                  <StatusMark
                    label={row.protectedLabel}
                    tone={row.protected ? "warning" : "neutral"}
                  />
                </td>
                <td className="px-4 py-3">
                  <AssuranceMark assurance={row.assurance} />
                </td>
                <td className="px-4 py-3 text-right">
                  <Button variant="ghost" size="compact" onClick={() => onInspect(row)}>
                    <Info aria-hidden="true" className="size-4" />
                    {canPlan(row) ? "계획 보기" : "상세"}
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
              <StatusMark
                label={row.enabledLabel}
                tone={row.enabled ? "success" : "neutral"}
              />
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
            <Button className="mt-4 w-full" variant="secondary" onClick={() => onInspect(row)}>
              <Info aria-hidden="true" className="size-4" />
              {canPlan(row) ? "변경 계획 열기" : "상세 보기"}
            </Button>
          </article>
        ))}
      </div>
    </>
  );
}

function SiteInspector({
  row,
  plan,
  accepted,
  receipt,
  planning,
  executing,
  errorMessage,
  onCreatePlan,
  onApprove,
}: {
  row: NginxRowView;
  plan: NginxSiteStatePlanView | null;
  accepted: OperationAcceptedView | null;
  receipt: OperationReceiptView | null;
  planning: boolean;
  executing: boolean;
  errorMessage: string | null;
  onCreatePlan: () => void;
  onApprove: (password: string) => Promise<void>;
}) {
  if (plan !== null) {
    return (
      <OperationPlan
        plan={plan}
        accepted={accepted}
        receipt={receipt}
        executing={executing}
        errorMessage={errorMessage}
        onApprove={onApprove}
      />
    );
  }
  return (
    <div>
      <div className="flex size-10 items-center justify-center rounded-control bg-subtle text-text">
        {row.protected ? (
          <FileLock2 aria-hidden="true" className="size-5" />
        ) : (
          <Server aria-hidden="true" className="size-5" />
        )}
      </div>
      <dl className="mt-6 divide-y divide-border border-y border-border text-sm">
        <DetailRow label="상태" value={row.enabledLabel} />
        <DetailRow label="설정 원본" value={row.sourceState} />
        <DetailRow label="소유권" value={row.protectedLabel} />
        <DetailRow
          label="다음 변경"
          value={canPlan(row) ? (row.enabled ? "비활성화" : "활성화") : "차단됨"}
        />
      </dl>
      <div className="mt-5">
        <AssuranceDetails assurance={row.assurance} />
      </div>
      {errorMessage ? (
        <p role="alert" className="mt-5 text-sm font-medium leading-6 text-danger">
          {errorMessage}
        </p>
      ) : null}
      {canPlan(row) ? (
        <Button className="mt-6 w-full" disabled={planning} onClick={onCreatePlan}>
          {planning ? (
            <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />
          ) : (
            <RotateCcw aria-hidden="true" className="size-4" />
          )}
          {planning ? "현재 상태 재검증 중" : `${row.enabled ? "비활성화" : "활성화"} 계획 만들기`}
        </Button>
      ) : null}
    </div>
  );
}

function OperationPlan({
  plan,
  accepted,
  receipt,
  executing,
  errorMessage,
  onApprove,
}: {
  plan: NginxSiteStatePlanView;
  accepted: OperationAcceptedView | null;
  receipt: OperationReceiptView | null;
  executing: boolean;
  errorMessage: string | null;
  onApprove: (password: string) => Promise<void>;
}) {
  const [password, setPassword] = useState("");

  async function submit(event: SyntheticEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const submittedPassword = password;
    setPassword("");
    await onApprove(submittedPassword);
  }

  if (receipt !== null) return <OperationResult receipt={receipt} />;

  if (accepted !== null) {
    return (
      <div aria-live="polite">
        <div className="flex items-start gap-3">
          <LoaderCircle aria-hidden="true" className="size-6 shrink-0 animate-spin text-warning" />
          <div>
            <h3 className="text-base font-semibold text-text">
              {STAGE_LABELS[accepted.currentStage]}
            </h3>
            <p className="mt-1 text-sm leading-6 text-muted">
              작업은 서버에서 계속됩니다. 연결이 끊겨도 이력에서 최종 결과를 다시 확인할 수 있습니다.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center gap-2 text-sm font-semibold text-text">
        <span>{stateLabel(plan.currentState)}</span>
        <ArrowRight aria-hidden="true" className="size-4 text-muted" />
        <span>{stateLabel(plan.targetState)}</span>
      </div>
      <p className="mt-2 text-sm leading-6 text-muted">
        대상은 <strong className="font-semibold text-text">{plan.displayName}</strong> 하나입니다.
        계획 만료 시각은 {formatDateTime(plan.expiresAt)}입니다.
      </p>

      <section className="mt-6 border-y border-border py-4" aria-labelledby="impact-heading">
        <h3 id="impact-heading" className="text-xs font-semibold text-muted">실행 영향</h3>
        <BulletList values={plan.impact} />
      </section>

      <div className="mt-5">
        <AssuranceDetails assurance={plan.assurance} />
      </div>

      <section className="mt-5 border-y border-warning/35 py-4" aria-labelledby="recovery-heading">
        <div className="flex items-start gap-3">
          <TriangleAlert aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-warning" />
          <div>
            <h3 id="recovery-heading" className="text-sm font-semibold text-text">
              원복 검증도 실패하면 수동 복구가 필요합니다
            </h3>
            <BulletList values={plan.recoveryPath} />
          </div>
        </div>
      </section>

      <dl className="mt-5 text-xs text-muted">
        <dt className="font-semibold">계획 hash</dt>
        <dd className="mt-1 break-all font-mono leading-5">{plan.planHash}</dd>
      </dl>

      {errorMessage ? (
        <p role="alert" className="mt-5 text-sm font-medium leading-6 text-danger">
          {errorMessage}
        </p>
      ) : null}

      <form className="mt-6" onSubmit={(event) => void submit(event)}>
        <label htmlFor="operation-password" className="mb-2 block text-sm font-medium text-text">
          Linux 계정 비밀번호로 이 계획 승인
        </label>
        <Input
          id="operation-password"
          type="password"
          autoComplete="current-password"
          maxLength={1024}
          required
          disabled={executing}
          value={password}
          onChange={(event) => setPassword(event.currentTarget.value)}
        />
        <Button className="mt-4 w-full" type="submit" disabled={executing || password.length === 0}>
          {executing ? (
            <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />
          ) : (
            <KeyRound aria-hidden="true" className="size-4" />
          )}
          {executing ? "적용·검증·원복 판단 중" : "재인증 후 실행"}
        </Button>
      </form>
    </div>
  );
}

function OperationResult({ receipt }: { receipt: OperationReceiptView }) {
  const failure = receipt.terminalState === "RECOVERY_REQUIRED";
  const rolledBack = receipt.terminalState === "ROLLED_BACK";
  const succeeded = receipt.terminalState === "SUCCEEDED";
  const terminal = isTerminalStage(receipt.terminalState);
  return (
    <div aria-live="polite">
      <div className="flex items-start gap-3">
        {succeeded ? (
          <CheckCircle2 aria-hidden="true" className="size-6 shrink-0 text-success" />
        ) : failure ? (
          <XCircle aria-hidden="true" className="size-6 shrink-0 text-danger" />
        ) : !terminal ? (
          <LoaderCircle aria-hidden="true" className="size-6 shrink-0 animate-spin text-warning" />
        ) : (
          <RotateCcw aria-hidden="true" className="size-6 shrink-0 text-warning" />
        )}
        <div>
          <h3 className="text-base font-semibold text-text">
            {STAGE_LABELS[receipt.terminalState]}
          </h3>
          <p className="mt-1 text-sm leading-6 text-muted">
            {succeeded
              ? "적용 후 문법·reload·active 상태를 확인했습니다."
              : rolledBack
                ? "적용은 실패했지만 이전 link 상태 복원과 재검증을 마쳤습니다."
                : !terminal
                  ? "작업은 서버에서 계속됩니다. 표시된 단계는 감사 원장에 기록된 상태입니다."
                  : "성공으로 처리하지 않았습니다. 아래 단계와 복구 경로를 확인하세요."}
          </p>
        </div>
      </div>

      <ol className="mt-6 border-y border-border py-2">
        {receipt.stages.map((stage) => (
          <li key={stage.sequence} className="flex gap-3 py-3 text-sm">
            <CircleDot aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted" />
            <div className="min-w-0">
              <p className="font-medium text-text">{STAGE_LABELS[stage.stage]}</p>
              <p className="mt-1 break-words text-xs text-muted">
                {formatDateTime(stage.recordedAt)} · {stage.resultCode}
              </p>
            </div>
          </li>
        ))}
      </ol>

      {receipt.recoveryPath.length > 0 ? (
        <section className="mt-5 border-y border-danger/35 py-4">
          <h4 className="text-sm font-semibold text-text">수동 복구 경로</h4>
          <BulletList values={receipt.recoveryPath} />
        </section>
      ) : null}

      <div className="mt-5">
        <AssuranceDetails assurance={receipt.assurance} />
      </div>
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4 py-4">
      <dt className="text-muted">{label}</dt>
      <dd className="text-right font-medium text-text">{value}</dd>
    </div>
  );
}

function BulletList({ values }: { values: string[] }) {
  return (
    <ul className="mt-2 space-y-1 text-sm leading-6 text-muted">
      {values.map((value) => (
        <li key={value} className="flex gap-2">
          <span aria-hidden="true">·</span>
          <span>{value}</span>
        </li>
      ))}
    </ul>
  );
}

function stateLabel(state: NginxSiteState): string {
  return state === "enabled" ? "활성" : "비활성";
}

function isTerminalStage(stage: OperationStage): boolean {
  return [
    "SUCCEEDED",
    "ROLLED_BACK",
    "RECOVERY_REQUIRED",
    "REJECTED",
    "EXPIRED",
    "CANCELLED_BEFORE_APPLY",
  ].includes(stage);
}

function canPlan(row: NginxRowView): row is NginxRowView & {
  siteId: string;
  availableDigest: string;
  enabledStateDigest: string;
  operationType: string;
  operationSchemaVersion: number;
} {
  return (
    row.assurance.operationAvailable &&
    row.assurance.level === "g2_reversible_config" &&
    !row.protected &&
    row.sourceAvailable &&
    row.siteId !== null &&
    row.availableDigest !== null &&
    row.enabledStateDigest !== null &&
    row.operationType !== null &&
    row.operationSchemaVersion !== null
  );
}

function operationErrorCopy(error: unknown, fallback: string): string {
  if (!(error instanceof ApiError)) return fallback;
  if (error.status === 401) return "재인증에 실패했거나 세션이 만료되었습니다.";
  if (error.status === 403) return "현재 계정 또는 exact-plan 재인증으로 승인할 수 없습니다.";
  if (error.status === 409) return "계획이 만료·변경되었거나 다른 작업이 진행 중입니다. 상태를 다시 확인하세요.";
  if (error.status === 423) return "감사 원장 무결성 잠금으로 모든 변경이 차단되었습니다.";
  if (error.status === 428) return "설정된 추가 인증 수단을 사용할 수 없어 변경이 차단되었습니다.";
  return fallback;
}
