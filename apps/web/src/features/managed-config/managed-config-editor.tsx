import { useBlocker } from "@tanstack/react-router";
import {
  ArrowLeft,
  CheckCircle2,
  CircleDot,
  History,
  LoaderCircle,
  Play,
  RotateCcw,
  Save,
  TriangleAlert,
  XCircle,
} from "lucide-react";

import type {
  ManagedConfigPlanView,
  ManagedConfigResourceView,
  OperationAcceptedView,
  OperationReceiptView,
  OperationStage,
} from "../../shared/api/types";
import { formatDateTime } from "../../shared/domain/format";
import {
  managedConfigDiagnostics,
  managedConfigSyntaxDiagnosticLine,
  operationResultLabel,
} from "../../shared/domain/managed-config-diagnostic";
import { AssuranceDetails } from "../../shared/ui/assurance";
import { Button } from "../../shared/ui/button";
import {
  CodeEditor,
  type EditorDiagnostic,
  type EditorLanguage,
} from "../../shared/ui/code-editor";

const STAGE_LABELS: Record<OperationStage, string> = {
  PLANNED: "변경 준비",
  APPROVED: "변경 승인",
  SNAPSHOTTED: "이전 설정 백업",
  APPLYING: "설정 적용",
  VALIDATING: "문법 검사",
  RELOADING: "서비스 반영",
  VERIFYING: "작동 확인",
  ROLLING_BACK: "이전 설정 복구",
  SUCCEEDED: "저장 완료",
  ROLLED_BACK: "저장 실패 · 이전 설정 복구 완료",
  RECOVERY_REQUIRED: "저장 실패 · 수동 복구 필요",
  REJECTED: "변경 거부",
  EXPIRED: "변경 요청 만료",
  CANCELLED_BEFORE_APPLY: "적용 전 취소",
};

export interface ManagedConfigEditorProfile {
  language: EditorLanguage;
  contentLabel: string;
  validatorLabel: string;
  serviceLabel: string;
  backLabel: string;
}

interface ManagedConfigEditorProps {
  profile: ManagedConfigEditorProfile;
  resource: ManagedConfigResourceView;
  draft: string;
  plan: ManagedConfigPlanView | null;
  accepted: OperationAcceptedView | null;
  receipt: OperationReceiptView | null;
  planning: boolean;
  executing: boolean;
  errorMessage: string | null;
  diagnosticLine: number | null;
  history: OperationReceiptView[];
  historyLoading: boolean;
  historyError: boolean;
  restoreSource: OperationReceiptView | null;
  restorePlan: ManagedConfigPlanView | null;
  restoreAccepted: OperationAcceptedView | null;
  restoreReceipt: OperationReceiptView | null;
  restoreBusy: boolean;
  restoreError: string | null;
  serviceAction?: "reload" | "validate_only";
  onDraftChange: (value: string) => void;
  onBack: () => void;
  onSave: () => void;
  onRevise: (line: number | null) => void;
  onSelectRestore: (source: OperationReceiptView) => void;
  onApplyRestore: () => void;
  onCancelRestore: () => void;
}

export function ManagedConfigEditor({
  profile,
  resource,
  draft,
  plan,
  accepted,
  receipt,
  planning,
  executing,
  errorMessage,
  diagnosticLine,
  history,
  historyLoading,
  historyError,
  restoreSource,
  restorePlan,
  restoreAccepted,
  restoreReceipt,
  restoreBusy,
  restoreError,
  serviceAction = "reload",
  onDraftChange,
  onBack,
  onSave,
  onRevise,
  onSelectRestore,
  onApplyRestore,
  onCancelRestore,
}: ManagedConfigEditorProps) {
  const applied = receipt?.terminalState === "SUCCEEDED";
  const saveBusy = planning || executing || accepted !== null;
  const operationBusy = saveBusy || restoreBusy || restoreAccepted !== null;
  const hasUnappliedChanges = draft !== resource.content && !applied;
  const draftBytes = new TextEncoder().encode(draft).byteLength;
  const unchanged = draft === resource.content;
  const tooLarge = draftBytes > resource.maxBytes;
  const editorDiagnostics: EditorDiagnostic[] = managedConfigDiagnostics(receipt?.stages ?? [])
    .filter((diagnostic) => diagnostic.resourceId === resource.resourceId && diagnostic.line !== null)
    .flatMap((diagnostic) => [
      {
        line: diagnostic.line ?? 1,
        column: diagnostic.column ?? null,
        severity: diagnostic.severity,
        message: `${diagnostic.message} · 공식 검사기가 보고한 위치`,
      },
      ...(diagnostic.causeCandidateLines ?? []).map((line) => ({
        line,
        column: null,
        severity: "warning" as const,
        message: "직전 변경 중 원인 후보입니다. 세미콜론(;)과 중괄호를 확인하세요.",
      })),
    ]);

  useBlocker({
    enableBeforeUnload: hasUnappliedChanges,
    shouldBlockFn: () =>
      hasUnappliedChanges &&
      !window.confirm("저장하지 않은 설정 변경이 있습니다. 편집을 종료하시겠습니까?"),
  });

  const primaryAction = applied ? (
    <Button variant="secondary" onClick={onBack}>닫기</Button>
  ) : (
    <Button disabled={operationBusy || unchanged || tooLarge} onClick={onSave}>
      {saveBusy ? (
        <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />
      ) : (
        <Save aria-hidden="true" className="size-4" />
      )}
      {saveBusy ? "검증·저장 중" : "저장"}
    </Button>
  );

  return (
    <div className="relative">
      <header className="sticky top-0 z-20 -mx-3 border-b border-border bg-surface/95 px-3 pb-3 pt-1 backdrop-blur sm:-mx-6 sm:px-6">
        <div className="flex items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3">
            <Button aria-label={profile.backLabel} size="icon" variant="ghost" onClick={onBack}>
              <ArrowLeft aria-hidden="true" className="size-5" />
            </Button>
            <div className="min-w-0">
              <h2 className="truncate text-lg font-bold text-text">{resource.displayName}</h2>
              <p className="truncate font-mono text-xs text-muted">{resource.maskedPath}</p>
            </div>
          </div>
          <div className="hidden shrink-0 lg:block">{primaryAction}</div>
        </div>
      </header>

      <div className="py-4">
        <section className="mb-3 border-l-2 border-warning bg-warning/5 px-4 py-3 lg:hidden">
          <p className="text-sm font-semibold text-text">설정 변경은 데스크톱에서만 지원합니다.</p>
          <p className="mt-1 text-xs leading-5 text-muted">모바일·태블릿에서는 설정을 조회할 수 있지만 편집·저장은 차단됩니다.</p>
        </section>

        <section className="rounded-panel border border-border bg-subtle/35 px-4 py-3">
          <div className="flex items-start gap-3">
            <RotateCcw aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-action" />
            <p className="text-sm leading-6 text-muted">
              저장하면 <strong className="font-semibold text-text">{profile.validatorLabel}</strong> 후{" "}
              <strong className="font-semibold text-text">
                {serviceAction === "reload" ? `${profile.serviceLabel} reload` : "파일 read-back 검증"}
              </strong>을 실행합니다.
              실패하면 이전 설정으로 자동 복구합니다.
            </p>
          </div>
        </section>

        {accepted !== null ? (
          <section aria-live="polite" className="mt-3 flex items-center gap-3 rounded-panel border border-action/30 bg-action/5 p-4">
            <LoaderCircle aria-hidden="true" className="size-5 shrink-0 animate-spin text-action" />
            <div>
              <h3 className="text-sm font-semibold text-text">{STAGE_LABELS[accepted.currentStage]}</h3>
              <p className="mt-1 text-sm text-muted">검증과 반영을 진행하고 있습니다. 실패하면 자동 복구합니다.</p>
            </div>
          </section>
        ) : null}

        {receipt !== null ? (
          <ManagedConfigResult
            receipt={receipt}
            resourceId={resource.resourceId}
            serviceAction={serviceAction}
            onRevise={onRevise}
          />
        ) : null}

        {errorMessage ? (
          <div role="alert" className="mt-3 flex items-start gap-3 rounded-panel border border-danger/35 bg-danger/5 p-4">
            <XCircle aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-danger" />
            <p className="text-sm font-medium leading-6 text-danger">{errorMessage}</p>
          </div>
        ) : null}

        <section className="mt-3 rounded-panel border border-border bg-surface p-3 sm:p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-sm font-semibold text-text">{profile.contentLabel}</p>
            <p className={tooLarge ? "text-xs font-semibold text-danger" : "text-xs text-muted"}>
              {draftBytes.toLocaleString()} / {resource.maxBytes.toLocaleString()} bytes
            </p>
          </div>
          <CodeEditor
            ariaLabel={profile.contentLabel}
            className="mt-3 h-[68vh] min-h-[36rem]"
            language={profile.language}
            value={draft}
            readOnly={operationBusy || applied}
            diagnostics={editorDiagnostics}
            diagnosticLine={diagnosticLine}
            diagnosticMessage={
              diagnosticLine === null
                ? "서버 검증에서 이 줄이 거부되었습니다."
                : `${profile.validatorLabel}가 ${String(diagnosticLine)}번째 줄을 지목했습니다.`
            }
            onChange={onDraftChange}
          />
          <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-xs">
            <span className={diagnosticLine === null ? "text-muted" : "font-semibold text-danger"}>
              {diagnosticLine === null
                ? unchanged ? "변경 없음" : "저장 전 · 아직 서버에 반영되지 않음"
                : `${String(diagnosticLine)}번째 줄을 수정해 주세요.`}
            </span>
            {tooLarge ? <span className="font-semibold text-danger">허용 크기를 초과했습니다.</span> : null}
          </div>
        </section>

        <ManagedConfigHistory
          history={history}
          loading={historyLoading}
          failed={historyError}
          hasUnsavedChanges={!unchanged}
          source={restoreSource}
          plan={restorePlan}
          accepted={restoreAccepted}
          receipt={restoreReceipt}
          busy={restoreBusy}
          error={restoreError}
          onSelect={onSelectRestore}
          onApply={onApplyRestore}
          onCancel={onCancelRestore}
        />

        <details className="mt-3 rounded-panel border border-border bg-surface p-4 text-sm">
          <summary className="cursor-pointer font-semibold text-text">기술 세부정보</summary>
          {plan !== null ? (
            <dl className="mt-4 grid gap-3 border-b border-border pb-4 sm:grid-cols-3">
              <PlanValue label="변경 줄" value={`+${String(plan.addedLines)} / -${String(plan.removedLines)}`} />
              <PlanValue label="서비스 동작" value={`${profile.serviceLabel} ${plan.serviceAction}`} />
              <PlanValue label="계획 만료" value={formatDateTime(plan.expiresAt)} />
            </dl>
          ) : null}
          <div className="mt-4"><AssuranceDetails assurance={plan?.assurance ?? resource.assurance} /></div>
        </details>
      </div>

    </div>
  );
}

function ManagedConfigHistory({
  history,
  loading,
  failed,
  hasUnsavedChanges,
  source,
  plan,
  accepted,
  receipt,
  busy,
  error,
  onSelect,
  onApply,
  onCancel,
}: {
  history: OperationReceiptView[];
  loading: boolean;
  failed: boolean;
  hasUnsavedChanges: boolean;
  source: OperationReceiptView | null;
  plan: ManagedConfigPlanView | null;
  accepted: OperationAcceptedView | null;
  receipt: OperationReceiptView | null;
  busy: boolean;
  error: string | null;
  onSelect: (source: OperationReceiptView) => void;
  onApply: () => void;
  onCancel: () => void;
}) {
  const terminalRestore = receipt !== null && isTerminalStage(receipt.terminalState);
  return (
    <section className="mt-3 overflow-hidden rounded-panel border border-border bg-surface">
      <div className="flex items-start gap-3 border-b border-border px-4 py-3">
        <History aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted" />
        <div>
          <h3 className="text-sm font-semibold text-text">변경 이력과 복원</h3>
          <p className="mt-1 text-xs leading-5 text-muted">
            이 파일의 최근 성공 작업을 확인하고, 선택한 작업 직전 설정으로 되돌릴 수 있습니다.
          </p>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center gap-2 px-4 py-5 text-sm text-muted">
          <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />
          변경 이력을 불러오고 있습니다.
        </div>
      ) : failed ? (
        <p role="alert" className="px-4 py-5 text-sm text-danger">
          변경 이력을 불러오지 못했습니다. 현재 설정 편집은 가능하지만 수동 복원은 차단됩니다.
        </p>
      ) : history.length === 0 ? (
        <p className="px-4 py-5 text-sm text-muted">복원 가능한 변경 이력이 없습니다.</p>
      ) : (
        <ul className="divide-y divide-border">
          {history.slice(0, 5).map((operation) => {
            const selected = source?.operationId === operation.operationId;
            return (
              <li key={operation.operationId}>
                <div className="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-text">{operation.displayName}</p>
                    <p className="mt-1 text-xs text-muted">
                      {operation.actor.username} · {formatDateTime(operation.recordedAt)}
                    </p>
                  </div>
                  <Button
                    className="shrink-0"
                    size="compact"
                    variant="secondary"
                    disabled={busy || accepted !== null || hasUnsavedChanges}
                    onClick={() => onSelect(operation)}
                  >
                    <RotateCcw aria-hidden="true" className="size-4" />
                    변경 전 상태 확인
                  </Button>
                </div>

                {selected ? (
                  <div className="border-t border-border bg-subtle/35 px-4 py-4">
                    {busy && plan === null ? (
                      <div className="flex items-center gap-2 text-sm text-muted">
                        <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />
                        snapshot과 현재 설정을 대조하고 있습니다.
                      </div>
                    ) : null}

                    {plan !== null ? (
                      <>
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div>
                            <p className="text-sm font-semibold text-text">복원할 변경 내용</p>
                            <p className="mt-1 text-xs text-muted">
                              +{String(plan.addedLines)} / -{String(plan.removedLines)}줄
                            </p>
                          </div>
                          <Button size="compact" variant="ghost" onClick={onCancel} disabled={accepted !== null}>
                            취소
                          </Button>
                        </div>
                        {plan.diffSummary.length > 0 ? (
                          <pre
                            aria-label="복원 diff"
                            className="mt-3 max-h-56 overflow-auto rounded-control border border-border bg-surface p-3 font-mono text-xs leading-5 text-text"
                          >
                            {plan.diffSummary.join("\n")}
                          </pre>
                        ) : null}
                        <p className="mt-3 text-xs leading-5 text-muted">
                          현재 설정을 다시 백업한 뒤 복원본을 공식 문법 검사기로 검증하고 서비스를 반영합니다.
                          실패하면 방금 백업한 현재 설정으로 돌아갑니다.
                        </p>
                        {accepted !== null ? (
                          <div className="mt-3 flex items-center gap-2 text-sm font-medium text-action">
                            <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />
                            복원본을 검증하고 서비스에 반영하고 있습니다.
                          </div>
                        ) : terminalRestore ? (
                          <div
                            className={
                              receipt.terminalState === "SUCCEEDED"
                                ? "mt-3 rounded-control border border-success/30 bg-success/5 p-3 text-sm text-success"
                                : "mt-3 rounded-control border border-warning/30 bg-warning/5 p-3 text-sm text-warning"
                            }
                          >
                            {receipt.terminalState === "SUCCEEDED"
                              ? "복원과 서비스 검증을 완료했습니다."
                              : receipt.terminalState === "ROLLED_BACK"
                                ? "복원본 검증에 실패해 복원 전 설정을 유지했습니다."
                                : "자동 복구를 완료하지 못했습니다. 작업 기록의 복구 경로를 확인하세요."}
                          </div>
                        ) : (
                          <Button className="mt-3" disabled={busy} onClick={onApply}>
                            <Play aria-hidden="true" className="size-4" />
                            이 상태로 복원
                          </Button>
                        )}
                      </>
                    ) : null}

                    {error ? <p role="alert" className="mt-3 text-sm font-medium text-danger">{error}</p> : null}
                  </div>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}

      {hasUnsavedChanges ? (
        <p className="border-t border-border px-4 py-3 text-xs text-warning">
          저장하지 않은 편집 내용이 있어 복원 선택이 잠겼습니다. 먼저 저장하거나 변경을 취소하세요.
        </p>
      ) : null}
    </section>
  );
}

function ManagedConfigResult({
  receipt,
  resourceId,
  serviceAction,
  onRevise,
}: {
  receipt: OperationReceiptView;
  resourceId: string;
  serviceAction: "reload" | "validate_only";
  onRevise: (line: number | null) => void;
}) {
  const failure = receipt.terminalState === "RECOVERY_REQUIRED";
  const rolledBack = receipt.terminalState === "ROLLED_BACK";
  const succeeded = receipt.terminalState === "SUCCEEDED";
  const terminal = isTerminalStage(receipt.terminalState);
  const diagnostics = managedConfigDiagnostics(receipt.stages);
  const diagnosticLine = managedConfigSyntaxDiagnosticLine(receipt.stages, resourceId);

  return (
    <section
      aria-live="polite"
      className={
        succeeded
          ? "mt-3 rounded-panel border border-success/35 bg-success/5 p-4"
          : failure
            ? "mt-3 rounded-panel border border-danger/35 bg-danger/5 p-4"
            : "mt-3 rounded-panel border border-warning/35 bg-warning/5 p-4"
      }
    >
      <div className="flex items-start gap-3">
        {succeeded ? (
          <CheckCircle2 aria-hidden="true" className="size-5 shrink-0 text-success" />
        ) : failure ? (
          <XCircle aria-hidden="true" className="size-5 shrink-0 text-danger" />
        ) : !terminal ? (
          <LoaderCircle aria-hidden="true" className="size-5 shrink-0 animate-spin text-warning" />
        ) : (
          <TriangleAlert aria-hidden="true" className="size-5 shrink-0 text-warning" />
        )}
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold text-text">{STAGE_LABELS[receipt.terminalState]}</h3>
          <p className="mt-1 text-sm leading-6 text-muted">
            {succeeded
              ? serviceAction === "reload"
                ? "문법 검사, reload와 서비스 작동 확인을 마쳤습니다."
                : "문법 검사와 파일 read-back을 마쳤습니다. 중지된 서비스는 시작하지 않았습니다."
              : rolledBack
                ? "변경을 적용하지 않고 이전 설정을 복구·검증했습니다."
                : "자동 복구를 완료하지 못했습니다. 기술 세부정보의 복구 경로를 확인해 주세요."}
          </p>
          {rolledBack ? (
            <Button className="mt-3" size="compact" variant="secondary" onClick={() => onRevise(diagnosticLine)}>
              {diagnosticLine === null ? "다시 편집" : `${String(diagnosticLine)}번째 줄 수정`}
            </Button>
          ) : null}
        </div>
      </div>

      {diagnostics.length > 0 ? (
        <div className="mt-3 rounded-control border border-current/20 bg-surface/60 p-3">
          <p className="text-xs font-semibold">문법 검사 결과</p>
          <ul className="mt-2 space-y-2">
            {diagnostics.map((diagnostic, index) => (
              <li
                key={`${diagnostic.code}-${diagnostic.resourceId ?? "unknown"}-${String(diagnostic.line ?? 0)}-${String(index)}`}
                className="text-xs leading-5"
              >
                <span className="font-semibold">{diagnostic.message}</span>
                {diagnostic.maskedPath ? (
                  <span className="ml-1 font-mono text-muted">
                    {diagnostic.maskedPath}
                    {diagnostic.line ? `:${String(diagnostic.line)}` : ""}
                    {diagnostic.column ? `:${String(diagnostic.column)}` : ""}
                  </span>
                ) : null}
                {(diagnostic.causeCandidateLines?.length ?? 0) > 0 ? (
                  <span className="ml-1 font-semibold text-warning">
                    · 원인 후보 {diagnostic.causeCandidateLines?.map(String).join(", ")}번째 줄
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <details className="mt-3 border-t border-current/15 pt-3">
        <summary className="cursor-pointer text-xs font-semibold">작업 기록과 복구 정보</summary>
        <ol className="mt-2 divide-y divide-current/10">
          {receipt.stages.map((stage) => (
            <li key={stage.sequence} className="flex gap-2 py-2 text-xs">
              <CircleDot aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
              <span>{STAGE_LABELS[stage.stage]} · {formatDateTime(stage.recordedAt)} · {operationResultLabel(stage.resultCode)}</span>
            </li>
          ))}
        </ol>
        {receipt.recoveryPath.length > 0 ? (
          <ul className="mt-3 space-y-1 text-xs leading-5">
            {receipt.recoveryPath.map((value) => <li key={value}>· {value}</li>)}
          </ul>
        ) : null}
      </details>
    </section>
  );
}

function PlanValue({ label, value }: { label: string; value: string }) {
  return <div><dt className="text-xs text-muted">{label}</dt><dd className="mt-1 font-medium text-text">{value}</dd></div>;
}

function isTerminalStage(stage: OperationStage): boolean {
  return ["SUCCEEDED", "ROLLED_BACK", "RECOVERY_REQUIRED", "REJECTED", "EXPIRED", "CANCELLED_BEFORE_APPLY"].includes(stage);
}
