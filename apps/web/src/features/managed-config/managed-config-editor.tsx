import { useBlocker } from "@tanstack/react-router";
import {
  ArrowLeft,
  CheckCircle2,
  CircleDot,
  LoaderCircle,
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
  managedConfigSyntaxDiagnosticLine,
  operationResultLabel,
} from "../../shared/domain/managed-config-diagnostic";
import { AssuranceDetails } from "../../shared/ui/assurance";
import { Button } from "../../shared/ui/button";
import { CodeEditor, type EditorLanguage } from "../../shared/ui/code-editor";

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
  onDraftChange: (value: string) => void;
  onBack: () => void;
  onSave: () => void;
  onRevise: (line: number | null) => void;
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
  onDraftChange,
  onBack,
  onSave,
  onRevise,
}: ManagedConfigEditorProps) {
  const applied = receipt?.terminalState === "SUCCEEDED";
  const operationBusy = planning || executing || accepted !== null;
  const hasUnappliedChanges = draft !== resource.content && !applied;
  const draftBytes = new TextEncoder().encode(draft).byteLength;
  const unchanged = draft === resource.content;
  const tooLarge = draftBytes > resource.maxBytes;

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
      {operationBusy ? (
        <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />
      ) : (
        <Save aria-hidden="true" className="size-4" />
      )}
      {operationBusy ? "검증·저장 중" : "저장"}
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
          <div className="hidden shrink-0 sm:block">{primaryAction}</div>
        </div>
      </header>

      <div className="py-4">
        <section className="rounded-panel border border-border bg-subtle/35 px-4 py-3">
          <div className="flex items-start gap-3">
            <RotateCcw aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-action" />
            <p className="text-sm leading-6 text-muted">
              저장하면 <strong className="font-semibold text-text">{profile.validatorLabel}</strong> 후{" "}
              <strong className="font-semibold text-text">{profile.serviceLabel} reload</strong>를 실행합니다.
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
          <ManagedConfigResult receipt={receipt} onRevise={onRevise} />
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
            className="mt-3 min-h-[68vh]"
            language={profile.language}
            value={draft}
            readOnly={operationBusy || applied}
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

      <div className="sticky bottom-0 z-20 -mx-3 border-t border-border bg-surface/95 p-3 backdrop-blur sm:hidden [&>button]:w-full">
        {primaryAction}
      </div>
    </div>
  );
}

function ManagedConfigResult({
  receipt,
  onRevise,
}: {
  receipt: OperationReceiptView;
  onRevise: (line: number | null) => void;
}) {
  const failure = receipt.terminalState === "RECOVERY_REQUIRED";
  const rolledBack = receipt.terminalState === "ROLLED_BACK";
  const succeeded = receipt.terminalState === "SUCCEEDED";
  const terminal = isTerminalStage(receipt.terminalState);
  const diagnosticLine = managedConfigSyntaxDiagnosticLine(receipt.stages);

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
              ? "문법 검사, reload와 서비스 작동 확인을 마쳤습니다."
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
