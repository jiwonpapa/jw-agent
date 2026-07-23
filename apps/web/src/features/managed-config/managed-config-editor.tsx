import {
  ArrowLeft,
  Check,
  CheckCircle2,
  CircleDot,
  FilePenLine,
  LoaderCircle,
  Play,
  RotateCcw,
  XCircle,
} from "lucide-react";
import { useBlocker } from "@tanstack/react-router";
import { lazy, Suspense, type ReactNode } from "react";

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
import { AssuranceDetails, AssuranceMark } from "../../shared/ui/assurance";
import { Button } from "../../shared/ui/button";
import { CodeEditor, type EditorLanguage } from "../../shared/ui/code-editor";
import { Skeleton } from "../../shared/ui/skeleton";

const CodeDiff = lazy(async () => {
  const module = await import("../../shared/ui/code-diff");
  return { default: module.CodeDiff };
});

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

const WIZARD_STEPS = ["편집", "검증", "확인·적용", "결과"] as const;

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
  onCreatePlan: () => void;
  onApprove: () => Promise<void>;
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
  onCreatePlan,
  onApprove,
  onRevise,
}: ManagedConfigEditorProps) {
  const hasUnappliedChanges = draft !== resource.content && receipt?.terminalState !== "SUCCEEDED";
  useBlocker({
    enableBeforeUnload: hasUnappliedChanges,
    shouldBlockFn: () =>
      hasUnappliedChanges &&
      !window.confirm("적용하지 않은 설정 변경이 있습니다. 편집을 종료하시겠습니까?"),
  });

  if (receipt !== null) {
    return (
      <WizardFrame
        activeStep={3}
        resource={resource}
        action={<Button variant="secondary" onClick={onBack}>닫기</Button>}
        onBack={onBack}
      >
        <ManagedConfigResult receipt={receipt} onRevise={onRevise} />
      </WizardFrame>
    );
  }

  if (accepted !== null) {
    return (
      <WizardFrame activeStep={2} resource={resource} onBack={onBack}>
        <div aria-live="polite" className="flex min-h-52 items-center justify-center gap-3 rounded-panel border border-border bg-subtle/40 p-6">
          <LoaderCircle aria-hidden="true" className="size-6 shrink-0 animate-spin text-warning" />
          <div>
            <h3 className="text-base font-semibold text-text">{STAGE_LABELS[accepted.currentStage]}</h3>
            <p className="mt-1 text-sm leading-6 text-muted">
              백업·적용·검증·reload를 진행합니다. 실패하면 이전 설정으로 자동 원복합니다.
            </p>
          </div>
        </div>
      </WizardFrame>
    );
  }

  if (plan !== null) {
    const applyAction = (
      <Button disabled={executing} onClick={() => void onApprove()}>
        {executing ? <LoaderCircle aria-hidden="true" className="size-4 animate-spin" /> : <Play aria-hidden="true" className="size-4" />}
        {executing ? "적용 중" : `적용 후 ${profile.serviceLabel} reload`}
      </Button>
    );
    return (
      <WizardFrame activeStep={2} resource={resource} action={applyAction} onBack={() => onRevise(null)}>
        <ManagedConfigOperationPlan
          profile={profile}
          plan={plan}
          original={resource.content}
          modified={draft}
          errorMessage={errorMessage}
        />
      </WizardFrame>
    );
  }

  const draftBytes = new TextEncoder().encode(draft).byteLength;
  const unchanged = draft === resource.content;
  const tooLarge = draftBytes > resource.maxBytes;
  const validateAction = (
    <Button disabled={planning || unchanged || tooLarge} onClick={onCreatePlan}>
      {planning ? <LoaderCircle aria-hidden="true" className="size-4 animate-spin" /> : <Check aria-hidden="true" className="size-4" />}
      {planning ? "검증·diff 생성 중" : "검증하기"}
    </Button>
  );

  return (
    <WizardFrame activeStep={diagnosticLine === null ? 0 : 1} resource={resource} action={validateAction} onBack={onBack}>
      <div className="rounded-panel border border-border bg-surface p-3 sm:p-5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-sm font-semibold text-text">{profile.contentLabel}</p>
          <p className={tooLarge ? "text-xs font-semibold text-danger" : "text-xs text-muted"}>
            {draftBytes.toLocaleString()} / {resource.maxBytes.toLocaleString()} bytes
          </p>
        </div>
        <CodeEditor
          ariaLabel={profile.contentLabel}
          className="mt-3 min-h-[60vh]"
          language={profile.language}
          value={draft}
          diagnosticLine={diagnosticLine}
          diagnosticMessage={
            diagnosticLine === null
              ? "서버 검증에서 이 줄이 거부되었습니다."
              : `${profile.validatorLabel}가 ${String(diagnosticLine)}번째 줄을 지목했습니다.`
          }
          onChange={onDraftChange}
        />
        <p className="mt-2 text-xs text-muted">
          {unchanged ? "변경 없음" : "아직 서버에 적용되지 않았습니다. 검증 후 변경 내용을 확인합니다."}
        </p>
        {diagnosticLine !== null ? (
          <p role="alert" className="mt-2 text-sm font-semibold text-danger">
            {profile.validatorLabel}가 선택한 설정의 {String(diagnosticLine)}번째 줄을 지목했습니다.
          </p>
        ) : null}
      </div>

      {errorMessage ? (
        <div role="alert" className="mt-4 flex items-start gap-3 rounded-panel border border-danger/35 bg-danger/5 p-4">
          <XCircle aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-danger" />
          <p className="text-sm font-medium leading-6 text-danger">{errorMessage}</p>
        </div>
      ) : null}

      <details className="mt-4 rounded-panel border border-border bg-surface p-4 text-sm">
        <summary className="cursor-pointer font-semibold text-text">안전장치와 원복 범위 보기</summary>
        <div className="mt-4"><AssuranceDetails assurance={resource.assurance} /></div>
      </details>
    </WizardFrame>
  );
}

function WizardFrame({
  activeStep,
  resource,
  action,
  onBack,
  children,
}: {
  activeStep: number;
  resource: ManagedConfigResourceView;
  action?: ReactNode;
  onBack: () => void;
  children: ReactNode;
}) {
  return (
    <div className="relative">
      <header className="sticky top-0 z-20 -mx-3 border-b border-border bg-surface/95 px-3 pb-3 pt-1 backdrop-blur sm:-mx-6 sm:px-6">
        <div className="flex items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3">
            <Button aria-label="이전 화면" size="icon" variant="ghost" onClick={onBack}>
              <ArrowLeft aria-hidden="true" className="size-5" />
            </Button>
            <div className="min-w-0">
              <h2 className="truncate text-lg font-bold text-text">{resource.displayName}</h2>
              <p className="truncate font-mono text-xs text-muted">{resource.maskedPath}</p>
            </div>
          </div>
          <div className="hidden shrink-0 items-center gap-3 sm:flex">
            <AssuranceMark assurance={resource.assurance} />
            {action}
          </div>
        </div>
        <ol aria-label="설정 변경 단계" className="mt-3 grid grid-cols-4 gap-1">
          {WIZARD_STEPS.map((label, index) => (
            <li
              key={label}
              aria-current={index === activeStep ? "step" : undefined}
              className={index <= activeStep ? "border-t-2 border-action pt-2 text-xs font-semibold text-action" : "border-t-2 border-border pt-2 text-xs text-muted"}
            >
              <span className="hidden sm:inline">{String(index + 1)}. </span>{label}
            </li>
          ))}
        </ol>
      </header>
      <div className="py-5">{children}</div>
      {action ? <div className="sticky bottom-0 z-20 -mx-3 border-t border-border bg-surface/95 p-3 backdrop-blur sm:hidden [&>button]:w-full">{action}</div> : null}
    </div>
  );
}

function ManagedConfigOperationPlan({
  profile,
  plan,
  original,
  modified,
  errorMessage,
}: {
  profile: ManagedConfigEditorProfile;
  plan: ManagedConfigPlanView;
  original: string;
  modified: string;
  errorMessage: string | null;
}) {
  return (
    <div>
      <section className="rounded-panel border border-success/35 bg-success/5 p-4">
        <div className="flex items-start gap-3">
          <CheckCircle2 aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-success" />
          <div>
            <h3 className="text-sm font-semibold text-text">서버 사전 검증을 통과했습니다</h3>
            <p className="mt-1 text-sm leading-6 text-muted">변경 내용을 확인한 뒤 적용하십시오. 적용 시 이전 파일을 먼저 보관합니다.</p>
          </div>
        </div>
      </section>

      <dl className="mt-4 grid gap-3 rounded-panel border border-border bg-surface p-4 text-sm sm:grid-cols-2 lg:grid-cols-4">
        <PlanValue label="파일 크기" value={`${plan.currentBytes.toLocaleString()} → ${plan.proposedBytes.toLocaleString()} bytes`} />
        <PlanValue label="변경 줄" value={`+${String(plan.addedLines)} / -${String(plan.removedLines)}`} />
        <PlanValue label="적용 동작" value={`${profile.serviceLabel} ${plan.serviceAction}`} />
        <PlanValue label="계획 만료" value={formatDateTime(plan.expiresAt)} />
      </dl>

      <section className="mt-4 rounded-panel border border-border bg-surface p-4" aria-labelledby="config-diff-heading">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 id="config-diff-heading" className="text-sm font-semibold text-text">변경 내용</h3>
          <AssuranceMark assurance={plan.assurance} />
        </div>
        <Suspense fallback={<Skeleton className="mt-3 h-64 w-full" />}>
          <CodeDiff
            ariaLabel={`${profile.contentLabel.replace(" 내용", "")} 변경 diff`}
            className="mt-3 min-h-72"
            language={profile.language}
            original={original}
            modified={modified}
          />
        </Suspense>
      </section>

      {errorMessage ? <p role="alert" className="mt-4 text-sm font-medium leading-6 text-danger">{errorMessage}</p> : null}

      <details className="mt-4 rounded-panel border border-border bg-surface p-4">
        <summary className="cursor-pointer text-sm font-semibold text-text">영향·원복·수동 복구 정보</summary>
        <div className="mt-4 grid gap-5 lg:grid-cols-2">
          <div><h4 className="text-xs font-semibold text-muted">실행 영향</h4><BulletList values={plan.impact} /></div>
          <div><h4 className="text-xs font-semibold text-muted">수동 복구 경로</h4><BulletList values={plan.recoveryPath} /></div>
        </div>
        <div className="mt-5"><AssuranceDetails assurance={plan.assurance} /></div>
        <details className="mt-4 text-xs text-muted">
          <summary className="cursor-pointer font-medium text-action">텍스트 diff 요약</summary>
          <pre className="mt-2 max-h-40 overflow-auto rounded-control bg-subtle p-3 leading-5 text-text">{plan.diffSummary.length > 0 ? plan.diffSummary.join("\n") : "내용 변경 없음"}</pre>
        </details>
      </details>
    </div>
  );
}

function ManagedConfigResult({ receipt, onRevise }: { receipt: OperationReceiptView; onRevise: (line: number | null) => void }) {
  const failure = receipt.terminalState === "RECOVERY_REQUIRED";
  const rolledBack = receipt.terminalState === "ROLLED_BACK";
  const succeeded = receipt.terminalState === "SUCCEEDED";
  const terminal = isTerminalStage(receipt.terminalState);
  const diagnosticLine = managedConfigSyntaxDiagnosticLine(receipt.stages);
  return (
    <div aria-live="polite">
      <section className={succeeded ? "rounded-panel border border-success/35 bg-success/5 p-5" : failure ? "rounded-panel border border-danger/35 bg-danger/5 p-5" : "rounded-panel border border-warning/35 bg-warning/5 p-5"}>
        <div className="flex items-start gap-3">
          {succeeded ? <CheckCircle2 aria-hidden="true" className="size-6 shrink-0 text-success" /> : failure ? <XCircle aria-hidden="true" className="size-6 shrink-0 text-danger" /> : !terminal ? <LoaderCircle aria-hidden="true" className="size-6 shrink-0 animate-spin text-warning" /> : <RotateCcw aria-hidden="true" className="size-6 shrink-0 text-warning" />}
          <div>
            <h3 className="text-base font-semibold text-text">{STAGE_LABELS[receipt.terminalState]}</h3>
            <p className="mt-1 text-sm leading-6 text-muted">
              {succeeded ? "설정·문법·reload·서비스 상태를 확인했습니다." : rolledBack ? "적용 실패 후 이전 파일 복원과 재검증을 마쳤습니다." : !terminal ? "서버에서 작업을 계속하고 있습니다." : "성공 처리하지 않았습니다. 복구 정보를 확인하십시오."}
            </p>
          </div>
        </div>
      </section>

      {diagnosticLine !== null ? (
        <section className="mt-4 rounded-panel border border-danger/35 bg-danger/5 p-4" role="alert">
          <h4 className="text-sm font-semibold text-text">{diagnosticLine}번째 줄에서 검증 실패</h4>
          <p className="mt-1 text-sm leading-6 text-muted">서비스를 reload하지 않고 이전 설정으로 복원했습니다.</p>
        </section>
      ) : null}

      <details className="mt-4 rounded-panel border border-border bg-surface p-4">
        <summary className="cursor-pointer text-sm font-semibold text-text">작업 단계와 기술 정보 보기</summary>
        <ol className="mt-3 divide-y divide-border">
          {receipt.stages.map((stage) => (
            <li key={stage.sequence} className="flex gap-3 py-3 text-sm">
              <CircleDot aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted" />
              <div className="min-w-0">
                <p className="font-medium text-text">{STAGE_LABELS[stage.stage]}</p>
                <p className="mt-1 break-words text-xs text-muted">{formatDateTime(stage.recordedAt)} · {operationResultLabel(stage.resultCode)}</p>
              </div>
            </li>
          ))}
        </ol>
        {receipt.recoveryPath.length > 0 ? <div className="mt-4"><h4 className="text-sm font-semibold text-text">수동 복구 경로</h4><BulletList values={receipt.recoveryPath} /></div> : null}
        <div className="mt-5"><AssuranceDetails assurance={receipt.assurance} /></div>
      </details>

      {rolledBack ? (
        <Button className="mt-4" onClick={() => onRevise(diagnosticLine)}>
          <FilePenLine aria-hidden="true" className="size-4" />
          {diagnosticLine === null ? "편집 내용 다시 검토" : `${String(diagnosticLine)}번째 줄 수정`}
        </Button>
      ) : null}
    </div>
  );
}

function PlanValue({ label, value }: { label: string; value: string }) {
  return <div><dt className="text-xs text-muted">{label}</dt><dd className="mt-1 font-medium text-text">{value}</dd></div>;
}

function BulletList({ values }: { values: string[] }) {
  return <ul className="mt-2 space-y-1 text-sm leading-6 text-muted">{values.map((value) => <li key={value} className="flex gap-2"><span aria-hidden="true">·</span><span>{value}</span></li>)}</ul>;
}

function isTerminalStage(stage: OperationStage): boolean {
  return ["SUCCEEDED", "ROLLED_BACK", "RECOVERY_REQUIRED", "REJECTED", "EXPIRED", "CANCELLED_BEFORE_APPLY"].includes(stage);
}
