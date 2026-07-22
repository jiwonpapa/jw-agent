import {
  CheckCircle2,
  CircleDot,
  FilePenLine,
  KeyRound,
  LoaderCircle,
  RotateCcw,
  TriangleAlert,
  XCircle,
} from "lucide-react";
import { lazy, Suspense, useState, type SyntheticEvent } from "react";

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
import { cn } from "../../shared/ui/cn";
import { CodeEditor, type EditorLanguage } from "../../shared/ui/code-editor";
import { Input } from "../../shared/ui/input";
import { Skeleton } from "../../shared/ui/skeleton";
import {
  AdditionalAuthCodeField,
  useAdditionalAuthRequired,
} from "../../shared/ui/additional-auth-code";

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
  onApprove: (password: string, additionalAuthCode: string) => Promise<void>;
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
  if (receipt !== null) {
    return <ManagedConfigResult receipt={receipt} onRevise={onRevise} />;
  }
  if (accepted !== null) {
    return (
      <div aria-live="polite" className="flex items-start gap-3">
        <LoaderCircle aria-hidden="true" className="size-6 shrink-0 animate-spin text-warning" />
        <div>
          <h3 className="text-base font-semibold text-text">{STAGE_LABELS[accepted.currentStage]}</h3>
          <p className="mt-1 text-sm leading-6 text-muted">
            서버가 설정을 적용·검증하고 있습니다. 실패하면 snapshot으로 원복한 뒤 결과를 기록합니다.
          </p>
        </div>
      </div>
    );
  }
  if (plan !== null) {
    return (
      <ManagedConfigOperationPlan
        profile={profile}
        plan={plan}
        original={resource.content}
        modified={draft}
        executing={executing}
        errorMessage={errorMessage}
        onApprove={onApprove}
      />
    );
  }

  const draftBytes = new TextEncoder().encode(draft).byteLength;
  const unchanged = draft === resource.content;
  const tooLarge = draftBytes > resource.maxBytes;
  return (
    <div>
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-muted">{resource.adapterId}</p>
          <h3 className="mt-2 text-base font-semibold text-text">{resource.displayName}</h3>
          <p className="mt-1 text-xs font-mono text-muted">{resource.maskedPath}</p>
        </div>
        <AssuranceMark assurance={resource.assurance} />
      </div>

      <section className="mt-5 border-y border-warning/35 py-4">
        <div className="flex items-start gap-3">
          <TriangleAlert aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-warning" />
          <div>
            <p className="text-sm font-semibold text-text">저장 버튼으로 즉시 반영하지 않습니다</p>
            <p className="mt-1 text-sm leading-6 text-muted">
              먼저 diff 계획을 만든 뒤 Linux 비밀번호로 승인합니다. {profile.validatorLabel} 실패 시 reload 없이 이전 파일을 복원합니다.
            </p>
          </div>
        </div>
      </section>

      <p className="mt-5 text-sm font-medium text-text">{profile.contentLabel}</p>
      <CodeEditor
        ariaLabel={profile.contentLabel}
        className="mt-2"
        language={profile.language}
        value={draft}
        diagnosticLine={diagnosticLine}
        diagnosticMessage={
          diagnosticLine === null
            ? "서버 문법검사가 이 줄에서 실패했습니다."
            : `${profile.validatorLabel}가 ${String(diagnosticLine)}번째 줄을 지목했습니다.`
        }
        onChange={onDraftChange}
      />
      <div className="mt-2 flex items-center justify-between gap-3 text-xs text-muted">
        <span>{unchanged ? "변경 없음" : "편집 내용은 아직 서버에 적용되지 않음"}</span>
        <span className={tooLarge ? "font-semibold text-danger" : undefined}>
          {draftBytes.toLocaleString()} / {resource.maxBytes.toLocaleString()} bytes
        </span>
      </div>

      <div className="mt-5"><AssuranceDetails assurance={resource.assurance} /></div>
      {errorMessage ? <p role="alert" className="mt-5 text-sm font-medium leading-6 text-danger">{errorMessage}</p> : null}
      <Button className="mt-6 w-full" disabled={planning || unchanged || tooLarge} onClick={onCreatePlan}>
        {planning ? <LoaderCircle aria-hidden="true" className="size-4 animate-spin" /> : <FilePenLine aria-hidden="true" className="size-4" />}
        {planning ? "현재 파일 재검증·diff 생성 중" : "변경 계획 만들기"}
      </Button>
      <Button className="mt-3 w-full" variant="ghost" onClick={onBack}>{profile.backLabel}</Button>
    </div>
  );
}

function ManagedConfigOperationPlan({
  profile,
  plan,
  original,
  modified,
  executing,
  errorMessage,
  onApprove,
}: {
  profile: ManagedConfigEditorProfile;
  plan: ManagedConfigPlanView;
  original: string;
  modified: string;
  executing: boolean;
  errorMessage: string | null;
  onApprove: (password: string, additionalAuthCode: string) => Promise<void>;
}) {
  const [password, setPassword] = useState("");
  const [additionalAuthCode, setAdditionalAuthCode] = useState("");
  const additionalAuthRequired = useAdditionalAuthRequired();
  const [validationConfirmed, setValidationConfirmed] = useState(false);
  const [serviceActionConfirmed, setServiceActionConfirmed] = useState(false);

  async function submit(event: SyntheticEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!validationConfirmed || !serviceActionConfirmed) return;
    const submittedPassword = password;
    const submittedCode = additionalAuthCode;
    setPassword("");
    setAdditionalAuthCode("");
    await onApprove(submittedPassword, submittedCode);
  }

  return (
    <div>
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-xs font-mono text-muted">{plan.maskedPath}</p>
          <h3 className="mt-2 text-base font-semibold text-text">설정 변경 계획</h3>
        </div>
        <AssuranceMark assurance={plan.assurance} />
      </div>
      <dl className="mt-5 grid grid-cols-2 gap-3 border-y border-border py-4 text-sm">
        <PlanValue label="파일 크기" value={`${plan.currentBytes.toLocaleString()} → ${plan.proposedBytes.toLocaleString()} bytes`} />
        <PlanValue label="변경 줄" value={`+${String(plan.addedLines)} / -${String(plan.removedLines)}`} />
        <PlanValue label="서비스 동작" value={`${profile.serviceLabel} ${plan.serviceAction}`} />
        <PlanValue label="계획 만료" value={formatDateTime(plan.expiresAt)} />
      </dl>

      <section className="mt-5" aria-labelledby="config-diff-heading">
        <h4 id="config-diff-heading" className="text-xs font-semibold text-muted">제한된 diff 미리보기</h4>
        <Suspense fallback={<Skeleton className="mt-2 h-64 w-full" />}>
          <CodeDiff ariaLabel={`${profile.contentLabel} 변경 diff`} className="mt-2" language={profile.language} original={original} modified={modified} />
        </Suspense>
        <details className="mt-3 text-xs text-muted">
          <summary className="cursor-pointer font-medium text-action">텍스트 diff 요약</summary>
          <pre className="mt-2 max-h-40 overflow-auto rounded-control bg-subtle p-3 leading-5 text-text">{plan.diffSummary.length > 0 ? plan.diffSummary.join("\n") : "내용 변경 없음"}</pre>
        </details>
      </section>

      <section className="mt-5 border-y border-border py-4"><h4 className="text-xs font-semibold text-muted">실행 영향</h4><BulletList values={plan.impact} /></section>
      <div className="mt-5"><AssuranceDetails assurance={plan.assurance} /></div>
      <section className="mt-5 border-y border-warning/35 py-4"><h4 className="text-sm font-semibold text-text">원복도 검증 실패하면 수동 복구가 필요합니다</h4><BulletList values={plan.recoveryPath} /></section>
      {errorMessage ? <p role="alert" className="mt-5 text-sm font-medium leading-6 text-danger">{errorMessage}</p> : null}

      <form className="mt-6" onSubmit={(event) => void submit(event)}>
        <Confirm checked={validationConfirmed} onChange={setValidationConfirmed}>{`저장 후 ${profile.validatorLabel}를 통과해야만 reload하며, 실패 시 자동 원복한다는 점을 확인했습니다.`}</Confirm>
        <Confirm className="mt-3" checked={serviceActionConfirmed} onChange={setServiceActionConfirmed}>{`이 계획이 ${profile.serviceLabel} reload를 수행할 수 있음을 확인했습니다.`}</Confirm>
        <label htmlFor="config-operation-password" className="mt-5 block text-sm font-medium text-text">Linux 계정 비밀번호로 exact plan 승인</label>
        <Input id="config-operation-password" type="password" autoComplete="current-password" maxLength={1024} required disabled={executing} value={password} onChange={(event) => setPassword(event.currentTarget.value)} />
        <AdditionalAuthCodeField id="config-operation-totp" value={additionalAuthCode} onChange={setAdditionalAuthCode} disabled={executing} />
        <Button className="mt-4 w-full" type="submit" disabled={executing || password.length === 0 || (additionalAuthRequired && additionalAuthCode.length !== 6) || !validationConfirmed || !serviceActionConfirmed}>
          {executing ? <LoaderCircle aria-hidden="true" className="size-4 animate-spin" /> : <KeyRound aria-hidden="true" className="size-4" />}
          {executing ? "적용·검증·원복 판단 중" : "재인증 후 설정 적용"}
        </Button>
      </form>
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
      <div className="flex items-start gap-3">
        {succeeded ? <CheckCircle2 aria-hidden="true" className="size-6 shrink-0 text-success" /> : failure ? <XCircle aria-hidden="true" className="size-6 shrink-0 text-danger" /> : !terminal ? <LoaderCircle aria-hidden="true" className="size-6 shrink-0 animate-spin text-warning" /> : <RotateCcw aria-hidden="true" className="size-6 shrink-0 text-warning" />}
        <div>
          <h3 className="text-base font-semibold text-text">{STAGE_LABELS[receipt.terminalState]}</h3>
          <p className="mt-1 text-sm leading-6 text-muted">{succeeded ? "설정 bytes·metadata, 문법, reload, active 상태를 확인했습니다." : rolledBack ? "적용은 실패했지만 이전 파일 bytes·owner·mode 복원과 재검증을 마쳤습니다." : !terminal ? "작업은 서버에서 계속됩니다. 표시된 단계는 감사 원장에 기록된 상태입니다." : "성공으로 처리하지 않았습니다. 아래 단계와 복구 경로를 확인하세요."}</p>
        </div>
      </div>
      {diagnosticLine !== null ? <section className="mt-5 rounded-panel border border-danger/35 bg-danger/5 p-4" role="alert"><h4 className="text-sm font-semibold text-text">선택한 설정 {diagnosticLine}번째 줄에서 문법 오류</h4><p className="mt-1 text-sm leading-6 text-muted">서비스는 reload하지 않았고 이전 설정 복원과 재검증을 마쳤습니다. 편집기로 돌아가 표시된 줄을 수정하세요.</p></section> : null}
      <ol className="mt-6 border-y border-border py-2">
        {receipt.stages.map((stage) => <li key={stage.sequence} className="flex gap-3 py-3 text-sm"><CircleDot aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted" /><div className="min-w-0"><p className="font-medium text-text">{STAGE_LABELS[stage.stage]}</p><p className="mt-1 break-words text-xs text-muted">{formatDateTime(stage.recordedAt)} · {operationResultLabel(stage.resultCode)}</p></div></li>)}
      </ol>
      {receipt.recoveryPath.length > 0 ? <section className="mt-5 border-y border-danger/35 py-4"><h4 className="text-sm font-semibold text-text">수동 복구 경로</h4><BulletList values={receipt.recoveryPath} /></section> : null}
      <div className="mt-5"><AssuranceDetails assurance={receipt.assurance} /></div>
      {rolledBack ? <Button className="mt-5 w-full" onClick={() => onRevise(diagnosticLine)}><FilePenLine aria-hidden="true" className="size-4" />{diagnosticLine === null ? "편집 내용 다시 검토" : `${String(diagnosticLine)}번째 줄 수정`}</Button> : null}
    </div>
  );
}

function PlanValue({ label, value }: { label: string; value: string }) {
  return <div><dt className="text-xs text-muted">{label}</dt><dd className="mt-1 font-medium text-text">{value}</dd></div>;
}

function Confirm({ checked, onChange, children, className }: { checked: boolean; onChange: (value: boolean) => void; children: string; className?: string }) {
  return <label className={cn("flex items-start gap-3 text-sm leading-6 text-text", className)}><input type="checkbox" className="mt-1 size-4 accent-accent" checked={checked} onChange={(event) => onChange(event.currentTarget.checked)} />{children}</label>;
}

function BulletList({ values }: { values: string[] }) {
  return <ul className="mt-2 space-y-1 text-sm leading-6 text-muted">{values.map((value) => <li key={value} className="flex gap-2"><span aria-hidden="true">·</span><span>{value}</span></li>)}</ul>;
}

function isTerminalStage(stage: OperationStage): boolean {
  return ["SUCCEEDED", "ROLLED_BACK", "RECOVERY_REQUIRED", "REJECTED", "EXPIRED", "CANCELLED_BEFORE_APPLY"].includes(stage);
}
