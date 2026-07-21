import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  BadgeCheck,
  CheckCircle2,
  CircleDot,
  Clock3,
  KeyRound,
  LoaderCircle,
  RotateCcw,
  ShieldAlert,
  TriangleAlert,
  XCircle,
} from "lucide-react";
import { useEffect, useRef, useState, type SyntheticEvent } from "react";

import {
  ApiError,
  approveCertbotRenewTest,
  getOperationReceipt,
  planCertbotRenewTest,
  reauthenticateForOperation,
  watchOperationEvents,
} from "../../shared/api/client";
import { certificatesQueryOptions, queryKeys } from "../../shared/api/queries";
import type {
  CertificateInventoryView,
  CertificateSummaryView,
  CertbotRenewTestPlanView,
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

export function CertificatesScreen() {
  const inventory = useQuery(certificatesQueryOptions);
  const queryClient = useQueryClient();
  const [plan, setPlan] = useState<CertbotRenewTestPlanView | null>(null);
  const [accepted, setAccepted] = useState<OperationAcceptedView | null>(null);
  const [receipt, setReceipt] = useState<OperationReceiptView | null>(null);
  const [sheetOpen, setSheetOpen] = useState(false);
  const [planning, setPlanning] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const requestInFlight = useRef(false);
  const approvalKey = useRef<string | null>(null);

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
            await queryClient.invalidateQueries({ queryKey: queryKeys.certificates });
          }
        } catch (error) {
          if (!(error instanceof DOMException && error.name === "AbortError")) {
            setErrorMessage(operationErrorCopy(error, "갱신 검증 영수증을 불러오지 못했습니다."));
          }
        }
      });
    }

    closeStream = watchOperationEvents(operation.eventStream, refreshReceipt, refreshReceipt);
    refreshReceipt();
    return () => {
      controller.abort();
      closeStream();
    };
  }, [accepted, queryClient]);

  async function createRenewPlan(data: CertificateInventoryView): Promise<void> {
    if (
      requestInFlight.current ||
      data.renewTestOperationType !== "certbot.certificate.renew_test/v1"
    ) return;
    requestInFlight.current = true;
    setPlanning(true);
    setErrorMessage(null);
    setReceipt(null);
    setAccepted(null);
    try {
      const idempotencyKey = `web_${crypto.randomUUID()}`;
      const nextPlan = await planCertbotRenewTest({
        schemaVersion: data.schemaVersion,
        operationType: data.renewTestOperationType,
        expectedInventoryDigest: data.inventoryDigest,
        idempotencyKey,
      });
      approvalKey.current = idempotencyKey;
      setPlan(nextPlan);
      setSheetOpen(true);
    } catch (error) {
      setErrorMessage(operationErrorCopy(error, "갱신 검증 계획을 만들지 못했습니다."));
      setSheetOpen(true);
      await queryClient.invalidateQueries({ queryKey: queryKeys.certificates });
    } finally {
      requestInFlight.current = false;
      setPlanning(false);
    }
  }

  async function approveRenewPlan(password: string): Promise<void> {
    if (requestInFlight.current || plan === null || approvalKey.current === null) return;
    requestInFlight.current = true;
    setExecuting(true);
    setErrorMessage(null);
    try {
      const reauth = await reauthenticateForOperation({ password, planHash: plan.planHash });
      queryClient.setQueryData(queryKeys.session, reauth.session);
      const operation = await approveCertbotRenewTest({
        schemaVersion: plan.schemaVersion,
        planId: plan.planId,
        planHash: plan.planHash,
        idempotencyKey: approvalKey.current,
        reauthToken: reauth.reauthToken,
        externalEffectConfirmed: true,
      });
      setAccepted(operation);
    } catch (error) {
      setErrorMessage(operationErrorCopy(error, "갱신 검증 승인을 완료하지 못했습니다."));
    } finally {
      requestInFlight.current = false;
      setExecuting(false);
    }
  }

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Certificates / Certbot"
        title="TLS 인증서"
        description="Certbot 인증서의 공개 메타데이터와 자동 갱신 timer를 확인합니다. 개인키와 ACME 계정 비밀은 화면으로 가져오지 않습니다."
        action={
          inventory.data?.renewTestOperationType === "certbot.certificate.renew_test/v1" ? (
            <StatusMark label="G1 검증 가능" tone="info" />
          ) : (
            <StatusMark label="조회 전용" tone="info" />
          )
        }
      />

      {inventory.isPending ? (
        <div className="space-y-3 py-7" aria-label="인증서 목록 불러오는 중">
          <Skeleton className="h-28 w-full" />
          <Skeleton className="h-40 w-full" />
        </div>
      ) : inventory.isError ? (
        <SurfaceState
          kind="error"
          title="인증서 상태를 불러오지 못했습니다"
          description="root inventory를 추측해서 표시하지 않습니다. canonical 상태를 다시 조회해 주세요."
          action={{ label: "다시 조회", onClick: () => void inventory.refetch() }}
        />
      ) : (
        <CertificateInventory
          data={inventory.data}
          planning={planning}
          onCreateRenewPlan={() => void createRenewPlan(inventory.data)}
        />
      )}

      <Sheet
        open={sheetOpen}
        onOpenChange={setSheetOpen}
        title="Certbot 갱신 사전 검증"
        description="외부 CA 효과와 실행 증거를 확인한 뒤 승인합니다."
        side="right"
      >
        <RenewTestInspector
          plan={plan}
          accepted={accepted}
          receipt={receipt}
          executing={executing}
          errorMessage={errorMessage}
          onApprove={approveRenewPlan}
        />
      </Sheet>
    </div>
  );
}

function CertificateInventory({
  data,
  planning,
  onCreateRenewPlan,
}: {
  data: CertificateInventoryView;
  planning: boolean;
  onCreateRenewPlan: () => void;
}) {
  return (
    <>
      <section className="py-7" aria-labelledby="certificate-runtime-heading">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h2 id="certificate-runtime-heading" className="text-sm font-semibold text-text">
              Certbot 갱신 상태
            </h2>
            <p className="mt-1 text-sm text-muted">관찰 시각 {formatDateTime(data.observedAt)}</p>
          </div>
          <AssuranceMark assurance={data.assurance} />
        </div>
        <dl className="mt-5 grid gap-px overflow-hidden rounded-panel border border-border bg-border sm:grid-cols-3">
          <RuntimeValue
            icon={BadgeCheck}
            label="Certbot"
            value={data.certbotInstalled ? "설치됨" : "설치 안 됨"}
            healthy={data.certbotInstalled}
          />
          <RuntimeValue
            icon={Clock3}
            label="갱신 timer"
            value={data.timerEnabled ? "활성화" : "비활성"}
            healthy={data.timerEnabled}
          />
          <RuntimeValue
            icon={Clock3}
            label="timer 실행 상태"
            value={data.timerActive ? "대기 중" : "중지됨"}
            healthy={data.timerActive}
          />
        </dl>
        {data.problems.length > 0 ? (
          <div className="mt-5 rounded-panel border border-warning/35 bg-warning/5 p-4">
            <div className="flex items-start gap-3">
              <ShieldAlert aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-warning" />
              <div>
                <p className="text-sm font-semibold text-text">확인이 필요한 항목</p>
                <ul className="mt-2 space-y-1 text-sm text-muted">
                  {data.problems.map((problem) => <li key={problem}>· {problemLabel(problem)}</li>)}
                </ul>
              </div>
            </div>
          </div>
        ) : null}
        {data.renewTestOperationType === "certbot.certificate.renew_test/v1" ? (
          <div className="mt-5 border-t border-border pt-5">
            <p className="text-sm leading-6 text-muted">
              갱신 사전 검증은 인증서를 교체하지 않지만 ACME staging challenge를 실제로 요청합니다.
              실행 전 계획과 G1 비원복 범위를 확인해야 합니다.
            </p>
            <Button className="mt-4 w-full sm:w-auto" disabled={planning} onClick={onCreateRenewPlan}>
              {planning ? (
                <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />
              ) : (
                <Clock3 aria-hidden="true" className="size-4" />
              )}
              {planning ? "현재 상태 재검증 중" : "갱신 사전 검증 계획 만들기"}
            </Button>
          </div>
        ) : null}
      </section>

      <section className="border-t border-border py-7" aria-labelledby="certificate-list-heading">
        <div className="flex items-start gap-3">
          <KeyRound aria-hidden="true" className="mt-0.5 size-5 text-muted" />
          <div>
            <h2 id="certificate-list-heading" className="text-sm font-semibold text-text">
              인증서 lineage
            </h2>
            <p className="mt-1 text-sm leading-6 text-muted">
              SAN·만료·fingerprint만 표시하며 개인키 본문과 실제 root 경로는 숨깁니다.
            </p>
          </div>
        </div>
        {data.certificates.length === 0 ? (
          <SurfaceState
            kind="empty"
            title="관찰 가능한 Certbot 인증서가 없습니다"
            description="발급 기능은 staging·attach fault gate가 끝날 때까지 제공하지 않습니다. 기존 인증서는 /etc/letsencrypt 표준 lineage만 인식합니다."
          />
        ) : (
          <div className="mt-6 grid gap-4 xl:grid-cols-2">
            {data.certificates.map((certificate) => (
              <CertificateCard key={certificate.primaryDomain} certificate={certificate} />
            ))}
          </div>
        )}
      </section>

      <section className="border-t border-border py-7" aria-labelledby="certificate-boundary-heading">
        <h2 id="certificate-boundary-heading" className="text-sm font-semibold text-text">
          현재 안전 경계
        </h2>
        <div className="mt-4 max-w-3xl">
          <AssuranceDetails assurance={data.assurance} />
        </div>
      </section>
    </>
  );
}

function RuntimeValue({
  icon: Icon,
  label,
  value,
  healthy,
}: {
  icon: typeof BadgeCheck;
  label: string;
  value: string;
  healthy: boolean;
}) {
  return (
    <div className="bg-surface p-4">
      <dt className="flex items-center gap-2 text-xs font-medium text-muted">
        <Icon aria-hidden="true" className="size-4" />
        {label}
      </dt>
      <dd className="mt-2"><StatusMark label={value} tone={healthy ? "success" : "warning"} /></dd>
    </div>
  );
}

function CertificateCard({ certificate }: { certificate: CertificateSummaryView }) {
  return (
    <article className="rounded-panel border border-border bg-surface p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold text-text">{certificate.primaryDomain}</h3>
          <p className="mt-1 text-xs text-muted">{certificate.certificatePath}</p>
        </div>
        <StatusMark
          label={certificate.webrootManaged ? "webroot 관리" : "외부 설정"}
          tone={certificate.webrootManaged ? "success" : "warning"}
        />
      </div>
      <dl className="mt-5 grid gap-4 text-sm sm:grid-cols-2">
        <div>
          <dt className="text-xs text-muted">만료</dt>
          <dd className="mt-1 font-medium text-text">{certificate.notAfter}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted">개인키 파일</dt>
          <dd className="mt-1 font-medium text-text">{certificate.privateKeyPresent ? "존재 확인" : "확인 실패"}</dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="text-xs text-muted">SAN</dt>
          <dd className="mt-1 break-words font-medium text-text">{certificate.sans.join(", ")}</dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="text-xs text-muted">SHA-256 fingerprint</dt>
          <dd className="mt-1 break-all font-mono text-xs text-text">{certificate.fingerprintSha256}</dd>
        </div>
      </dl>
    </article>
  );
}

const STAGE_LABELS: Record<OperationStage, string> = {
  PLANNED: "계획 생성",
  APPROVED: "승인 완료",
  SNAPSHOTTED: "인증서 상태 저장",
  APPLYING: "Certbot dry-run 실행",
  VALIDATING: "결과·timer 재검증",
  RELOADING: "서비스 reload",
  VERIFYING: "적용 상태 확인",
  ROLLING_BACK: "이전 상태 원복",
  SUCCEEDED: "갱신 검증 완료",
  ROLLED_BACK: "실패 · 원복 완료",
  RECOVERY_REQUIRED: "중단 · 수동 확인 필요",
  REJECTED: "검증 실패",
  EXPIRED: "계획 만료",
  CANCELLED_BEFORE_APPLY: "실행 전 취소",
};

function RenewTestInspector({
  plan,
  accepted,
  receipt,
  executing,
  errorMessage,
  onApprove,
}: {
  plan: CertbotRenewTestPlanView | null;
  accepted: OperationAcceptedView | null;
  receipt: OperationReceiptView | null;
  executing: boolean;
  errorMessage: string | null;
  onApprove: (password: string) => Promise<void>;
}) {
  const [password, setPassword] = useState("");
  const [externalEffectConfirmed, setExternalEffectConfirmed] = useState(false);

  async function submit(event: SyntheticEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!externalEffectConfirmed) return;
    const submittedPassword = password;
    setPassword("");
    await onApprove(submittedPassword);
  }

  if (receipt !== null) return <RenewTestResult receipt={receipt} />;

  if (accepted !== null) {
    return (
      <div aria-live="polite" className="flex items-start gap-3">
        <LoaderCircle aria-hidden="true" className="size-6 shrink-0 animate-spin text-warning" />
        <div>
          <h3 className="text-base font-semibold text-text">
            {STAGE_LABELS[accepted.currentStage]}
          </h3>
          <p className="mt-1 text-sm leading-6 text-muted">
            one-shot Certbot runner가 실행 중입니다. 창을 닫아도 감사 원장에서 최종 결과를 다시
            확인할 수 있습니다.
          </p>
        </div>
      </div>
    );
  }

  if (plan === null) {
    return errorMessage ? (
      <SurfaceState kind="error" title="계획을 만들지 못했습니다" description={errorMessage} />
    ) : (
      <SurfaceState
        kind="empty"
        title="검증 계획이 없습니다"
        description="인증서 화면에서 현재 상태를 다시 조회한 뒤 계획을 만드세요."
      />
    );
  }

  return (
    <div>
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-muted">
            certbot renew --dry-run
          </p>
          <h3 className="mt-2 text-base font-semibold text-text">외부 갱신 사전 검증 계획</h3>
        </div>
        <AssuranceMark assurance={plan.assurance} />
      </div>

      <dl className="mt-5 grid grid-cols-2 gap-3 border-y border-border py-4 text-sm">
        <div>
          <dt className="text-xs text-muted">인증서 수</dt>
          <dd className="mt-1 font-medium text-text">{plan.certificateCount.toLocaleString()}개</dd>
        </div>
        <div>
          <dt className="text-xs text-muted">계획 만료</dt>
          <dd className="mt-1 font-medium text-text">{formatDateTime(plan.expiresAt)}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted">timer 활성화</dt>
          <dd className="mt-1 font-medium text-text">{plan.timerEnabled ? "예" : "아니요"}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted">timer 상태</dt>
          <dd className="mt-1 font-medium text-text">{plan.timerActive ? "대기 중" : "중지"}</dd>
        </div>
      </dl>

      <section className="mt-5 border-y border-warning/35 py-4">
        <div className="flex items-start gap-3">
          <TriangleAlert aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-warning" />
          <div>
            <h4 className="text-sm font-semibold text-text">G1 · 자동 원복 보장 없음</h4>
            <p className="mt-1 text-sm leading-6 text-muted">
              로컬 인증서를 교체하지 않지만 외부 CA의 challenge·rate-limit 기록은 되돌릴 수
              없습니다. 전체 명령 출력은 저장하지 않습니다.
            </p>
          </div>
        </div>
      </section>

      <section className="mt-5">
        <h4 className="text-xs font-semibold text-muted">실행 영향</h4>
        <BulletList values={plan.impact} />
      </section>
      <div className="mt-5">
        <AssuranceDetails assurance={plan.assurance} />
      </div>
      <section className="mt-5 border-y border-border py-4">
        <h4 className="text-xs font-semibold text-muted">중단 시 확인 경로</h4>
        <BulletList values={plan.recoveryPath} />
      </section>

      {errorMessage ? (
        <p role="alert" className="mt-5 text-sm font-medium leading-6 text-danger">
          {errorMessage}
        </p>
      ) : null}

      <form className="mt-6" onSubmit={(event) => void submit(event)}>
        <label className="flex items-start gap-3 text-sm leading-6 text-text">
          <input
            type="checkbox"
            className="mt-1 size-4 accent-accent"
            checked={externalEffectConfirmed}
            onChange={(event) => setExternalEffectConfirmed(event.currentTarget.checked)}
          />
          인증서를 교체하지 않아도 외부 CA 요청은 원복할 수 없다는 점을 확인했습니다.
        </label>
        <label htmlFor="certbot-renew-password" className="mt-5 block text-sm font-medium text-text">
          Linux 계정 비밀번호로 exact plan 승인
        </label>
        <Input
          id="certbot-renew-password"
          type="password"
          autoComplete="current-password"
          maxLength={1024}
          required
          disabled={executing}
          value={password}
          onChange={(event) => setPassword(event.currentTarget.value)}
        />
        <Button
          className="mt-4 w-full"
          type="submit"
          disabled={executing || password.length === 0 || !externalEffectConfirmed}
        >
          {executing ? (
            <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />
          ) : (
            <KeyRound aria-hidden="true" className="size-4" />
          )}
          {executing ? "승인·실행 요청 중" : "재인증 후 dry-run 실행"}
        </Button>
      </form>
    </div>
  );
}

function RenewTestResult({ receipt }: { receipt: OperationReceiptView }) {
  const succeeded = receipt.terminalState === "SUCCEEDED";
  const recoveryRequired = receipt.terminalState === "RECOVERY_REQUIRED";
  return (
    <div aria-live="polite">
      <div className="flex items-start gap-3">
        {succeeded ? (
          <CheckCircle2 aria-hidden="true" className="size-6 shrink-0 text-success" />
        ) : recoveryRequired ? (
          <XCircle aria-hidden="true" className="size-6 shrink-0 text-danger" />
        ) : (
          <RotateCcw aria-hidden="true" className="size-6 shrink-0 text-warning" />
        )}
        <div>
          <h3 className="text-base font-semibold text-text">
            {STAGE_LABELS[receipt.terminalState]}
          </h3>
          <p className="mt-1 text-sm leading-6 text-muted">
            {succeeded
              ? "Certbot dry-run 성공과 timer·sanitized inventory 재조회를 확인했습니다."
              : "성공으로 처리하지 않았습니다. 아래 감사 단계와 확인 경로를 검토하세요."}
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
          <h4 className="text-sm font-semibold text-text">수동 확인 경로</h4>
          <BulletList values={receipt.recoveryPath} />
        </section>
      ) : null}
      <div className="mt-5">
        <AssuranceDetails assurance={receipt.assurance} />
      </div>
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

function operationErrorCopy(error: unknown, fallback: string): string {
  if (!(error instanceof ApiError)) return fallback;
  const messages: Record<string, string> = {
    stale_inventory: "인증서 상태가 바뀌었습니다. 다시 조회한 뒤 새 계획을 만드세요.",
    resource_busy: "다른 Certbot 작업이 실행 중입니다. 완료 후 다시 시도하세요.",
    plan_expired: "계획이 만료되었습니다. 현재 상태로 새 계획을 만드세요.",
    renewal_test_failed: "Certbot 갱신 사전 검증이 실패했습니다. 원문 대신 감사 digest가 기록됐습니다.",
    forensic_lockdown: "감사 원장 무결성 잠금 상태여서 작업이 차단되었습니다.",
  };
  return messages[error.code] ?? fallback;
}

function problemLabel(problem: string): string {
  if (problem === "certbot_not_installed") return "Ubuntu Certbot이 설치되지 않았습니다.";
  if (problem === "certbot_timer_disabled") return "certbot.timer가 활성화되지 않았습니다.";
  if (problem === "certbot_timer_inactive") return "certbot.timer가 현재 대기 상태가 아닙니다.";
  if (problem.startsWith("certificate_invalid:")) return `${problem.slice(20)} lineage를 안전하게 읽지 못했습니다.`;
  return "표준 Certbot lineage가 아닌 항목을 발견했습니다.";
}
