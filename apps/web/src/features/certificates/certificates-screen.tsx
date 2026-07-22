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
  approveCertbotAttach,
  approveCertbotIssue,
  approveCertbotRenewTest,
  getOperationReceipt,
  planCertbotIssue,
  planCertbotAttach,
  planCertbotRenewTest,
  reauthenticateForOperation,
  watchOperationEvents,
} from "../../shared/api/client";
import {
  accessSettingsQueryOptions,
  certificatesQueryOptions,
  nginxSitesQueryOptions,
  queryKeys,
} from "../../shared/api/queries";
import type {
  CertificateEnvironment,
  CertificateInventoryView,
  CertificateSummaryView,
  CertbotAttachPlanView,
  CertbotIssuePlanView,
  CertbotRenewTestPlanView,
  OperationAcceptedView,
  OperationReceiptView,
  OperationStage,
} from "../../shared/api/types";
import { formatDateTime } from "../../shared/domain/format";
import { AssuranceDetails, AssuranceMark } from "../../shared/ui/assurance";
import {
  AdditionalAuthCodeField,
  useAdditionalAuthRequired,
} from "../../shared/ui/additional-auth-code";
import { Button } from "../../shared/ui/button";
import { Input } from "../../shared/ui/input";
import { BulletList, isTerminalStage } from "../../shared/ui/operation-details";
import { Sheet } from "../../shared/ui/sheet";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";

export function CertificatesScreen() {
  const inventory = useQuery(certificatesQueryOptions);
  const accessSettings = useQuery(accessSettingsQueryOptions);
  const nginxSites = useQuery(nginxSitesQueryOptions);
  const queryClient = useQueryClient();
  const [renewPlan, setRenewPlan] = useState<CertbotRenewTestPlanView | null>(null);
  const [issuePlan, setIssuePlan] = useState<CertbotIssuePlanView | null>(null);
  const [attachPlan, setAttachPlan] = useState<CertbotAttachPlanView | null>(null);
  const [operationKind, setOperationKind] = useState<"issue" | "renew" | "attach" | null>(null);
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
            setErrorMessage(
              operationErrorCopy(
                error,
                operationKind === "issue"
                  ? "발급 영수증을 불러오지 못했습니다."
                  : operationKind === "attach"
                    ? "TLS 연결 영수증을 불러오지 못했습니다."
                    : "갱신 검증 영수증을 불러오지 못했습니다.",
              ),
            );
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
  }, [accepted, operationKind, queryClient]);

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
    setIssuePlan(null);
    setAttachPlan(null);
    setOperationKind("renew");
    try {
      const idempotencyKey = `web_${crypto.randomUUID()}`;
      const nextPlan = await planCertbotRenewTest({
        schemaVersion: data.schemaVersion,
        operationType: data.renewTestOperationType,
        expectedInventoryDigest: data.inventoryDigest,
        idempotencyKey,
      });
      approvalKey.current = idempotencyKey;
      setRenewPlan(nextPlan);
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

  async function approveRenewPlan(password: string, additionalAuthCode: string): Promise<void> {
    if (requestInFlight.current || renewPlan === null || approvalKey.current === null) return;
    requestInFlight.current = true;
    setExecuting(true);
    setErrorMessage(null);
    try {
      const reauth = await reauthenticateForOperation({ password, planHash: renewPlan.planHash, additionalAuthCode });
      queryClient.setQueryData(queryKeys.session, reauth.session);
      const operation = await approveCertbotRenewTest({
        schemaVersion: renewPlan.schemaVersion,
        planId: renewPlan.planId,
        planHash: renewPlan.planHash,
        idempotencyKey: approvalKey.current,
        reauthToken: reauth.reauthToken,
        additionalAuthClaim: reauth.additionalAuthClaim ?? null,
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

  async function createIssuePlan(input: {
    email: string;
    alternativeDomains: string[];
    environment: CertificateEnvironment;
  }): Promise<void> {
    const data = inventory.data;
    const publicHost = accessSettings.data?.publicHost;
    const site = nginxSites.data?.sites.find(
      (candidate) =>
        candidate.protected &&
        candidate.enabled &&
        candidate.siteId !== undefined &&
        candidate.availableDigest !== undefined,
    );
    if (
      requestInFlight.current ||
      data?.issueOperationType !== "certbot.certificate.issue/v1" ||
      publicHost === undefined ||
      publicHost === null ||
      site?.siteId === undefined ||
      site.siteId === null ||
      site.availableDigest === undefined ||
      site.availableDigest === null
    ) return;
    requestInFlight.current = true;
    setPlanning(true);
    setErrorMessage(null);
    setReceipt(null);
    setAccepted(null);
    setRenewPlan(null);
    setAttachPlan(null);
    setOperationKind("issue");
    try {
      const idempotencyKey = `web_${crypto.randomUUID()}`;
      const nextPlan = await planCertbotIssue({
        schemaVersion: data.schemaVersion,
        operationType: data.issueOperationType,
        primaryDomain: publicHost,
        alternativeDomains: input.alternativeDomains,
        accountEmail: input.email,
        environment: input.environment,
        siteId: site.siteId,
        expectedSiteDigest: site.availableDigest,
        expectedInventoryDigest: data.inventoryDigest,
        tosAgreed: true,
        idempotencyKey,
      });
      approvalKey.current = idempotencyKey;
      setIssuePlan(nextPlan);
      setSheetOpen(true);
    } catch (error) {
      setErrorMessage(operationErrorCopy(error, "인증서 발급 계획을 만들지 못했습니다."));
      setSheetOpen(true);
      await queryClient.invalidateQueries({ queryKey: queryKeys.certificates });
    } finally {
      requestInFlight.current = false;
      setPlanning(false);
    }
  }

  async function approveIssuePlan(password: string, additionalAuthCode: string): Promise<void> {
    if (requestInFlight.current || issuePlan === null || approvalKey.current === null) return;
    requestInFlight.current = true;
    setExecuting(true);
    setErrorMessage(null);
    try {
      const reauth = await reauthenticateForOperation({ password, planHash: issuePlan.planHash, additionalAuthCode });
      queryClient.setQueryData(queryKeys.session, reauth.session);
      const operation = await approveCertbotIssue({
        schemaVersion: issuePlan.schemaVersion,
        planId: issuePlan.planId,
        planHash: issuePlan.planHash,
        idempotencyKey: approvalKey.current,
        reauthToken: reauth.reauthToken,
        additionalAuthClaim: reauth.additionalAuthClaim ?? null,
        externalEffectConfirmed: true,
        localAttachDeferredConfirmed: true,
      });
      setAccepted(operation);
    } catch (error) {
      setErrorMessage(operationErrorCopy(error, "인증서 발급 승인을 완료하지 못했습니다."));
    } finally {
      requestInFlight.current = false;
      setExecuting(false);
    }
  }

  async function createAttachPlan(certificate: CertificateSummaryView): Promise<void> {
    const data = inventory.data;
    const publicHost = accessSettings.data?.publicHost;
    const site = nginxSites.data?.sites.find(
      (candidate) =>
        candidate.protected &&
        candidate.enabled &&
        candidate.siteId !== undefined &&
        candidate.availableDigest !== undefined,
    );
    if (
      requestInFlight.current ||
      data?.attachOperationType !== "certbot.certificate.attach/v1" ||
      publicHost === undefined ||
      publicHost === null ||
      certificate.primaryDomain !== publicHost ||
      site?.siteId === undefined ||
      site.siteId === null ||
      site.availableDigest === undefined ||
      site.availableDigest === null
    ) return;
    requestInFlight.current = true;
    setPlanning(true);
    setErrorMessage(null);
    setReceipt(null);
    setAccepted(null);
    setIssuePlan(null);
    setRenewPlan(null);
    setOperationKind("attach");
    try {
      const idempotencyKey = `web_${crypto.randomUUID()}`;
      const nextPlan = await planCertbotAttach({
        schemaVersion: data.schemaVersion,
        operationType: data.attachOperationType,
        primaryDomain: certificate.primaryDomain,
        siteId: site.siteId,
        expectedSiteDigest: site.availableDigest,
        expectedInventoryDigest: data.inventoryDigest,
        expectedCertificateFingerprint: certificate.fingerprintSha256,
        idempotencyKey,
      });
      approvalKey.current = idempotencyKey;
      setAttachPlan(nextPlan);
      setSheetOpen(true);
    } catch (error) {
      setErrorMessage(operationErrorCopy(error, "TLS 연결 계획을 만들지 못했습니다."));
      setSheetOpen(true);
      await queryClient.invalidateQueries({ queryKey: queryKeys.certificates });
    } finally {
      requestInFlight.current = false;
      setPlanning(false);
    }
  }

  async function approveAttachPlan(password: string, additionalAuthCode: string): Promise<void> {
    if (requestInFlight.current || attachPlan === null || approvalKey.current === null) return;
    requestInFlight.current = true;
    setExecuting(true);
    setErrorMessage(null);
    try {
      const reauth = await reauthenticateForOperation({ password, planHash: attachPlan.planHash, additionalAuthCode });
      queryClient.setQueryData(queryKeys.session, reauth.session);
      const operation = await approveCertbotAttach({
        schemaVersion: attachPlan.schemaVersion,
        planId: attachPlan.planId,
        planHash: attachPlan.planHash,
        idempotencyKey: approvalKey.current,
        reauthToken: reauth.reauthToken,
        additionalAuthClaim: reauth.additionalAuthClaim ?? null,
        configReplaceConfirmed: true,
        serviceReloadConfirmed: true,
      });
      setAccepted(operation);
    } catch (error) {
      setErrorMessage(operationErrorCopy(error, "TLS 연결 승인을 완료하지 못했습니다."));
    } finally {
      requestInFlight.current = false;
      setExecuting(false);
    }
  }

  const publicHost = accessSettings.data?.publicHost ?? null;
  const issueSiteReady = nginxSites.data?.sites.some(
    (site) =>
      site.protected &&
      site.enabled &&
      site.siteId !== null &&
      site.siteId !== undefined &&
      site.availableDigest !== null &&
      site.availableDigest !== undefined,
  ) ?? false;

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Certificates / Certbot"
        title="TLS 인증서"
        description="Certbot 인증서의 공개 메타데이터와 자동 갱신 timer를 확인합니다. 개인키와 ACME 계정 비밀은 화면으로 가져오지 않습니다."
        action={
          inventory.data?.attachOperationType === "certbot.certificate.attach/v1" ? (
            <StatusMark label="G2 연결 가능" tone="success" />
          ) : inventory.data?.issueOperationType === "certbot.certificate.issue/v1" ||
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
          publicHost={publicHost}
          issueSiteReady={issueSiteReady}
          onCreateIssuePlan={(input) => void createIssuePlan(input)}
          onCreateRenewPlan={() => void createRenewPlan(inventory.data)}
          onCreateAttachPlan={(certificate) => void createAttachPlan(certificate)}
        />
      )}

      <Sheet
        open={sheetOpen}
        onOpenChange={setSheetOpen}
        title={
          operationKind === "issue"
            ? "Certbot 인증서 발급"
            : operationKind === "attach"
              ? "Nginx TLS 인증서 연결"
              : "Certbot 갱신 사전 검증"
        }
        description={
          operationKind === "attach"
            ? "교체 범위·자동 원복·SNI 검증을 확인한 뒤 승인합니다."
            : "외부 CA 효과와 실행 증거를 확인한 뒤 승인합니다."
        }
        side="right"
      >
        {operationKind === "issue" ? (
          <IssueInspector
            plan={issuePlan}
            accepted={accepted}
            receipt={receipt}
            executing={executing}
            errorMessage={errorMessage}
            onApprove={approveIssuePlan}
          />
        ) : operationKind === "attach" ? (
          <AttachInspector
            plan={attachPlan}
            accepted={accepted}
            receipt={receipt}
            executing={executing}
            errorMessage={errorMessage}
            onApprove={approveAttachPlan}
          />
        ) : (
          <RenewTestInspector
            plan={renewPlan}
            accepted={accepted}
            receipt={receipt}
            executing={executing}
            errorMessage={errorMessage}
            onApprove={approveRenewPlan}
          />
        )}
      </Sheet>
    </div>
  );
}

function CertificateInventory({
  data,
  planning,
  publicHost,
  issueSiteReady,
  onCreateIssuePlan,
  onCreateRenewPlan,
  onCreateAttachPlan,
}: {
  data: CertificateInventoryView;
  planning: boolean;
  publicHost: string | null;
  issueSiteReady: boolean;
  onCreateIssuePlan: (input: {
    email: string;
    alternativeDomains: string[];
    environment: CertificateEnvironment;
  }) => void;
  onCreateRenewPlan: () => void;
  onCreateAttachPlan: (certificate: CertificateSummaryView) => void;
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
        {data.issueOperationType === "certbot.certificate.issue/v1" && publicHost !== null ? (
          <IssueSetup
            primaryDomain={publicHost}
            siteReady={issueSiteReady}
            planning={planning}
            onCreatePlan={onCreateIssuePlan}
          />
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
            description="신규 발급은 staging 검증부터 시작합니다. 기존 인증서는 /etc/letsencrypt 표준 lineage만 인식합니다."
          />
        ) : (
          <div className="mt-6 grid gap-4 xl:grid-cols-2">
            {data.certificates.map((certificate) => (
              <CertificateCard
                key={certificate.primaryDomain}
                certificate={certificate}
                attachAvailable={
                  data.attachOperationType === "certbot.certificate.attach/v1" &&
                  publicHost === certificate.primaryDomain &&
                  issueSiteReady &&
                  certificate.privateKeyPresent &&
                  certificate.renewalConfigPresent &&
                  certificate.webrootManaged
                }
                planning={planning}
                onCreateAttachPlan={onCreateAttachPlan}
              />
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

function IssueSetup({
  primaryDomain,
  siteReady,
  planning,
  onCreatePlan,
}: {
  primaryDomain: string;
  siteReady: boolean;
  planning: boolean;
  onCreatePlan: (input: {
    email: string;
    alternativeDomains: string[];
    environment: CertificateEnvironment;
  }) => void;
}) {
  const [email, setEmail] = useState("");
  const [alternatives, setAlternatives] = useState("");
  const [environment, setEnvironment] = useState<CertificateEnvironment>("staging");
  const [tosAgreed, setTosAgreed] = useState(false);

  function submit(event: SyntheticEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (!siteReady || !tosAgreed || email.length === 0) return;
    const alternativeDomains = alternatives
      .split(",")
      .map((value) => value.trim().toLowerCase())
      .filter((value) => value.length > 0 && value !== primaryDomain)
      .sort();
    onCreatePlan({ email, alternativeDomains: [...new Set(alternativeDomains)], environment });
  }

  return (
    <section className="mt-6 border-t border-border pt-6" aria-labelledby="certificate-issue-heading">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h3 id="certificate-issue-heading" className="text-sm font-semibold text-text">
            신규 인증서 발급
          </h3>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-muted">
            먼저 staging challenge를 통과한 뒤 같은 DNS·Nginx 설정으로만 production 계획을 만들 수
            있습니다. 발급 후 TLS 연결은 별도 G2 승인입니다.
          </p>
        </div>
        <StatusMark label="G1 · 원복 없음" tone="warning" />
      </div>

      <form className="mt-5 grid gap-4 sm:grid-cols-2" onSubmit={submit}>
        <div>
          <label htmlFor="certbot-primary-domain" className="text-sm font-medium text-text">
            기본 도메인
          </label>
          <Input id="certbot-primary-domain" value={primaryDomain} readOnly />
        </div>
        <div>
          <label htmlFor="certbot-account-email" className="text-sm font-medium text-text">
            ACME 계정 이메일
          </label>
          <Input
            id="certbot-account-email"
            type="email"
            autoComplete="email"
            maxLength={254}
            required
            value={email}
            onChange={(event) => setEmail(event.currentTarget.value.trim())}
          />
          <p className="mt-1 text-xs leading-5 text-muted">계획 화면과 감사 export에는 마스킹됩니다.</p>
        </div>
        <div>
          <label htmlFor="certbot-alternative-domains" className="text-sm font-medium text-text">
            추가 도메인 <span className="font-normal text-muted">(선택, 쉼표 구분)</span>
          </label>
          <Input
            id="certbot-alternative-domains"
            inputMode="url"
            placeholder="www.example.com"
            value={alternatives}
            onChange={(event) => setAlternatives(event.currentTarget.value)}
          />
        </div>
        <div>
          <label htmlFor="certbot-environment" className="text-sm font-medium text-text">
            CA 환경
          </label>
          <select
            id="certbot-environment"
            className="mt-2 h-10 w-full rounded-control border border-border bg-surface px-3 text-sm text-text outline-none focus:border-accent"
            value={environment}
            onChange={(event) => setEnvironment(event.currentTarget.value as CertificateEnvironment)}
          >
            <option value="staging">staging · 비저장 challenge 검증</option>
            <option value="production">production · 실제 인증서 발급</option>
          </select>
        </div>
        <label className="flex items-start gap-3 text-sm leading-6 text-text sm:col-span-2">
          <input
            type="checkbox"
            className="mt-1 size-4 accent-accent"
            checked={tosAgreed}
            onChange={(event) => setTosAgreed(event.currentTarget.checked)}
          />
          Let’s Encrypt 이용약관 동의와 외부 CA 요청이 발생하는 계획임을 확인했습니다.
        </label>
        {!siteReady ? (
          <p role="alert" className="text-sm leading-6 text-warning sm:col-span-2">
            활성화된 제품 관리 Nginx site와 고정 ACME webroot include를 확인할 수 없어 계획을 차단했습니다.
          </p>
        ) : null}
        <div className="sm:col-span-2">
          <Button
            type="submit"
            className="w-full sm:w-auto"
            disabled={planning || !siteReady || !tosAgreed || email.length === 0}
          >
            {planning ? (
              <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />
            ) : (
              <BadgeCheck aria-hidden="true" className="size-4" />
            )}
            {planning ? "DNS·포트·Nginx 확인 중" : "발급 전 계획 만들기"}
          </Button>
        </div>
      </form>
    </section>
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

function CertificateCard({
  certificate,
  attachAvailable,
  planning,
  onCreateAttachPlan,
}: {
  certificate: CertificateSummaryView;
  attachAvailable: boolean;
  planning: boolean;
  onCreateAttachPlan: (certificate: CertificateSummaryView) => void;
}) {
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
      {attachAvailable ? (
        <div className="mt-5 border-t border-border pt-4">
          <p className="text-sm leading-6 text-muted">
            이 lineage를 관리 주소에 연결할 수 있습니다. 먼저 변경 계획과 G2 자동 원복 범위를
            확인합니다.
          </p>
          <Button
            className="mt-3 w-full sm:w-auto"
            disabled={planning}
            onClick={() => onCreateAttachPlan(certificate)}
          >
            {planning ? (
              <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />
            ) : (
              <BadgeCheck aria-hidden="true" className="size-4" />
            )}
            {planning ? "현재 설정 확인 중" : "Nginx 연결 계획 만들기"}
          </Button>
        </div>
      ) : null}
    </article>
  );
}

function AttachInspector({
  plan,
  accepted,
  receipt,
  executing,
  errorMessage,
  onApprove,
}: {
  plan: CertbotAttachPlanView | null;
  accepted: OperationAcceptedView | null;
  receipt: OperationReceiptView | null;
  executing: boolean;
  errorMessage: string | null;
  onApprove: (password: string, additionalAuthCode: string) => Promise<void>;
}) {
  const [password, setPassword] = useState("");
  const [additionalAuthCode, setAdditionalAuthCode] = useState("");
  const additionalAuthRequired = useAdditionalAuthRequired();
  const [replaceConfirmed, setReplaceConfirmed] = useState(false);
  const [reloadConfirmed, setReloadConfirmed] = useState(false);

  async function submit(event: SyntheticEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!replaceConfirmed || !reloadConfirmed) return;
    const submittedPassword = password;
    const submittedCode = additionalAuthCode;
    setPassword("");
    setAdditionalAuthCode("");
    await onApprove(submittedPassword, submittedCode);
  }

  if (receipt !== null) return <AttachResult receipt={receipt} />;
  if (accepted !== null) {
    return (
      <div aria-live="polite" className="flex items-start gap-3">
        <LoaderCircle aria-hidden="true" className="size-6 shrink-0 animate-spin text-warning" />
        <div>
          <h3 className="text-base font-semibold text-text">{STAGE_LABELS[accepted.currentStage]}</h3>
          <p className="mt-1 text-sm leading-6 text-muted">
            Nginx 설정 교체·검증·reload·SNI 확인을 진행합니다. 실패하면 snapshot으로 자동
            원복합니다.
          </p>
        </div>
      </div>
    );
  }
  if (plan === null) {
    return errorMessage ? (
      <SurfaceState kind="error" title="TLS 연결 계획을 만들지 못했습니다" description={errorMessage} />
    ) : (
      <SurfaceState kind="empty" title="TLS 연결 계획이 없습니다" description="현재 lineage와 Nginx 상태를 다시 조회하세요." />
    );
  }

  return (
    <div>
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-muted">
            certbot lineage → protected nginx
          </p>
          <h3 className="mt-2 text-base font-semibold text-text">{plan.primaryDomain} TLS 연결 계획</h3>
        </div>
        <AssuranceMark assurance={plan.assurance} />
      </div>

      <dl className="mt-5 grid grid-cols-2 gap-3 border-y border-border py-4 text-sm">
        <div className="col-span-2">
          <dt className="text-xs text-muted">설정 교체</dt>
          <dd className="mt-1 break-words font-medium text-text">
            {plan.currentCertificatePath} → {plan.targetCertificatePath}
          </dd>
        </div>
        <div>
          <dt className="text-xs text-muted">계획 만료</dt>
          <dd className="mt-1 font-medium text-text">{formatDateTime(plan.expiresAt)}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted">갱신 timer</dt>
          <dd className="mt-1 font-medium text-text">
            {plan.timerEnabled && plan.timerActive ? "활성·대기" : "검증 실패"}
          </dd>
        </div>
        <div className="col-span-2">
          <dt className="text-xs text-muted">SAN</dt>
          <dd className="mt-1 break-words font-medium text-text">{plan.sans.join(", ")}</dd>
        </div>
        <div className="col-span-2">
          <dt className="text-xs text-muted">대상 인증서 SHA-256</dt>
          <dd className="mt-1 break-all font-mono text-xs text-text">{plan.certificateFingerprint}</dd>
        </div>
      </dl>

      <section className="mt-5 border-y border-success/35 py-4">
        <div className="flex items-start gap-3">
          <BadgeCheck aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-success" />
          <div>
            <h4 className="text-sm font-semibold text-text">G2 · 제한된 설정 자동 원복</h4>
            <p className="mt-1 text-sm leading-6 text-muted">
              이 계획은 보호된 vhost의 인증서 지시문 두 개만 바꿉니다. 문법·reload·SNI 지문
              확인 중 하나라도 실패하면 파일 원본 bytes·owner·mode를 복원합니다.
            </p>
          </div>
        </div>
      </section>
      <section className="mt-5">
        <h4 className="text-xs font-semibold text-muted">실행 영향</h4>
        <BulletList values={plan.impact} />
      </section>
      <div className="mt-5"><AssuranceDetails assurance={plan.assurance} /></div>
      <section className="mt-5 border-y border-border py-4">
        <h4 className="text-xs font-semibold text-muted">원복 실패 시 복구 경로</h4>
        <BulletList values={plan.recoveryPath} />
      </section>

      {errorMessage ? <p role="alert" className="mt-5 text-sm font-medium text-danger">{errorMessage}</p> : null}
      <form className="mt-6" onSubmit={(event) => void submit(event)}>
        <label className="flex items-start gap-3 text-sm leading-6 text-text">
          <input
            type="checkbox"
            className="mt-1 size-4 accent-accent"
            checked={replaceConfirmed}
            onChange={(event) => setReplaceConfirmed(event.currentTarget.checked)}
          />
          보호된 Nginx vhost의 인증서 지시문 두 개가 교체됨을 확인했습니다.
        </label>
        <label className="mt-3 flex items-start gap-3 text-sm leading-6 text-text">
          <input
            type="checkbox"
            className="mt-1 size-4 accent-accent"
            checked={reloadConfirmed}
            onChange={(event) => setReloadConfirmed(event.currentTarget.checked)}
          />
          nginx.service reload와 기존 연결 재수립 가능성을 확인했습니다.
        </label>
        <label htmlFor="certbot-attach-password" className="mt-5 block text-sm font-medium text-text">
          Linux 계정 비밀번호로 exact plan 승인
        </label>
        <Input
          id="certbot-attach-password"
          type="password"
          autoComplete="current-password"
          maxLength={1024}
          required
          disabled={executing}
          value={password}
          onChange={(event) => setPassword(event.currentTarget.value)}
        />
        <AdditionalAuthCodeField id="certbot-attach-totp" value={additionalAuthCode} onChange={setAdditionalAuthCode} disabled={executing} />
        <Button
          className="mt-4 w-full"
          type="submit"
          disabled={executing || password.length === 0 || (additionalAuthRequired && additionalAuthCode.length !== 6) || !replaceConfirmed || !reloadConfirmed}
        >
          {executing ? <LoaderCircle aria-hidden="true" className="size-4 animate-spin" /> : <KeyRound aria-hidden="true" className="size-4" />}
          {executing ? "승인·실행 요청 중" : "재인증 후 TLS 연결"}
        </Button>
      </form>
    </div>
  );
}

function AttachResult({ receipt }: { receipt: OperationReceiptView }) {
  const succeeded = receipt.terminalState === "SUCCEEDED";
  const rolledBack = receipt.terminalState === "ROLLED_BACK";
  return (
    <div aria-live="polite">
      <div className="flex items-start gap-3">
        {succeeded ? (
          <CheckCircle2 aria-hidden="true" className="size-6 shrink-0 text-success" />
        ) : rolledBack ? (
          <RotateCcw aria-hidden="true" className="size-6 shrink-0 text-warning" />
        ) : (
          <XCircle aria-hidden="true" className="size-6 shrink-0 text-danger" />
        )}
        <div>
          <h3 className="text-base font-semibold text-text">
            {succeeded ? "TLS 연결 검증 완료" : STAGE_LABELS[receipt.terminalState]}
          </h3>
          <p className="mt-1 text-sm leading-6 text-muted">
            {succeeded
              ? "Nginx 설정·reload·SNI 인증서 지문·Certbot 갱신 상태를 모두 확인했습니다."
              : rolledBack
                ? "적용 검증에 실패해 Nginx 설정 원본을 복원하고 reload 상태까지 확인했습니다."
                : "자동 원복 완료를 증명하지 못했습니다. 아래 복구 경로를 즉시 확인하세요."}
          </p>
        </div>
      </div>
      <ol className="mt-6 border-y border-border py-2">
        {receipt.stages.map((stage) => (
          <li key={stage.sequence} className="flex gap-3 py-3 text-sm">
            <CircleDot aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted" />
            <div className="min-w-0">
              <p className="font-medium text-text">{STAGE_LABELS[stage.stage]}</p>
              <p className="mt-1 break-words text-xs text-muted">{formatDateTime(stage.recordedAt)} · {stage.resultCode}</p>
            </div>
          </li>
        ))}
      </ol>
      {receipt.recoveryPath.length > 0 ? <section className="mt-5"><BulletList values={receipt.recoveryPath} /></section> : null}
      <div className="mt-5"><AssuranceDetails assurance={receipt.assurance} /></div>
    </div>
  );
}

function IssueInspector({
  plan,
  accepted,
  receipt,
  executing,
  errorMessage,
  onApprove,
}: {
  plan: CertbotIssuePlanView | null;
  accepted: OperationAcceptedView | null;
  receipt: OperationReceiptView | null;
  executing: boolean;
  errorMessage: string | null;
  onApprove: (password: string, additionalAuthCode: string) => Promise<void>;
}) {
  const [password, setPassword] = useState("");
  const [additionalAuthCode, setAdditionalAuthCode] = useState("");
  const additionalAuthRequired = useAdditionalAuthRequired();
  const [externalEffectConfirmed, setExternalEffectConfirmed] = useState(false);
  const [attachDeferredConfirmed, setAttachDeferredConfirmed] = useState(false);

  async function submit(event: SyntheticEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!externalEffectConfirmed || !attachDeferredConfirmed) return;
    const submittedPassword = password;
    const submittedCode = additionalAuthCode;
    setPassword("");
    setAdditionalAuthCode("");
    await onApprove(submittedPassword, submittedCode);
  }

  if (receipt !== null) return <IssueResult receipt={receipt} />;
  if (accepted !== null) {
    return (
      <div aria-live="polite" className="flex items-start gap-3">
        <LoaderCircle aria-hidden="true" className="size-6 shrink-0 animate-spin text-warning" />
        <div>
          <h3 className="text-base font-semibold text-text">{STAGE_LABELS[accepted.currentStage]}</h3>
          <p className="mt-1 text-sm leading-6 text-muted">
            one-shot Certbot runner가 실행 중입니다. 창이 닫혀도 opsd 감사 원장이 결과를 계속
            추적합니다.
          </p>
        </div>
      </div>
    );
  }
  if (plan === null) {
    return errorMessage ? (
      <SurfaceState kind="error" title="발급 계획을 만들지 못했습니다" description={errorMessage} />
    ) : (
      <SurfaceState kind="empty" title="발급 계획이 없습니다" description="현재 상태로 새 계획을 만드세요." />
    );
  }

  return (
    <div>
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-muted">
            certbot certonly · {plan.environment}
          </p>
          <h3 className="mt-2 text-base font-semibold text-text">{plan.primaryDomain} 발급 계획</h3>
        </div>
        <AssuranceMark assurance={plan.assurance} />
      </div>

      <dl className="mt-5 grid grid-cols-2 gap-3 border-y border-border py-4 text-sm">
        <div>
          <dt className="text-xs text-muted">CA 환경</dt>
          <dd className="mt-1 font-medium text-text">{plan.environment}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted">계획 만료</dt>
          <dd className="mt-1 font-medium text-text">{formatDateTime(plan.expiresAt)}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted">DNS 일치</dt>
          <dd className="mt-1 break-words font-medium text-text">{plan.resolvedAddresses.join(", ")}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted">로컬 listener</dt>
          <dd className="mt-1 font-medium text-text">
            80 {plan.localPort80Reachable ? "확인" : "실패"} · 443 {plan.localPort443Reachable ? "확인" : "미확인"}
          </dd>
        </div>
        <div className="col-span-2">
          <dt className="text-xs text-muted">SAN</dt>
          <dd className="mt-1 break-words font-medium text-text">{plan.domains.join(", ")}</dd>
        </div>
        <div className="col-span-2">
          <dt className="text-xs text-muted">ACME 계정</dt>
          <dd className="mt-1 font-medium text-text">{plan.maskedAccountEmail}</dd>
        </div>
      </dl>

      {plan.environment === "production" && !plan.stagingEvidenceValid ? (
        <p role="alert" className="mt-5 text-sm font-medium leading-6 text-danger">
          같은 도메인·DNS·Nginx digest의 최근 staging 성공 증거가 없어 production 실행을 차단합니다.
        </p>
      ) : null}

      <section className="mt-5 border-y border-warning/35 py-4">
        <div className="flex items-start gap-3">
          <TriangleAlert aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-warning" />
          <div>
            <h4 className="text-sm font-semibold text-text">G1 · CA 외부효과는 자동 원복 불가</h4>
            <p className="mt-1 text-sm leading-6 text-muted">
              production 발급과 rate-limit 기록은 되돌릴 수 없습니다. 이번 승인에는 Nginx TLS 연결이
              포함되지 않습니다.
            </p>
          </div>
        </div>
      </section>
      <section className="mt-5">
        <h4 className="text-xs font-semibold text-muted">실행 영향</h4>
        <BulletList values={plan.impact} />
      </section>
      <div className="mt-5"><AssuranceDetails assurance={plan.assurance} /></div>
      <section className="mt-5 border-y border-border py-4">
        <h4 className="text-xs font-semibold text-muted">실패·중단 시 확인 경로</h4>
        <BulletList values={plan.recoveryPath} />
      </section>

      {errorMessage ? <p role="alert" className="mt-5 text-sm font-medium text-danger">{errorMessage}</p> : null}
      <form className="mt-6" onSubmit={(event) => void submit(event)}>
        <label className="flex items-start gap-3 text-sm leading-6 text-text">
          <input
            type="checkbox"
            className="mt-1 size-4 accent-accent"
            checked={externalEffectConfirmed}
            onChange={(event) => setExternalEffectConfirmed(event.currentTarget.checked)}
          />
          CA challenge·발급·rate-limit 외부효과는 자동 원복되지 않음을 확인했습니다.
        </label>
        <label className="mt-3 flex items-start gap-3 text-sm leading-6 text-text">
          <input
            type="checkbox"
            className="mt-1 size-4 accent-accent"
            checked={attachDeferredConfirmed}
            onChange={(event) => setAttachDeferredConfirmed(event.currentTarget.checked)}
          />
          이번 작업은 발급까지만 수행하며 Nginx TLS 연결은 별도 G2 계획임을 확인했습니다.
        </label>
        <label htmlFor="certbot-issue-password" className="mt-5 block text-sm font-medium text-text">
          Linux 계정 비밀번호로 exact plan 승인
        </label>
        <Input
          id="certbot-issue-password"
          type="password"
          autoComplete="current-password"
          maxLength={1024}
          required
          disabled={executing}
          value={password}
          onChange={(event) => setPassword(event.currentTarget.value)}
        />
        <AdditionalAuthCodeField id="certbot-issue-totp" value={additionalAuthCode} onChange={setAdditionalAuthCode} disabled={executing} />
        <Button
          className="mt-4 w-full"
          type="submit"
          disabled={
            executing ||
            password.length === 0 ||
            (additionalAuthRequired && additionalAuthCode.length !== 6) ||
            !externalEffectConfirmed ||
            !attachDeferredConfirmed ||
            (plan.environment === "production" && !plan.stagingEvidenceValid)
          }
        >
          {executing ? <LoaderCircle aria-hidden="true" className="size-4 animate-spin" /> : <KeyRound aria-hidden="true" className="size-4" />}
          {executing ? "승인·실행 요청 중" : `${plan.environment} 발급 실행`}
        </Button>
      </form>
    </div>
  );
}

function IssueResult({ receipt }: { receipt: OperationReceiptView }) {
  const succeeded = receipt.terminalState === "SUCCEEDED";
  return (
    <div aria-live="polite">
      <div className="flex items-start gap-3">
        {succeeded ? (
          <CheckCircle2 aria-hidden="true" className="size-6 shrink-0 text-success" />
        ) : (
          <XCircle aria-hidden="true" className="size-6 shrink-0 text-danger" />
        )}
        <div>
          <h3 className="text-base font-semibold text-text">
            {succeeded ? "인증서 발급 검증 완료" : STAGE_LABELS[receipt.terminalState]}
          </h3>
          <p className="mt-1 text-sm leading-6 text-muted">
            {succeeded
              ? "Certbot 결과와 sanitized inventory를 검증했습니다. TLS 연결은 아직 변경하지 않았습니다."
              : "발급을 성공으로 처리하지 않았습니다. DNS·80 포트·webroot와 감사 단계를 확인하세요."}
          </p>
        </div>
      </div>
      <ol className="mt-6 border-y border-border py-2">
        {receipt.stages.map((stage) => (
          <li key={stage.sequence} className="flex gap-3 py-3 text-sm">
            <CircleDot aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted" />
            <div className="min-w-0">
              <p className="font-medium text-text">{STAGE_LABELS[stage.stage]}</p>
              <p className="mt-1 break-words text-xs text-muted">{formatDateTime(stage.recordedAt)} · {stage.resultCode}</p>
            </div>
          </li>
        ))}
      </ol>
      {receipt.recoveryPath.length > 0 ? <section className="mt-5"><BulletList values={receipt.recoveryPath} /></section> : null}
      <div className="mt-5"><AssuranceDetails assurance={receipt.assurance} /></div>
    </div>
  );
}

const STAGE_LABELS: Record<OperationStage, string> = {
  PLANNED: "계획 생성",
  APPROVED: "승인 완료",
  SNAPSHOTTED: "인증서 상태 저장",
  APPLYING: "Certbot 작업 실행",
  VALIDATING: "결과 재검증",
  RELOADING: "서비스 reload",
  VERIFYING: "적용 상태 확인",
  ROLLING_BACK: "이전 상태 원복",
  SUCCEEDED: "작업 검증 완료",
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
  onApprove: (password: string, additionalAuthCode: string) => Promise<void>;
}) {
  const [password, setPassword] = useState("");
  const [additionalAuthCode, setAdditionalAuthCode] = useState("");
  const additionalAuthRequired = useAdditionalAuthRequired();
  const [externalEffectConfirmed, setExternalEffectConfirmed] = useState(false);

  async function submit(event: SyntheticEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!externalEffectConfirmed) return;
    const submittedPassword = password;
    const submittedCode = additionalAuthCode;
    setPassword("");
    setAdditionalAuthCode("");
    await onApprove(submittedPassword, submittedCode);
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
        <AdditionalAuthCodeField id="certbot-renew-totp" value={additionalAuthCode} onChange={setAdditionalAuthCode} disabled={executing} />
        <Button
          className="mt-4 w-full"
          type="submit"
          disabled={executing || password.length === 0 || (additionalAuthRequired && additionalAuthCode.length !== 6) || !externalEffectConfirmed}
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
            {succeeded ? "갱신 검증 완료" : STAGE_LABELS[receipt.terminalState]}
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

function operationErrorCopy(error: unknown, fallback: string): string {
  if (!(error instanceof ApiError)) return fallback;
  const messages: Record<string, string> = {
    stale_inventory: "인증서 상태가 바뀌었습니다. 다시 조회한 뒤 새 계획을 만드세요.",
    stale_site: "Nginx 관리 site가 바뀌었습니다. 현재 설정을 다시 조회하세요.",
    invalid_domain: "공개 관리 도메인과 발급 도메인이 일치하지 않습니다.",
    dns_resolution_failed: "공개 DNS를 조회하지 못했습니다. A/AAAA 레코드를 확인하세요.",
    dns_mismatch: "공개 DNS 주소와 설정된 서버 주소가 일치하지 않습니다.",
    challenge_unreachable: "로컬 80 포트 또는 ACME challenge 경로를 확인할 수 없습니다.",
    wrong_webroot: "제품 관리 Nginx site에 고정 ACME webroot include가 없습니다.",
    staging_required: "같은 도메인·DNS·Nginx 설정의 최근 staging 성공이 먼저 필요합니다.",
    preflight_stale: "DNS·포트 사전검증이 만료되었습니다. 새 계획을 만드세요.",
    issuance_failed: "Certbot 발급이 실패했습니다. 원문 대신 감사 digest만 기록됐습니다.",
    certificate_invalid: "발급 결과의 SAN·lineage·timer 검증을 통과하지 못했습니다.",
    attach_unsupported: "보호된 관리 vhost의 TLS 지시문 구조를 안전하게 한정할 수 없습니다.",
    attach_unavailable: "Nginx TLS 연결 사전조건 또는 fault gate가 준비되지 않았습니다.",
    protected_config_invalid: "보호된 관리 vhost의 구조가 변경되어 작업을 차단했습니다.",
    tls_read_back_failed: "SNI 인증서 지문 또는 Nginx·timer read-back이 실패해 자동 원복했습니다.",
    config_replace_confirmation: "Nginx 인증서 지시문 교체 확인이 필요합니다.",
    service_reload_confirmation: "Nginx reload 영향 확인이 필요합니다.",
    issuance_unavailable: "신규 발급 사전조건 또는 fault gate가 준비되지 않았습니다.",
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
