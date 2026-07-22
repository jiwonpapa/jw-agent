// The request and response types in this module come from api/openapi.json.
// Route and feature modules must not call fetch directly.
import createClient from "openapi-fetch";

import type { paths } from "./generated/schema";
import type {
  AccessSettingsView,
  AdditionalAuthPolicy,
  CertificateInventoryView,
  CertbotAttachApprovalRequest,
  CertbotAttachPlanRequest,
  CertbotAttachPlanView,
  CertbotIssueApprovalRequest,
  CertbotIssuePlanRequest,
  CertbotIssuePlanView,
  CertbotRenewTestApprovalRequest,
  CertbotRenewTestPlanRequest,
  CertbotRenewTestPlanView,
  FileCapabilityView,
  FileListView,
  FilePathRequest,
  FileSessionRequest,
  FileSessionView,
  FileStatView,
  FileTextView,
  FileUploadPlanRequest,
  FileUploadPlanView,
  FileUploadResultView,
  HealthView,
  HostObservation,
  IntegrationCatalogView,
  ManagedConfigApprovalRequest,
  ManagedConfigPlanRequest,
  ManagedConfigPlanView,
  ManagedConfigResourceView,
  NginxSiteStatePlanRequest,
  NginxSiteStatePlanView,
  NginxSitesView,
  OperationAcceptedView,
  OperationApprovalRequest,
  OperationListView,
  OperationReceiptView,
  OperationStageEvidenceView,
  PhpFpmView,
  ProblemDetails,
  ReauthView,
  SessionView,
  ServicesView,
  TerminalCapabilityView,
  TerminalTicketRequest,
  TerminalTicketView,
  TotpEnrollmentConfirmView,
  TotpEnrollmentStartView,
  TotpVerificationView,
} from "./types";

const api = createClient<paths>({
  baseUrl: "/",
  credentials: "same-origin",
  headers: {
    Accept: "application/json",
  },
});

let csrfToken: string | null = null;

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryAfterSeconds: number | null;

  constructor(problem: Partial<ProblemDetails> | undefined, response: Response) {
    super(problem?.title ?? "요청을 완료하지 못했습니다.");
    this.name = "ApiError";
    this.status = response.status;
    this.code = problem?.code ?? "unknown_error";
    const retryAfter = response.headers.get("retry-after");
    this.retryAfterSeconds = retryAfter === null ? null : Number.parseInt(retryAfter, 10);
  }
}

function rememberSession(session: SessionView): SessionView {
  csrfToken = session.csrfToken;
  return session;
}

function forgetSession(): void {
  csrfToken = null;
}

function mutationHeaders(): Record<string, string> {
  return csrfToken === null ? {} : { "X-CSRF-Token": csrfToken };
}

export async function getHealth(signal?: AbortSignal): Promise<HealthView> {
  const { data, error, response } = await api.GET("/api/v1/health", {
    signal: signal ?? null,
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function getSession(signal?: AbortSignal): Promise<SessionView> {
  const { data, error, response } = await api.GET("/api/v1/auth/session", {
    signal: signal ?? null,
  });
  if (data !== undefined) return rememberSession(data);
  forgetSession();
  throw new ApiError(error, response);
}

export async function getOptionalSession(signal?: AbortSignal): Promise<SessionView | null> {
  try {
    return await getSession(signal);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return null;
    throw error;
  }
}

export async function login(input: { username: string; password: string }): Promise<SessionView> {
  const { data, error, response } = await api.POST("/api/v1/auth/login", {
    body: input,
  });
  if (data !== undefined) return rememberSession(data);
  forgetSession();
  throw new ApiError(error, response);
}

export async function logout(): Promise<void> {
  const { error, response } = await api.POST("/api/v1/auth/logout", {
    headers: mutationHeaders(),
  });
  forgetSession();
  if (!response.ok) throw new ApiError(error, response);
}

export async function getHost(signal?: AbortSignal): Promise<HostObservation> {
  const { data, error, response } = await api.GET("/api/v1/host", { signal: signal ?? null });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function getNginxSites(signal?: AbortSignal): Promise<NginxSitesView> {
  const { data, error, response } = await api.GET("/api/v1/services/nginx/sites", {
    signal: signal ?? null,
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function getServices(signal?: AbortSignal): Promise<ServicesView> {
  const { data, error, response } = await api.GET("/api/v1/services", {
    signal: signal ?? null,
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function getPhpFpm(signal?: AbortSignal): Promise<PhpFpmView> {
  const { data, error, response } = await api.GET("/api/v1/services/php-fpm", {
    signal: signal ?? null,
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function getRecentOperations(signal?: AbortSignal): Promise<OperationListView> {
  const { data, error, response } = await api.GET("/api/v1/activity", {
    signal: signal ?? null,
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function getCertificates(signal?: AbortSignal): Promise<CertificateInventoryView> {
  const { data, error, response } = await api.GET("/api/v1/certificates", {
    signal: signal ?? null,
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function planCertbotIssue(
  input: CertbotIssuePlanRequest,
): Promise<CertbotIssuePlanView> {
  const { data, error, response } = await api.POST("/api/v1/operations/certbot/issue/plans", {
    body: input,
    headers: mutationHeaders(),
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function approveCertbotIssue(
  input: CertbotIssueApprovalRequest,
): Promise<OperationAcceptedView> {
  const { data, error, response } = await api.POST(
    "/api/v1/operations/certbot/issue/approvals",
    {
      body: input,
      headers: mutationHeaders(),
    },
  );
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function planCertbotRenewTest(
  input: CertbotRenewTestPlanRequest,
): Promise<CertbotRenewTestPlanView> {
  const { data, error, response } = await api.POST(
    "/api/v1/operations/certbot/renew-test/plans",
    {
      body: input,
      headers: mutationHeaders(),
    },
  );
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function approveCertbotRenewTest(
  input: CertbotRenewTestApprovalRequest,
): Promise<OperationAcceptedView> {
  const { data, error, response } = await api.POST(
    "/api/v1/operations/certbot/renew-test/approvals",
    {
      body: input,
      headers: mutationHeaders(),
    },
  );
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function planCertbotAttach(
  input: CertbotAttachPlanRequest,
): Promise<CertbotAttachPlanView> {
  const { data, error, response } = await api.POST(
    "/api/v1/operations/certbot/attach/plans",
    {
      body: input,
      headers: mutationHeaders(),
    },
  );
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function approveCertbotAttach(
  input: CertbotAttachApprovalRequest,
): Promise<OperationAcceptedView> {
  const { data, error, response } = await api.POST(
    "/api/v1/operations/certbot/attach/approvals",
    {
      body: input,
      headers: mutationHeaders(),
    },
  );
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function planNginxSiteState(
  input: NginxSiteStatePlanRequest,
): Promise<NginxSiteStatePlanView> {
  const { data, error, response } = await api.POST(
    "/api/v1/operations/nginx/site-state/plans",
    {
      body: input,
      headers: mutationHeaders(),
    },
  );
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function getManagedConfigResource(
  resourceId: string,
  signal?: AbortSignal,
): Promise<ManagedConfigResourceView> {
  const { data, error, response } = await api.GET("/api/v1/config-resources/{resource_id}", {
    params: { path: { resource_id: resourceId } },
    signal: signal ?? null,
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function planManagedConfig(
  input: ManagedConfigPlanRequest,
): Promise<ManagedConfigPlanView> {
  const { data, error, response } = await api.POST(
    "/api/v1/operations/service/config-file/plans",
    {
      body: input,
      headers: mutationHeaders(),
    },
  );
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function approveManagedConfig(
  input: ManagedConfigApprovalRequest,
): Promise<OperationAcceptedView> {
  const { data, error, response } = await api.POST(
    "/api/v1/operations/service/config-file/approvals",
    {
      body: input,
      headers: mutationHeaders(),
    },
  );
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function reauthenticateForOperation(input: {
  password: string;
  planHash: string;
  additionalAuthCode?: string;
}): Promise<ReauthView & { additionalAuthClaim?: string }> {
  const { data, error, response } = await api.POST("/api/v1/auth/reauth", {
    body: {
      password: input.password,
      purpose: {
        kind: "operation",
        planHash: input.planHash,
      },
    },
    headers: mutationHeaders(),
  });
  if (data !== undefined) {
    rememberSession(data.session);
    if (input.additionalAuthCode === undefined || input.additionalAuthCode.length === 0) {
      return data;
    }
    const verified = await verifyTotpForOperation({
      reauthToken: data.reauthToken,
      planHash: input.planHash,
      code: input.additionalAuthCode,
    });
    return { ...data, additionalAuthClaim: verified.additionalAuthClaim };
  }
  throw new ApiError(error, response);
}

export async function reauthenticateForTotpEnrollment(password: string): Promise<ReauthView> {
  return reauthenticateForTotpPurpose(password, "totp_enrollment");
}

export async function reauthenticateForTotpReset(password: string): Promise<ReauthView> {
  return reauthenticateForTotpPurpose(password, "totp_recovery_reset");
}

async function reauthenticateForTotpPurpose(
  password: string,
  kind: "totp_enrollment" | "totp_recovery_reset",
): Promise<ReauthView> {
  const { data, error, response } = await api.POST("/api/v1/auth/reauth", {
    body: { password, purpose: { kind } },
    headers: mutationHeaders(),
  });
  if (data !== undefined) {
    rememberSession(data.session);
    return data;
  }
  throw new ApiError(error, response);
}

export async function beginTotpEnrollment(reauthToken: string): Promise<TotpEnrollmentStartView> {
  const { data, error, response } = await api.POST("/api/v1/settings/access/totp/enrollment", {
    body: { reauthToken },
    headers: mutationHeaders(),
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function confirmTotpEnrollment(input: {
  enrollmentId: string;
  code: string;
}): Promise<TotpEnrollmentConfirmView> {
  const { data, error, response } = await api.POST(
    "/api/v1/settings/access/totp/enrollment/confirm",
    { body: input, headers: mutationHeaders() },
  );
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function verifyTotpForOperation(input: {
  reauthToken: string;
  planHash: string;
  code: string;
}): Promise<TotpVerificationView> {
  const { data, error, response } = await api.POST("/api/v1/auth/totp/verify", {
    body: input,
    headers: mutationHeaders(),
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function resetTotp(input: {
  reauthToken: string;
  recoveryCode: string;
}): Promise<void> {
  const { error, response } = await api.POST("/api/v1/settings/access/totp/reset", {
    body: input,
    headers: mutationHeaders(),
  });
  if (response.ok) {
    forgetSession();
    return;
  }
  throw new ApiError(error, response);
}

export async function approveNginxSiteState(
  input: OperationApprovalRequest,
): Promise<OperationAcceptedView> {
  const { data, error, response } = await api.POST(
    "/api/v1/operations/nginx/site-state/approvals",
    {
      body: input,
      headers: mutationHeaders(),
    },
  );
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export function watchOperationEvents(
  eventStream: string,
  onStage: (stage: OperationStageEvidenceView) => void,
  onStreamError: (code: string) => void,
): () => void {
  if (!/^\/api\/v1\/operations\/[A-Za-z0-9_-]{1,64}\/events$/.test(eventStream)) {
    onStreamError("invalid_event_stream");
    return () => undefined;
  }
  const source = new EventSource(eventStream);
  source.addEventListener("operation-stage", (event) => {
    if (!(event instanceof MessageEvent) || typeof event.data !== "string") return;
    try {
      onStage(JSON.parse(event.data) as OperationStageEvidenceView);
    } catch {
      onStreamError("invalid_operation_event");
    }
  });
  source.addEventListener("operation-error", (event) => {
    if (!(event instanceof MessageEvent) || typeof event.data !== "string") {
      onStreamError("operation_event_unavailable");
      return;
    }
    try {
      const value = JSON.parse(event.data) as { code?: unknown };
      onStreamError(typeof value.code === "string" ? value.code : "operation_event_unavailable");
    } catch {
      onStreamError("invalid_operation_event");
    }
  });
  return () => source.close();
}

export async function getOperationReceipt(
  operationId: string,
  signal?: AbortSignal,
): Promise<OperationReceiptView> {
  const { data, error, response } = await api.GET("/api/v1/operations/{operation_id}", {
    params: { path: { operation_id: operationId } },
    signal: signal ?? null,
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function getIntegrations(signal?: AbortSignal): Promise<IntegrationCatalogView> {
  const { data, error, response } = await api.GET("/api/v1/integrations", {
    signal: signal ?? null,
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function getAccessSettings(signal?: AbortSignal): Promise<AccessSettingsView> {
  const { data, error, response } = await api.GET("/api/v1/settings/access", {
    signal: signal ?? null,
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function updateAdditionalAuthPolicy(input: {
  policy: AdditionalAuthPolicy;
  reauthToken?: string;
}): Promise<AccessSettingsView> {
  const { data, error, response } = await api.PUT(
    "/api/v1/settings/access/additional-auth",
    {
      body: input,
      headers: mutationHeaders(),
    },
  );
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function reauthenticateForPolicy(input: {
  password: string;
  targetPolicy: AdditionalAuthPolicy;
}): Promise<ReauthView> {
  const { data, error, response } = await api.POST("/api/v1/auth/reauth", {
    body: {
      password: input.password,
      purpose: {
        kind: "security_policy_change",
        targetPolicy: input.targetPolicy,
      },
    },
    headers: mutationHeaders(),
  });
  if (data !== undefined) {
    rememberSession(data.session);
    return data;
  }
  throw new ApiError(error, response);
}

export async function getTerminalCapability(
  signal?: AbortSignal,
): Promise<TerminalCapabilityView> {
  const { data, error, response } = await api.GET("/api/v1/terminal", {
    signal: signal ?? null,
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function issueTerminalTicket(
  input: TerminalTicketRequest,
): Promise<TerminalTicketView> {
  const { data, error, response } = await api.POST("/api/v1/terminal/tickets", {
    body: input,
    headers: mutationHeaders(),
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export function openTerminalSocket(websocketPath: string, ticket: string): WebSocket {
  if (websocketPath !== "/api/v1/terminal/connect") {
    throw new Error("서버가 허용하지 않은 터미널 경로를 반환했습니다.");
  }
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return new WebSocket(
    `${protocol}//${window.location.host}${websocketPath}`,
    ["jw-terminal-v1", `ticket.${ticket}`],
  );
}

export async function getFileCapability(signal?: AbortSignal): Promise<FileCapabilityView> {
  const { data, error, response } = await api.GET("/api/v1/files", {
    signal: signal ?? null,
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function createFileSession(input: FileSessionRequest): Promise<FileSessionView> {
  const { data, error, response } = await api.POST("/api/v1/files/sessions", {
    body: input,
    headers: mutationHeaders(),
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function closeFileSession(sessionToken: string): Promise<void> {
  const { error, response } = await api.POST("/api/v1/files/sessions/close", {
    body: { sessionToken },
    headers: mutationHeaders(),
  });
  if (response.ok) return;
  throw new ApiError(error, response);
}

export async function listFiles(input: FilePathRequest): Promise<FileListView> {
  const { data, error, response } = await api.POST("/api/v1/files/list", {
    body: input,
    headers: mutationHeaders(),
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function statFile(input: FilePathRequest): Promise<FileStatView> {
  const { data, error, response } = await api.POST("/api/v1/files/stat", {
    body: input,
    headers: mutationHeaders(),
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function readTextFile(input: FilePathRequest): Promise<FileTextView> {
  const { data, error, response } = await api.POST("/api/v1/files/read", {
    body: input,
    headers: mutationHeaders(),
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function downloadFile(input: FilePathRequest): Promise<Blob> {
  const { data, error, response } = await api.POST("/api/v1/files/download", {
    body: input,
    headers: mutationHeaders(),
    parseAs: "blob",
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function planFileUpload(
  input: FileUploadPlanRequest,
): Promise<FileUploadPlanView> {
  const { data, error, response } = await api.POST("/api/v1/files/upload/plans", {
    body: input,
    headers: mutationHeaders(),
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}

export async function applyFileUpload(input: {
  sessionToken: string;
  planToken: string;
  content: Uint8Array<ArrayBuffer>;
}): Promise<FileUploadResultView> {
  const { data, error, response } = await api.POST("/api/v1/files/upload", {
    body: input.content as unknown as number[],
    bodySerializer: (body) => body as unknown as BodyInit,
    headers: {
      ...mutationHeaders(),
      "Content-Type": "application/octet-stream",
      "X-JW-File-Session": input.sessionToken,
      "X-JW-Upload-Plan": input.planToken,
    },
  });
  if (data !== undefined) return data;
  throw new ApiError(error, response);
}
