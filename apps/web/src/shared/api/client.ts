// The request and response types in this module come from api/openapi.json.
// Route and feature modules must not call fetch directly.
import createClient from "openapi-fetch";

import type { paths } from "./generated/schema";
import type {
  AccessSettingsView,
  AdditionalAuthPolicy,
  HealthView,
  HostObservation,
  IntegrationCatalogView,
  NginxSitesView,
  ProblemDetails,
  ReauthView,
  SessionView,
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

function mutationHeaders(): HeadersInit {
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
