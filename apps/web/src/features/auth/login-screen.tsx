import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { Eye, EyeOff, KeyRound, LockKeyhole, Server, ShieldCheck } from "lucide-react";
import { useEffect, useRef, useState, type SyntheticEvent } from "react";

import { ApiError, login } from "../../shared/api/client";
import { healthQueryOptions, queryKeys, sessionQueryOptions } from "../../shared/api/queries";
import { AUTH_COPY, PRODUCT } from "../../shared/content/copy";
import { safeReturnTo } from "../../shared/domain/return-to";
import { Button } from "../../shared/ui/button";
import { Input } from "../../shared/ui/input";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark } from "../../shared/ui/status-mark";

interface LoginScreenProps {
  returnTo: string;
}

export function LoginScreen({ returnTo }: LoginScreenProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const errorRef = useRef<HTMLDivElement>(null);
  const health = useQuery(healthQueryOptions);
  const session = useQuery(sessionQueryOptions);
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  useEffect(() => {
    if (session.data === undefined) return;
    void navigate({ to: safeReturnTo(returnTo), replace: true });
  }, [navigate, returnTo, session.data]);

  useEffect(() => {
    if (errorMessage !== null) errorRef.current?.focus();
  }, [errorMessage]);

  const isRecovery = health.data?.ingress === "recovery";
  const hasValidTransport = isRecovery || window.location.protocol === "https:";
  const pamAvailable = health.data?.pam === "available";
  const formEnabled = health.isSuccess && hasValidTransport && pamAvailable;

  async function handleSubmit(event: SyntheticEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!formEnabled || submitting) return;

    setSubmitting(true);
    setErrorMessage(null);
    try {
      const authenticatedSession = await login({ username, password });
      queryClient.setQueryData(queryKeys.session, authenticatedSession);
      setPassword("");
      await navigate({ to: safeReturnTo(returnTo), replace: true });
    } catch (error) {
      setPassword("");
      if (error instanceof ApiError && error.status === 429) {
        const retry = error.retryAfterSeconds;
        setErrorMessage(
          retry === null
            ? "요청이 너무 많습니다. 잠시 후 다시 시도해 주세요."
            : `${String(retry)}초 후 다시 시도해 주세요.`,
        );
      } else if (error instanceof ApiError && error.status >= 500) {
        setErrorMessage(AUTH_COPY.unavailable);
      } else {
        setErrorMessage(AUTH_COPY.genericError);
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="login-canvas">
      <header className="flex h-14 items-center border-b border-border px-4 md:px-8">
        <div className="flex items-center gap-3">
          <div className="flex size-8 items-center justify-center rounded-control bg-text text-surface">
            <Server aria-hidden="true" className="size-4" />
          </div>
          <div>
            <p className="text-sm font-semibold text-text">{PRODUCT.name}</p>
            <p className="text-xs text-muted">{PRODUCT.edition}</p>
          </div>
        </div>
      </header>

      <main className="login-grid">
        <section className="hidden lg:block" aria-labelledby="login-context-title">
          <p className="text-xs font-semibold uppercase tracking-widest text-muted">Ubuntu server care</p>
          <h1 id="login-context-title" className="mt-4 max-w-xl text-4xl font-semibold leading-tight text-text">
            서버 상태와 접속 경계를 한 화면에서 확인합니다.
          </h1>
          <div className="mt-10 divide-y divide-border border-y border-border">
            <div className="flex items-start gap-4 py-5">
              <ShieldCheck aria-hidden="true" className="mt-0.5 size-5 text-action" />
              <div>
                <p className="text-sm font-semibold text-text">Linux PAM 인증</p>
                <p className="mt-1 text-sm leading-6 text-muted">별도 웹 비밀번호를 만들거나 저장하지 않습니다.</p>
              </div>
            </div>
            <div className="flex items-start gap-4 py-5">
              <LockKeyhole aria-hidden="true" className="mt-0.5 size-5 text-action" />
              <div>
                <p className="text-sm font-semibold text-text">두 개의 복구 경로</p>
                <p className="mt-1 text-sm leading-6 text-muted">공개 HTTPS가 실패해도 SSH 터널 접속을 유지합니다.</p>
              </div>
            </div>
          </div>
        </section>

        <section className="rounded-panel border border-border bg-surface p-5 sm:p-7" aria-labelledby="login-title">
          <KeyRound aria-hidden="true" className="size-6 text-action" />
          <h1 id="login-title" className="mt-5 text-2xl font-semibold text-text">
            {AUTH_COPY.title}
          </h1>
          <p className="mt-2 text-sm leading-6 text-muted">{AUTH_COPY.description}</p>

          <div className="mt-5 border-y border-border py-3">
            {health.isPending ? (
              <Skeleton className="h-5 w-40" />
            ) : health.isError ? (
              <StatusMark label="Agent 연결 실패" tone="danger" />
            ) : (
              <StatusMark
                label={isRecovery ? AUTH_COPY.recovery : AUTH_COPY.public}
                tone={health.data.status === "ok" ? "success" : "warning"}
              />
            )}
          </div>

          {!hasValidTransport && health.isSuccess ? (
            <div className="mt-5 border-l-2 border-danger pl-3 text-sm leading-6 text-text">
              {AUTH_COPY.httpsRequired}
            </div>
          ) : null}

          {health.isSuccess && !pamAvailable ? (
            <div className="mt-5 border-l-2 border-warning pl-3 text-sm leading-6 text-text">
              {AUTH_COPY.unavailable}
            </div>
          ) : null}

          {errorMessage ? (
            <div
              ref={errorRef}
              tabIndex={-1}
              role="alert"
              className="mt-5 rounded-control bg-danger/10 px-3 py-3 text-sm font-medium text-danger"
            >
              {errorMessage}
            </div>
          ) : null}

          <form className="mt-6 space-y-5" onSubmit={(event) => void handleSubmit(event)}>
            <div>
              <label htmlFor="username" className="mb-2 block text-sm font-medium text-text">
                {AUTH_COPY.username}
              </label>
              <Input
                id="username"
                name="username"
                autoComplete="username"
                autoCapitalize="none"
                spellCheck={false}
                maxLength={64}
                required
                disabled={!formEnabled || submitting}
                value={username}
                onChange={(event) => setUsername(event.currentTarget.value)}
              />
            </div>

            <div>
              <label htmlFor="password" className="mb-2 block text-sm font-medium text-text">
                {AUTH_COPY.password}
              </label>
              <div className="relative">
                <Input
                  id="password"
                  name="password"
                  type={passwordVisible ? "text" : "password"}
                  autoComplete="current-password"
                  maxLength={1024}
                  required
                  disabled={!formEnabled || submitting}
                  value={password}
                  className="pr-12"
                  onChange={(event) => setPassword(event.currentTarget.value)}
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 flex w-11 items-center justify-center rounded-r-control text-muted hover:text-text disabled:opacity-45"
                  aria-label={passwordVisible ? AUTH_COPY.hidePassword : AUTH_COPY.showPassword}
                  disabled={!formEnabled || submitting}
                  onClick={() => setPasswordVisible((visible) => !visible)}
                >
                  {passwordVisible ? (
                    <EyeOff aria-hidden="true" className="size-4" />
                  ) : (
                    <Eye aria-hidden="true" className="size-4" />
                  )}
                </button>
              </div>
            </div>

            <Button className="w-full" type="submit" disabled={!formEnabled || submitting}>
              {submitting ? AUTH_COPY.submitting : AUTH_COPY.submit}
            </Button>
          </form>

          <p className="mt-5 text-xs leading-5 text-muted">
            비밀번호는 JW Agent DB·로그·브라우저 저장소에 보관하지 않습니다.
          </p>
        </section>
      </main>

      <footer className="border-t border-border px-4 py-4 text-xs text-muted md:px-8">
        지원 범위: Ubuntu 24.04 LTS · 로컬 pam_unix
      </footer>
    </div>
  );
}
