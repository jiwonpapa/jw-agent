import * as Dialog from "@radix-ui/react-dialog";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, LogOut, ShieldCheck, X } from "lucide-react";
import {
  createContext,
  useCallback,
  useContext,
  useRef,
  useState,
  type ReactNode,
  type SyntheticEvent,
} from "react";

import {
  ApiError,
  enterAdministrativeAccess,
  leaveAdministrativeAccess,
} from "../../shared/api/client";
import { queryKeys, sessionQueryOptions } from "../../shared/api/queries";
import type { SessionView } from "../../shared/api/types";
import { ROLE_LABELS } from "../../shared/content/copy";
import { formatDateTime } from "../../shared/domain/format";
import { Button } from "../../shared/ui/button";
import { Input } from "../../shared/ui/input";
import { StatusMark } from "../../shared/ui/status-mark";

interface AdministrativeAccessContextValue {
  requestAccess: (afterGranted?: () => void) => void;
  leaveAccess: () => Promise<void>;
  leaving: boolean;
}

const AdministrativeAccessContext = createContext<AdministrativeAccessContextValue | null>(null);

export function AdministrativeAccessProvider({ children }: { children: ReactNode }) {
  const session = useQuery(sessionQueryOptions).data;
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [leaving, setLeaving] = useState(false);
  const [password, setPassword] = useState("");
  const [additionalAuthCode, setAdditionalAuthCode] = useState("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const afterGrantedRef = useRef<(() => void) | null>(null);

  const requestAccess = useCallback((afterGranted?: () => void) => {
    if (session?.administrativeAccess === "administrative") {
      afterGranted?.();
      return;
    }
    afterGrantedRef.current = afterGranted ?? null;
    setErrorMessage(null);
    setOpen(true);
  }, [session?.administrativeAccess]);

  async function handleSubmit(event: SyntheticEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (submitting || session?.subject.role !== "admin") return;
    setSubmitting(true);
    setErrorMessage(null);
    try {
      const next = await enterAdministrativeAccess(
        additionalAuthCode.length === 0 ? { password } : { password, additionalAuthCode },
      );
      queryClient.setQueryData(queryKeys.session, next);
      setPassword("");
      setAdditionalAuthCode("");
      setOpen(false);
      const afterGranted = afterGrantedRef.current;
      afterGrantedRef.current = null;
      afterGranted?.();
    } catch (error) {
      setPassword("");
      setAdditionalAuthCode("");
      if (error instanceof ApiError && error.status === 429) {
        setErrorMessage("요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.");
      } else if (error instanceof ApiError && error.status >= 500) {
        setErrorMessage("현재 PAM 또는 추가 인증을 사용할 수 없습니다.");
      } else {
        setErrorMessage("Linux 비밀번호와 추가 인증 코드를 확인해 주세요.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  async function leaveAccess(): Promise<void> {
    if (leaving) return;
    setLeaving(true);
    try {
      const next = await leaveAdministrativeAccess();
      queryClient.setQueryData(queryKeys.session, next);
    } finally {
      setLeaving(false);
    }
  }

  function handleOpenChange(nextOpen: boolean): void {
    if (submitting) return;
    setOpen(nextOpen);
    if (!nextOpen) {
      setPassword("");
      setAdditionalAuthCode("");
      setErrorMessage(null);
      afterGrantedRef.current = null;
    }
  }

  return (
    <AdministrativeAccessContext.Provider value={{ requestAccess, leaveAccess, leaving }}>
      {children}
      <Dialog.Root open={open} onOpenChange={handleOpenChange}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 animate-overlay-in bg-text/45 backdrop-blur-sm" />
          <Dialog.Content className="fixed left-1/2 top-1/2 z-[60] max-h-[calc(100dvh-2rem)] w-[calc(100%-2rem)] max-w-lg -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-panel border border-border bg-surface p-5 shadow-xl sm:p-7">
            <div className="flex items-start justify-between gap-4">
              <div>
                <Dialog.Title className="text-xl font-semibold text-text">관리 모드 열기</Dialog.Title>
                <Dialog.Description className="mt-2 text-sm leading-6 text-muted">
                  root 계정으로 로그인하지 않습니다. 승인된 typed 작업만 root opsd가 실행합니다.
                </Dialog.Description>
              </div>
              <Dialog.Close className="inline-flex size-11 shrink-0 items-center justify-center rounded-control text-muted hover:bg-subtle hover:text-text">
                <X aria-hidden="true" className="size-5" />
                <span className="sr-only">닫기</span>
              </Dialog.Close>
            </div>

            <div className="mt-6 rounded-control border border-warning/40 bg-warning/5 p-4">
              <div className="flex items-start gap-3">
                <ShieldCheck aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-warning" />
                <div className="text-sm leading-6">
                  <p className="font-semibold text-text">15분 제한 관리 권한</p>
                  <p className="mt-1 text-muted">진입하면 session ID가 회전하며 열린 터미널·SFTP 연결은 보안상 종료됩니다.</p>
                  <p className="mt-1 text-muted">15분 동안 지원되는 설정 저장에는 비밀번호를 다시 요구하지 않습니다.</p>
                </div>
              </div>
            </div>

            {session?.subject.role !== "admin" ? (
              <div className="mt-5 rounded-control border border-danger/30 bg-danger/5 p-4 text-sm text-danger" role="alert">
                이 계정에는 관리 모드 권한이 없습니다.
              </div>
            ) : null}
            {errorMessage ? (
              <div className="mt-5 rounded-control border border-danger/30 bg-danger/5 p-4 text-sm text-danger" role="alert">
                {errorMessage}
              </div>
            ) : null}

            <form className="mt-6 space-y-5" onSubmit={(event) => void handleSubmit(event)}>
              <div>
                <label htmlFor="administrative-password" className="mb-2 block text-sm font-medium text-text">Linux 비밀번호</label>
                <Input
                  id="administrative-password"
                  type="password"
                  autoComplete="current-password"
                  maxLength={1024}
                  required
                  disabled={submitting || session?.subject.role !== "admin"}
                  value={password}
                  onChange={(event) => setPassword(event.currentTarget.value)}
                />
              </div>
              {session?.additionalAuthPolicy === "disabled" ? null : (
                <div>
                  <label htmlFor="administrative-totp" className="mb-2 block text-sm font-medium text-text">인증 앱 6자리 코드</label>
                  <Input
                    id="administrative-totp"
                    className="font-mono tracking-[0.3em]"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    maxLength={6}
                    required
                    disabled={submitting}
                    value={additionalAuthCode}
                    onChange={(event) => setAdditionalAuthCode(event.currentTarget.value.replace(/\D/g, "").slice(0, 6))}
                  />
                </div>
              )}
              <Button className="w-full" type="submit" disabled={submitting || session?.subject.role !== "admin"}>
                <KeyRound aria-hidden="true" className="size-4" />
                {submitting ? "관리 권한 확인 중" : "재인증 후 관리 모드 열기"}
              </Button>
            </form>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </AdministrativeAccessContext.Provider>
  );
}

export function useAdministrativeAccess(): AdministrativeAccessContextValue {
  const value = useContext(AdministrativeAccessContext);
  if (value === null) throw new Error("AdministrativeAccessProvider is missing");
  return value;
}

export function accessModeLabel(session: SessionView): string {
  if (session.subject.role === "viewer") return "읽기 전용";
  if (session.administrativeAccess === "administrative") return "관리 권한 · 관리 모드";
  if (session.subject.role === "admin") return "관리 권한 · 표준 모드";
  return "작업 권한 · 표준 모드";
}

export function SessionAccessPanel({
  session,
  observedAt,
  showHeading = true,
}: {
  session: SessionView;
  observedAt?: string | undefined;
  showHeading?: boolean;
}) {
  const { requestAccess, leaveAccess, leaving } = useAdministrativeAccess();
  const administrative = session.administrativeAccess === "administrative";
  return (
    <section className="rounded-panel border border-border bg-surface p-4 sm:p-5" aria-labelledby={showHeading ? "current-session-heading" : undefined}>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          {showHeading ? <h2 id="current-session-heading" className="text-sm font-semibold text-text">계정·현재 세션</h2> : null}
          <p className={showHeading ? "mt-1 text-sm text-muted" : "text-sm text-muted"}>{session.subject.username} · Linux UID {String(session.subject.uid)} · 비-root</p>
        </div>
        <StatusMark label={accessModeLabel(session)} tone={administrative ? "warning" : session.subject.role === "viewer" ? "neutral" : "info"} />
      </div>
      <dl className="mt-4 grid gap-px overflow-hidden rounded-control border border-border bg-border sm:grid-cols-2">
        <SessionField label="JW Agent 역할" value={ROLE_LABELS[session.subject.role]} />
        <SessionField label="root 실행 경계" value={administrative ? "root opsd typed 작업 승인 가능" : "root 작업 잠김"} />
        <SessionField label="접속 경로" value={session.ingress === "public" ? "공개 HTTPS" : "Loopback · SSH 복구"} />
        <SessionField label={administrative ? "관리 모드 만료" : "로그인 세션 만료"} value={formatDateTime(administrative && session.administrativeExpiresAt ? session.administrativeExpiresAt : session.idleExpiresAt)} />
        {observedAt === undefined ? null : <SessionField label="서버 관찰 시각" value={formatDateTime(observedAt)} />}
        <SessionField label="임의 root 명령" value="지원 안 함 · root shell/파일 CRUD 차단" />
      </dl>
      {session.subject.role === "admin" ? (
        <div className="mt-4 flex flex-wrap gap-2">
          {administrative ? (
            <Button variant="secondary" disabled={leaving} onClick={() => void leaveAccess()}>
              <LogOut aria-hidden="true" className="size-4" />
              {leaving ? "관리 모드 종료 중" : "관리 모드 종료"}
            </Button>
          ) : (
            <Button onClick={() => requestAccess()}>
              <KeyRound aria-hidden="true" className="size-4" />
              관리 모드 열기
            </Button>
          )}
        </div>
      ) : null}
    </section>
  );
}

function SessionField({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-surface p-3">
      <dt className="text-xs text-muted">{label}</dt>
      <dd className="mt-1 text-sm leading-5 text-text">{value}</dd>
    </div>
  );
}
