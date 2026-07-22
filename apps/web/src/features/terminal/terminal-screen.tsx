import { useQuery } from "@tanstack/react-query";
import "@xterm/xterm/css/xterm.css";
import { CircleStop, KeyRound, ShieldAlert, SquareTerminal, TriangleAlert } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { terminalQueryOptions } from "../../shared/api/queries";
import { Button } from "../../shared/ui/button";
import { AssuranceDetails } from "../../shared/ui/assurance";
import { cn } from "../../shared/ui/cn";
import { Input } from "../../shared/ui/input";
import { Sheet } from "../../shared/ui/sheet";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";
import { AdditionalAuthCodeField, useAdditionalAuthRequired } from "../../shared/ui/additional-auth-code";
import { useTerminalSession } from "./terminal-session";

export function TerminalScreen() {
  const capabilityQuery = useQuery(terminalQueryOptions);
  const [password, setPassword] = useState("");
  const [riskConfirmed, setRiskConfirmed] = useState(false);
  const [additionalAuthCode, setAdditionalAuthCode] = useState("");
  const [connectOpen, setConnectOpen] = useState(false);
  const hostRef = useRef<HTMLDivElement | null>(null);
  const terminalSession = useTerminalSession();
  const { active, attach, disconnect, message, state } = terminalSession;
  const additionalAuthRequired = useAdditionalAuthRequired();

  useEffect(() => {
    const host = hostRef.current;
    if (host === null || capabilityQuery.data === undefined) return;
    return attach(host);
  }, [attach, capabilityQuery.data]);

  if (capabilityQuery.isPending) {
    return (
      <div>
        <Skeleton className="h-9 w-52" />
        <Skeleton className="mt-8 h-44 w-full" />
        <Skeleton className="mt-4 h-80 w-full" />
      </div>
    );
  }

  if (capabilityQuery.isError) {
    return (
      <SurfaceState
        kind="error"
        title="터미널 상태를 확인하지 못했습니다"
        description="OpenSSH 상태를 추측하지 않습니다. 서버 판정을 다시 요청해 주세요."
        action={{ label: "다시 확인", onClick: () => void capabilityQuery.refetch() }}
      />
    );
  }

  const capability = capabilityQuery.data;
  async function connect(): Promise<void> {
    if (!capability.available || !riskConfirmed || password.length === 0 || active) return;
    const connected = await terminalSession.connect(password, riskConfirmed, additionalAuthCode);
    setPassword("");
    setAdditionalAuthCode("");
    if (connected) setConnectOpen(false);
  }

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Manual access / OpenSSH"
        title="터미널"
        description={`${capability.username} Linux 계정으로 여는 제한 시간 OpenSSH 세션입니다.`}
        action={
          active ? (
            <Button variant="secondary" onClick={disconnect}>
              <CircleStop aria-hidden="true" className="size-4" />세션 종료
            </Button>
          ) : (
            <Button disabled={!capability.available} onClick={() => setConnectOpen(true)}>
              <KeyRound aria-hidden="true" className="size-4" />터미널 연결
            </Button>
          )
        }
      />

      {!capability.available ? (
        <SurfaceState
          kind="unsupported"
          title="터미널을 열 수 없습니다"
          description={capability.reason ?? "OpenSSH와 권한 정책을 확인해 주세요."}
        />
      ) : (
        <section className="py-6" aria-labelledby="terminal-session-heading">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
            <h2 id="terminal-session-heading" className="text-sm font-semibold text-text">터미널 세션</h2>
            <StatusMark
              label={active ? "연결됨 · 비-root" : "연결 안 됨 · G1"}
              tone={active ? "success" : "warning"}
            />
          </div>
          <div
            className="terminal-frame"
            data-state={state}
            aria-label="OpenSSH 터미널 출력"
          >
            <div ref={hostRef} className="terminal-host" />
            {!active ? (
              <div className="terminal-placeholder">
                <SquareTerminal aria-hidden="true" className="size-7" />
                <p>‘터미널 연결’을 누르면 이 영역에 바로 세션이 열립니다.</p>
              </div>
            ) : null}
          </div>

          {message !== null ? (
            <p
              className={cn(
                "mt-4 flex items-start gap-2 text-sm",
                state === "error" ? "text-danger" : "text-muted",
              )}
              role={state === "error" ? "alert" : "status"}
            >
              <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
              {message}
            </p>
          ) : null}
        </section>
      )}

      <details className="border-t border-border py-5">
        <summary className="cursor-pointer text-sm font-semibold text-text">세션 보안과 제한 보기</summary>
        <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_19rem]">
          <div>
            <div className="flex items-start gap-3">
              <ShieldAlert aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-warning" />
              <p className="text-sm leading-6 text-muted">
                root 로그인과 sudo 비밀번호 자동 입력은 지원하지 않습니다. 터미널 명령은 자동 원복되지
                않으므로 typed operation이 없는 진단에만 사용해 주세요.
              </p>
            </div>
            <div className="mt-5"><AssuranceDetails assurance={capability.assurance} /></div>
          </div>
          <dl className="divide-y divide-border border-y border-border text-sm">
            <Limit label="Idle 종료" value={`${String(Math.round(capability.limits.idleTimeoutSeconds / 60))}분`} />
            <Limit label="최대 세션" value={`${String(Math.round(capability.limits.maxLifetimeSeconds / 60))}분`} />
            <Limit label="동시 연결" value={`${String(capability.limits.maxSessionsPerUser)}개`} />
            <Limit label="명령 내용" value="저장 안 함" />
          </dl>
        </div>
      </details>

      <Sheet
        open={connectOpen}
        onOpenChange={setConnectOpen}
        side="right"
        title="터미널 연결"
        description={`${capability.username} 계정의 OpenSSH 세션을 시작합니다.`}
      >
        <StatusMark label="G1 · 자동 원복 없음" tone="warning" />
        <label htmlFor="terminal-password" className="mt-6 block text-sm font-semibold text-text">
          Linux 비밀번호 재확인
        </label>
        <Input
          id="terminal-password"
          className="mt-2"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
        />
        <AdditionalAuthCodeField id="terminal-totp" value={additionalAuthCode} onChange={setAdditionalAuthCode} disabled={state === "connecting"} />
        <label className="mt-5 flex cursor-pointer items-start gap-3 text-sm leading-6 text-text">
          <input
            type="checkbox"
            className="mt-1 size-4 shrink-0 accent-action"
            checked={riskConfirmed}
            onChange={(event) => setRiskConfirmed(event.target.checked)}
          />
          <span>명령은 자동 원복되지 않으며 잘못된 명령으로 서비스나 데이터가 손상될 수 있음을 확인했습니다.</span>
        </label>
        <Button
          className="mt-6 w-full"
          disabled={!riskConfirmed || password.length === 0 || (additionalAuthRequired && additionalAuthCode.length !== 6) || active}
          onClick={() => void connect()}
        >
          <KeyRound aria-hidden="true" className="size-4" />
          {state === "connecting" ? "OpenSSH 연결 중" : "재인증 후 연결"}
        </Button>
        <p className="mt-3 text-xs leading-5 text-muted">
          비밀번호와 1회용 ticket은 저장하지 않으며 ticket은 30초 안에 한 번만 사용됩니다.
        </p>
      </Sheet>
    </div>
  );
}

function Limit({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4 py-3">
      <dt className="text-muted">{label}</dt>
      <dd className="font-semibold text-text">{value}</dd>
    </div>
  );
}
