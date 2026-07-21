import { useQuery } from "@tanstack/react-query";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { CircleStop, KeyRound, ShieldAlert, SquareTerminal, TriangleAlert } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import {
  ApiError,
  issueTerminalTicket,
  openTerminalSocket,
} from "../../shared/api/client";
import { terminalQueryOptions } from "../../shared/api/queries";
import { Button } from "../../shared/ui/button";
import { AssuranceDetails } from "../../shared/ui/assurance";
import { cn } from "../../shared/ui/cn";
import { Input } from "../../shared/ui/input";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";

type TerminalState = "idle" | "connecting" | "active" | "ended" | "error";

const MIN_ROWS = 12;
const MAX_ROWS = 120;
const MIN_COLS = 40;
const MAX_COLS = 300;
const MAX_INPUT_BYTES = 16 * 1024;

export function TerminalScreen() {
  const capabilityQuery = useQuery(terminalQueryOptions);
  const [password, setPassword] = useState("");
  const [riskConfirmed, setRiskConfirmed] = useState(false);
  const [state, setState] = useState<TerminalState>("idle");
  const [message, setMessage] = useState<string | null>(null);
  const hostRef = useRef<HTMLDivElement | null>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const terminalReadyRef = useRef(false);
  const sendResize = useCallback((): void => {
    const socket = socketRef.current;
    const terminal = terminalRef.current;
    if (socket?.readyState !== WebSocket.OPEN || terminal === null) return;
    socket.send(
      JSON.stringify({
        type: "resize",
        rows: clamp(terminal.rows, MIN_ROWS, MAX_ROWS),
        cols: clamp(terminal.cols, MIN_COLS, MAX_COLS),
      }),
    );
  }, []);

  useEffect(() => {
    return () => {
      socketRef.current?.close(1000, "route_closed");
      terminalRef.current?.dispose();
      socketRef.current = null;
      terminalRef.current = null;
      fitRef.current = null;
      terminalReadyRef.current = false;
    };
  }, []);

  useEffect(() => {
    if (state !== "active" || hostRef.current === null) return;
    const host = hostRef.current;
    const observer = new ResizeObserver(() => {
      fitRef.current?.fit();
      sendResize();
    });
    observer.observe(host);
    return () => observer.disconnect();
  }, [sendResize, state]);

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
  const active = state === "active" || state === "connecting";

  async function connect(): Promise<void> {
    if (!capability.available || !riskConfirmed || password.length === 0 || active) return;
    setState("connecting");
    setMessage(null);
    terminalReadyRef.current = false;
    try {
      const issued = await issueTerminalTicket({
        password,
        rows: 24,
        cols: 80,
        riskConfirmed: true,
      });
      setPassword("");
      const socket = openTerminalSocket(issued.websocketPath, issued.ticket);
      socket.binaryType = "arraybuffer";
      socketRef.current = socket;
      bindSocket(socket);
    } catch (error) {
      setPassword("");
      setState("error");
      setMessage(terminalErrorMessage(error));
    }
  }

  function bindSocket(socket: WebSocket): void {
    socket.addEventListener("open", () => {
      const host = hostRef.current;
      if (host === null) {
        socket.close(1011, "terminal_surface_missing");
        return;
      }
      const terminal = new Terminal({
        convertEol: true,
        cursorBlink: true,
        fontFamily: '"SFMono-Regular", Consolas, "Liberation Mono", monospace',
        fontSize: 13,
        scrollback: 2_000,
        theme: {
          background: "#111820",
          foreground: "#e7edf4",
          cursor: "#78b5f0",
          selectionBackground: "#315779",
        },
      });
      const fit = new FitAddon();
      terminal.loadAddon(fit);
      terminal.open(host);
      fit.fit();
      terminal.focus();
      terminal.onData((data) => {
        if (new TextEncoder().encode(data).byteLength > MAX_INPUT_BYTES) {
          setMessage("한 번에 붙여넣을 수 있는 크기(16 KiB)를 넘었습니다.");
          return;
        }
        if (terminalReadyRef.current && socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ type: "input", data }));
        }
      });
      terminal.onResize(() => sendResize());
      terminalRef.current = terminal;
      fitRef.current = fit;
      setMessage("OpenSSH 인증과 셸 준비를 확인하고 있습니다.");
    });
    socket.addEventListener("message", (event) => {
      if (event.data instanceof ArrayBuffer) {
        terminalRef.current?.write(new Uint8Array(event.data));
        return;
      }
      if (typeof event.data === "string") {
        try {
          const status = JSON.parse(event.data) as { type?: unknown; sessionId?: unknown };
          if (status.type === "ready" && typeof status.sessionId === "string") {
            terminalReadyRef.current = true;
            setState("active");
            setMessage(`세션 ${status.sessionId.slice(0, 8)} · 명령 내용은 저장하지 않습니다.`);
            fitRef.current?.fit();
            sendResize();
          }
        } catch {
          socket.close(1002, "invalid_server_message");
        }
      }
    });
    socket.addEventListener("close", (event) => {
      socketRef.current = null;
      terminalRef.current?.dispose();
      terminalRef.current = null;
      fitRef.current = null;
      terminalReadyRef.current = false;
      setState(event.code === 1000 ? "ended" : "error");
      setMessage(closeMessage(event.reason));
    });
    socket.addEventListener("error", () => {
      setState("error");
      setMessage("터미널 연결이 중단되었습니다. 기존 SSH 서비스는 변경하지 않았습니다.");
    });
  }

  function disconnect(): void {
    socketRef.current?.close(1000, "user_disconnect");
  }

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Manual access / OpenSSH"
        title="비루트 터미널"
        description="자동화가 지원하지 않는 진단만 현재 Linux 계정 권한으로 잠시 수행합니다."
        action={<StatusMark label="G1 · 자동 원복 없음" tone="warning" />}
      />

      <section className="py-7" aria-labelledby="terminal-boundary-heading">
        <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_19rem]">
          <div>
            <div className="flex items-start gap-3">
              <ShieldAlert aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-warning" />
              <div>
                <h2 id="terminal-boundary-heading" className="text-sm font-semibold text-text">
                  세션 경계
                </h2>
                <p className="mt-1 text-sm leading-6 text-muted">
                  {capability.username} 계정으로 loopback OpenSSH에 연결합니다. root 로그인과 sudo
                  비밀번호 자동 입력은 지원하지 않습니다.
                </p>
              </div>
            </div>
            <div className="mt-5">
              <AssuranceDetails assurance={capability.assurance} />
            </div>
          </div>

          <dl className="divide-y divide-border border-y border-border text-sm">
            <Limit label="Idle 종료" value={`${String(Math.round(capability.limits.idleTimeoutSeconds / 60))}분`} />
            <Limit label="최대 세션" value={`${String(Math.round(capability.limits.maxLifetimeSeconds / 60))}분`} />
            <Limit label="동시 연결" value={`${String(capability.limits.maxSessionsPerUser)}개`} />
            <Limit label="명령 기록" value="저장 안 함" />
          </dl>
        </div>
      </section>

      {!capability.available ? (
        <SurfaceState
          kind="unsupported"
          title="터미널을 열 수 없습니다"
          description={capability.reason ?? "OpenSSH와 권한 정책을 확인해 주세요."}
        />
      ) : (
        <section className="border-t border-border py-7" aria-labelledby="terminal-session-heading">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 id="terminal-session-heading" className="text-sm font-semibold text-text">
                제한 시간 세션
              </h2>
              <p className="mt-1 text-sm text-muted">연결이 끊기면 재접속되지 않습니다. 새로 승인해야 합니다.</p>
            </div>
            {active ? (
              <Button variant="secondary" onClick={disconnect}>
                <CircleStop aria-hidden="true" className="size-4" />
                세션 종료
              </Button>
            ) : null}
          </div>

          {!active ? (
            <div className="mt-5 max-w-2xl border-l-2 border-warning bg-warning/5 px-4 py-4">
              <label htmlFor="terminal-password" className="text-sm font-semibold text-text">
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
              <label className="mt-4 flex cursor-pointer items-start gap-3 text-sm leading-6 text-text">
                <input
                  type="checkbox"
                  className="mt-1 size-4 shrink-0 accent-action"
                  checked={riskConfirmed}
                  onChange={(event) => setRiskConfirmed(event.target.checked)}
                />
                <span>
                  터미널 명령은 자동 원복되지 않으며, 잘못된 명령으로 서비스나 데이터가 손상될 수 있음을
                  확인했습니다.
                </span>
              </label>
              <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center">
                <Button
                  disabled={!riskConfirmed || password.length === 0}
                  onClick={() => void connect()}
                >
                  <KeyRound aria-hidden="true" className="size-4" />
                  재인증 후 연결
                </Button>
                <p className="text-xs leading-5 text-muted">
                  비밀번호와 일회용 ticket은 저장하지 않으며 30초 안에 한 번만 사용합니다.
                </p>
              </div>
            </div>
          ) : null}

          <div
            className="terminal-frame mt-5"
            data-state={state}
            aria-label="OpenSSH 터미널 출력"
          >
            <div ref={hostRef} className="terminal-host" />
            {!active ? (
              <div className="terminal-placeholder">
                <SquareTerminal aria-hidden="true" className="size-7" />
                <p>위험 경계를 확인하고 재인증하면 터미널이 열립니다.</p>
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

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, value));
}

function terminalErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.code === "invalid_credentials") return "Linux 비밀번호를 확인해 주세요.";
    if (error.code === "terminal_busy") return "이미 열린 터미널 세션을 먼저 종료해 주세요.";
    if (error.code === "terminal_unavailable") return "OpenSSH 또는 보안 권한이 준비되지 않았습니다.";
  }
  return "터미널 ticket을 발급하지 못했습니다. 잠시 후 다시 시도해 주세요.";
}

function closeMessage(reason: string): string {
  const copy: Record<string, string> = {
    browser_closed: "사용자가 터미널 세션을 종료했습니다.",
    remote_exit: "원격 셸이 종료되었습니다.",
    remote_closed: "OpenSSH 연결이 종료되었습니다.",
    session_revoked: "로그아웃 또는 세션 철회로 터미널이 종료되었습니다.",
    idle_timeout: "5분 동안 입출력이 없어 세션을 종료했습니다.",
    max_lifetime_reached: "최대 사용 시간 30분에 도달해 세션을 종료했습니다.",
    frame_limit_exceeded: "허용된 입력 크기를 넘어 세션을 종료했습니다.",
    input_limit_exceeded: "허용된 붙여넣기 크기를 넘어 세션을 종료했습니다.",
    openssh_authentication_failed: "OpenSSH 비밀번호 인증에 실패했습니다. 계정과 loopback 인증 정책을 확인해 주세요.",
    openssh_authentication_timeout: "OpenSSH 비밀번호 인증 시간이 초과되었습니다.",
  };
  return copy[reason] ?? "터미널 연결이 종료되었습니다. 새 세션은 다시 승인해야 합니다.";
}
