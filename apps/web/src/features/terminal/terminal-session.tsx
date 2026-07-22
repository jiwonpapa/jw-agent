import type { FitAddon } from "@xterm/addon-fit";
import type { Terminal } from "@xterm/xterm";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

import { ApiError, issueTerminalTicket, openTerminalSocket } from "../../shared/api/client";

export type TerminalSessionState = "idle" | "connecting" | "active" | "ended" | "error";

interface TerminalSessionController {
  state: TerminalSessionState;
  message: string | null;
  active: boolean;
  connect: (password: string, riskConfirmed: boolean) => Promise<boolean>;
  disconnect: () => void;
  attach: (host: HTMLDivElement) => () => void;
}

const MIN_ROWS = 12;
const MAX_ROWS = 120;
const MIN_COLS = 40;
const MAX_COLS = 300;
const MAX_INPUT_BYTES = 16 * 1024;
const MAX_DETACHED_OUTPUT_BYTES = 512 * 1024;

const TerminalSessionContext = createContext<TerminalSessionController | null>(null);

export function TerminalSessionProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<TerminalSessionState>("idle");
  const [message, setMessage] = useState<string | null>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const hostRef = useRef<HTMLDivElement | null>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const terminalReadyRef = useRef(false);
  const creatingTerminalRef = useRef<Promise<void> | null>(null);
  const detachedOutputRef = useRef<Uint8Array[]>([]);
  const detachedOutputBytesRef = useRef(0);

  const sendResize = useCallback((): void => {
    const socket = socketRef.current;
    const terminal = terminalRef.current;
    if (socket?.readyState !== WebSocket.OPEN || terminal === null) return;
    socket.send(JSON.stringify({
      type: "resize",
      rows: clamp(terminal.rows, MIN_ROWS, MAX_ROWS),
      cols: clamp(terminal.cols, MIN_COLS, MAX_COLS),
    }));
  }, []);

  const ensureTerminal = useCallback(async (): Promise<void> => {
    const host = hostRef.current;
    if (host === null) return;
    const existing = terminalRef.current;
    if (existing !== null) {
      const element = existing.element;
      if (element !== undefined && element.parentElement !== host) {
        host.replaceChildren(element);
      }
      fitRef.current?.fit();
      sendResize();
      existing.focus();
      return;
    }
    if (creatingTerminalRef.current !== null) {
      await creatingTerminalRef.current;
      return;
    }
    const create = (async () => {
      const [{ Terminal: XtermTerminal }, { FitAddon: XtermFitAddon }] = await Promise.all([
        import("@xterm/xterm"),
        import("@xterm/addon-fit"),
      ]);
      const currentHost = hostRef.current;
      if (currentHost === null || terminalRef.current !== null) return;
      const terminal = new XtermTerminal({
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
      const fit = new XtermFitAddon();
      terminal.loadAddon(fit);
      terminal.open(currentHost);
      terminal.onData((data) => {
        if (new TextEncoder().encode(data).byteLength > MAX_INPUT_BYTES) {
          setMessage("한 번에 붙여넣을 수 있는 크기(16 KiB)를 넘었습니다.");
          return;
        }
        const socket = socketRef.current;
        if (terminalReadyRef.current && socket?.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ type: "input", data }));
        }
      });
      terminal.onResize(sendResize);
      terminalRef.current = terminal;
      fitRef.current = fit;
      const pending = detachedOutputRef.current;
      detachedOutputRef.current = [];
      detachedOutputBytesRef.current = 0;
      for (const chunk of pending) terminal.write(chunk);
      fit.fit();
      sendResize();
      terminal.focus();
    })();
    creatingTerminalRef.current = create;
    try {
      await create;
    } finally {
      creatingTerminalRef.current = null;
    }
  }, [sendResize]);

  const resetTerminal = useCallback((): void => {
    terminalRef.current?.dispose();
    terminalRef.current = null;
    fitRef.current = null;
    terminalReadyRef.current = false;
    detachedOutputRef.current = [];
    detachedOutputBytesRef.current = 0;
  }, []);

  const bindSocket = useCallback((socket: WebSocket): void => {
    socket.addEventListener("open", () => {
      setMessage("OpenSSH 인증과 셸 준비를 확인하고 있습니다.");
      void ensureTerminal();
    });
    socket.addEventListener("message", (event) => {
      if (event.data instanceof ArrayBuffer) {
        const chunk = new Uint8Array(event.data);
        const terminal = terminalRef.current;
        if (terminal !== null) {
          terminal.write(chunk);
        } else if (chunk.byteLength <= MAX_DETACHED_OUTPUT_BYTES) {
          detachedOutputRef.current.push(chunk);
          detachedOutputBytesRef.current += chunk.byteLength;
          while (detachedOutputBytesRef.current > MAX_DETACHED_OUTPUT_BYTES) {
            const removed = detachedOutputRef.current.shift();
            if (removed === undefined) break;
            detachedOutputBytesRef.current -= removed.byteLength;
          }
        }
        return;
      }
      if (typeof event.data !== "string") return;
      try {
        const status = JSON.parse(event.data) as { type?: unknown; sessionId?: unknown };
        if (status.type === "ready" && typeof status.sessionId === "string") {
          terminalReadyRef.current = true;
          setState("active");
          setMessage(`세션 ${status.sessionId.slice(0, 8)} · 메뉴를 이동해도 연결을 유지합니다.`);
          void ensureTerminal();
        }
      } catch {
        socket.close(1002, "invalid_server_message");
      }
    });
    socket.addEventListener("close", (event) => {
      if (socketRef.current === socket) socketRef.current = null;
      resetTerminal();
      setState(event.code === 1000 ? "ended" : "error");
      setMessage(closeMessage(event.reason));
    });
    socket.addEventListener("error", () => {
      setState("error");
      setMessage("터미널 연결이 중단되었습니다. 기존 SSH 서비스는 변경하지 않았습니다.");
    });
  }, [ensureTerminal, resetTerminal]);

  const connect = useCallback(async (password: string, riskConfirmed: boolean): Promise<boolean> => {
    if (!riskConfirmed || password.length === 0 || socketRef.current !== null) return false;
    setState("connecting");
    setMessage(null);
    terminalReadyRef.current = false;
    try {
      const issued = await issueTerminalTicket({ password, rows: 24, cols: 80, riskConfirmed: true });
      const socket = openTerminalSocket(issued.websocketPath, issued.ticket);
      socket.binaryType = "arraybuffer";
      socketRef.current = socket;
      bindSocket(socket);
      return true;
    } catch (error) {
      setState("error");
      setMessage(terminalErrorMessage(error));
      return false;
    }
  }, [bindSocket]);

  const disconnect = useCallback((): void => {
    socketRef.current?.close(1000, "user_disconnect");
  }, []);

  const attach = useCallback((host: HTMLDivElement): (() => void) => {
    hostRef.current = host;
    void ensureTerminal();
    const observer = new ResizeObserver(() => {
      fitRef.current?.fit();
      sendResize();
    });
    observer.observe(host);
    return () => {
      observer.disconnect();
      if (hostRef.current === host) hostRef.current = null;
    };
  }, [ensureTerminal, sendResize]);

  useEffect(() => {
    return () => {
      socketRef.current?.close(1000, "session_revoked");
      resetTerminal();
    };
  }, [resetTerminal]);

  const value = useMemo<TerminalSessionController>(() => ({
    state,
    message,
    active: state === "active" || state === "connecting",
    connect,
    disconnect,
    attach,
  }), [attach, connect, disconnect, message, state]);

  return <TerminalSessionContext.Provider value={value}>{children}</TerminalSessionContext.Provider>;
}

export function useTerminalSession(): TerminalSessionController {
  const controller = useContext(TerminalSessionContext);
  if (controller === null) throw new Error("TerminalSessionProvider is required");
  return controller;
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
    user_disconnect: "사용자가 터미널 세션을 종료했습니다.",
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
