import { useQuery } from "@tanstack/react-query";
import {
  ChevronRight,
  CircleStop,
  Download,
  File,
  FileCode2,
  Folder,
  FolderOpen,
  KeyRound,
  Link2,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";

import {
  ApiError,
  closeFileSession,
  createFileSession,
  downloadFile,
  listFiles,
  readTextFile,
} from "../../shared/api/client";
import { fileCapabilityQueryOptions } from "../../shared/api/queries";
import type { FileEntryView, FileListView, FileSessionView, FileTextView } from "../../shared/api/types";
import { AssuranceDetails } from "../../shared/ui/assurance";
import { Button } from "../../shared/ui/button";
import { cn } from "../../shared/ui/cn";
import { Input } from "../../shared/ui/input";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";

type WorkState = "idle" | "connecting" | "loading" | "ready" | "error";

export function FilesScreen() {
  const capabilityQuery = useQuery(fileCapabilityQueryOptions);
  const [password, setPassword] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [session, setSession] = useState<FileSessionView | null>(null);
  const sessionRef = useRef<FileSessionView | null>(null);
  const [listing, setListing] = useState<FileListView | null>(null);
  const [preview, setPreview] = useState<FileTextView | null>(null);
  const [state, setState] = useState<WorkState>("idle");
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    sessionRef.current = session;
  }, [session]);

  useEffect(() => {
    return () => {
      const active = sessionRef.current;
      if (active !== null) void closeFileSession(active.sessionToken).catch(() => undefined);
    };
  }, []);

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
        title="파일 접근 상태를 확인하지 못했습니다"
        description="OpenSSH와 홈 경계를 추측하지 않습니다. 서버 판정을 다시 요청해 주세요."
        action={{ label: "다시 확인", onClick: () => void capabilityQuery.refetch() }}
      />
    );
  }

  const capability = capabilityQuery.data;

  async function connect(): Promise<void> {
    if (!capability.available || !confirmed || password.length === 0 || state === "connecting") return;
    setState("connecting");
    setMessage(null);
    try {
      const issued = await createFileSession({ password, readOnlyConfirmed: true });
      setPassword("");
      setSession(issued);
      const root = await listFiles({ sessionToken: issued.sessionToken, path: "" });
      setListing(root);
      setPreview(null);
      setState("ready");
      setMessage("홈 디렉터리를 읽기 전용으로 열었습니다. 파일 변경 기능은 차단되어 있습니다.");
    } catch (error) {
      setPassword("");
      setState("error");
      setMessage(fileErrorMessage(error));
    }
  }

  async function openDirectory(path: string): Promise<void> {
    if (session === null) return;
    setState("loading");
    setMessage(null);
    try {
      const next = await listFiles({ sessionToken: session.sessionToken, path });
      setListing(next);
      setPreview(null);
      setState("ready");
    } catch (error) {
      handleOperationError(error);
    }
  }

  async function openPreview(entry: FileEntryView): Promise<void> {
    if (session === null) return;
    setState("loading");
    setMessage(null);
    try {
      const text = await readTextFile({ sessionToken: session.sessionToken, path: entry.path });
      setPreview(text);
      setState("ready");
    } catch (error) {
      handleOperationError(error);
    }
  }

  async function saveDownload(entry: FileEntryView): Promise<void> {
    if (session === null) return;
    setState("loading");
    setMessage(null);
    try {
      const blob = await downloadFile({ sessionToken: session.sessionToken, path: entry.path });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = safeDownloadName(entry.name);
      anchor.click();
      URL.revokeObjectURL(url);
      setState("ready");
      setMessage(`${entry.name} 다운로드를 시작했습니다.`);
    } catch (error) {
      handleOperationError(error);
    }
  }

  function handleOperationError(error: unknown): void {
    if (error instanceof ApiError && [401, 403, 409].includes(error.status)) {
      setSession(null);
      setListing(null);
      setPreview(null);
    }
    setState("error");
    setMessage(fileErrorMessage(error));
  }

  async function disconnect(): Promise<void> {
    const active = session;
    setSession(null);
    setListing(null);
    setPreview(null);
    setState("idle");
    setMessage(null);
    if (active !== null) {
      try {
        await closeFileSession(active.sessionToken);
      } catch {
        setMessage("브라우저 세션은 비웠지만 서버 종료 확인에 실패했습니다. 최대 2분 안에 자동 만료됩니다.");
      }
    }
  }

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Manual access / OpenSSH SFTP"
        title="홈 파일"
        description="현재 Linux 계정의 홈 디렉터리만 읽기 전용으로 탐색합니다."
        action={<StatusMark label="G0 · 변경 없음" tone="success" />}
      />

      <section className="py-7" aria-labelledby="file-boundary-heading">
        <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_19rem]">
          <div>
            <div className="flex items-start gap-3">
              <ShieldCheck aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-success" />
              <div>
                <h2 id="file-boundary-heading" className="text-sm font-semibold text-text">읽기 경계</h2>
                <p className="mt-1 text-sm leading-6 text-muted">
                  {capability.username} 계정의 {capability.rootLabel} 아래만 허용합니다. 링크가 홈 밖을 가리키면
                  서버가 거부합니다.
                </p>
              </div>
            </div>
            <div className="mt-5"><AssuranceDetails assurance={capability.assurance} /></div>
          </div>
          <dl className="divide-y divide-border border-y border-border text-sm">
            <Limit label="Idle 종료" value={`${String(capability.limits.idleTimeoutSeconds / 60)}분`} />
            <Limit label="최대 세션" value={`${String(capability.limits.maxLifetimeSeconds / 60)}분`} />
            <Limit label="텍스트 미리보기" value={formatFileBytes(capability.limits.maxTextBytes)} />
            <Limit label="다운로드" value={formatFileBytes(capability.limits.maxDownloadBytes)} />
          </dl>
        </div>
      </section>

      {!capability.available ? (
        <SurfaceState
          kind="unsupported"
          title="파일 세션을 열 수 없습니다"
          description={capability.reason ?? "OpenSSH와 계정 권한을 확인해 주세요."}
        />
      ) : session === null ? (
        <section className="border-t border-border py-7" aria-labelledby="file-session-heading">
          <h2 id="file-session-heading" className="text-sm font-semibold text-text">제한 시간 세션</h2>
          <p className="mt-1 text-sm text-muted">비밀번호는 OpenSSH 인증 직후 폐기되며 파일 경로와 내용은 기록하지 않습니다.</p>
          <div className="mt-5 max-w-2xl border-l-2 border-success bg-success/5 px-4 py-4">
            <label htmlFor="file-password" className="text-sm font-semibold text-text">Linux 비밀번호 재확인</label>
            <Input
              id="file-password"
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
                checked={confirmed}
                onChange={(event) => setConfirmed(event.target.checked)}
              />
              <span>홈 디렉터리 읽기만 가능하며 업로드·편집·삭제·이동·권한 변경은 지원하지 않음을 확인했습니다.</span>
            </label>
            <Button className="mt-4" disabled={!confirmed || password.length === 0 || state === "connecting"} onClick={() => void connect()}>
              <KeyRound aria-hidden="true" className="size-4" />
              {state === "connecting" ? "OpenSSH 확인 중" : "재인증 후 열기"}
            </Button>
          </div>
        </section>
      ) : (
        <section className="border-t border-border py-7" aria-labelledby="file-browser-heading">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 id="file-browser-heading" className="text-sm font-semibold text-text">파일 탐색</h2>
              <p className="mt-1 text-sm text-muted">세션 토큰은 이 화면의 메모리에만 유지됩니다.</p>
            </div>
            <Button variant="secondary" onClick={() => void disconnect()}>
              <CircleStop aria-hidden="true" className="size-4" />세션 종료
            </Button>
          </div>

          {listing !== null ? (
            <div className="mt-5 grid min-w-0 gap-5 xl:grid-cols-[minmax(18rem,0.85fr)_minmax(0,1.15fr)]">
              <div className="min-w-0 overflow-hidden rounded-panel border border-border bg-surface">
                <Breadcrumb path={listing.path} onOpen={(path) => void openDirectory(path)} />
                <div className="divide-y divide-border" role="list" aria-label="홈 파일 목록">
                  {listing.entries.length === 0 ? (
                    <p className="px-4 py-8 text-center text-sm text-muted">이 디렉터리는 비어 있습니다.</p>
                  ) : listing.entries.map((entry) => (
                    <FileRow
                      key={entry.path}
                      entry={entry}
                      disabled={state === "loading"}
                      onDirectory={openDirectory}
                      onPreview={openPreview}
                      onDownload={saveDownload}
                    />
                  ))}
                </div>
                {listing.truncated ? <p className="border-t border-warning bg-warning/5 px-4 py-3 text-xs text-warning">500개까지만 표시했습니다.</p> : null}
              </div>

              <div className="min-w-0 rounded-panel border border-border bg-surface">
                {preview === null ? (
                  <div className="grid min-h-72 place-content-center justify-items-center gap-3 p-8 text-center text-sm text-muted">
                    <FileCode2 aria-hidden="true" className="size-7" />
                    <p>일반 파일의 ‘텍스트 보기’를 선택해 내용을 확인하세요.</p>
                  </div>
                ) : (
                  <div>
                    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-semibold text-text">{preview.path}</p>
                        <p className="mt-0.5 text-xs text-muted">{formatFileBytes(preview.sizeBytes)} · {preview.lineEnding.toUpperCase()} · {preview.digest.slice(0, 19)}…</p>
                      </div>
                      <StatusMark label="읽기 전용" tone="neutral" />
                    </div>
                    <pre className="max-h-[34rem] overflow-auto whitespace-pre-wrap break-words p-4 font-mono text-xs leading-6 text-text">{preview.content}</pre>
                  </div>
                )}
              </div>
            </div>
          ) : null}
        </section>
      )}

      {message !== null ? (
        <p className={cn("mt-4 flex items-start gap-2 text-sm", state === "error" ? "text-danger" : "text-muted")} role={state === "error" ? "alert" : "status"}>
          <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />{message}
        </p>
      ) : null}
    </div>
  );
}

function Breadcrumb({ path, onOpen }: { path: string; onOpen: (path: string) => void }) {
  const parts = path === "" ? [] : path.split("/");
  return (
    <nav className="flex min-h-12 items-center gap-1 overflow-x-auto border-b border-border px-3" aria-label="파일 경로">
      <button type="button" className="shrink-0 rounded-control px-2 py-1 text-sm font-semibold text-action hover:bg-subtle" onClick={() => onOpen("")}>~</button>
      {parts.map((part, index) => {
        const target = parts.slice(0, index + 1).join("/");
        return <span key={target} className="flex shrink-0 items-center gap-1"><ChevronRight aria-hidden="true" className="size-4 text-muted" /><button type="button" className="rounded-control px-2 py-1 text-sm text-text hover:bg-subtle" onClick={() => onOpen(target)}>{part}</button></span>;
      })}
    </nav>
  );
}

function FileRow({ entry, disabled, onDirectory, onPreview, onDownload }: {
  entry: FileEntryView;
  disabled: boolean;
  onDirectory: (path: string) => Promise<void>;
  onPreview: (entry: FileEntryView) => Promise<void>;
  onDownload: (entry: FileEntryView) => Promise<void>;
}) {
  const Icon = entry.kind === "directory" ? Folder : entry.kind === "symbolic_link" ? Link2 : File;
  return (
    <div className="flex min-w-0 items-center gap-3 px-4 py-3" role="listitem">
      <Icon aria-hidden="true" className={cn("size-5 shrink-0", entry.kind === "directory" ? "text-action" : "text-muted")} />
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium text-text">{entry.name}</p>
        <p className="mt-0.5 text-xs text-muted">{kindLabel(entry)}{entry.sizeBytes === null || entry.sizeBytes === undefined ? "" : ` · ${formatFileBytes(entry.sizeBytes)}`}</p>
      </div>
      {entry.kind === "directory" ? (
        <Button size="compact" variant="ghost" disabled={disabled} onClick={() => void onDirectory(entry.path)}><FolderOpen aria-hidden="true" className="size-4" />열기</Button>
      ) : entry.kind === "regular" ? (
        <div className="flex shrink-0 gap-1">
          <Button size="compact" variant="ghost" disabled={disabled} aria-label={`${entry.name} 텍스트 보기`} onClick={() => void onPreview(entry)}><FileCode2 aria-hidden="true" className="size-4" /><span className="hidden sm:inline">텍스트 보기</span></Button>
          <Button size="icon" variant="ghost" disabled={disabled} aria-label={`${entry.name} 다운로드`} onClick={() => void onDownload(entry)}><Download aria-hidden="true" className="size-4" /></Button>
        </div>
      ) : <StatusMark label={entry.kind === "symbolic_link" ? "링크" : "기타"} tone="neutral" />}
    </div>
  );
}

function Limit({ label, value }: { label: string; value: string }) {
  return <div className="flex items-center justify-between gap-4 py-3"><dt className="text-muted">{label}</dt><dd className="font-semibold text-text">{value}</dd></div>;
}

function kindLabel(entry: FileEntryView): string {
  if (entry.kind === "directory") return "디렉터리";
  if (entry.kind === "regular") return "일반 파일";
  if (entry.kind === "symbolic_link") return "심볼릭 링크 · 직접 열기 차단";
  return "지원하지 않는 파일 형식";
}

function safeDownloadName(name: string): string {
  const safe = Array.from(name, (character) => {
    const code = character.codePointAt(0) ?? 0;
    return character === "/" || character === "\\" || code < 32 || code === 127 ? "_" : character;
  }).join("");
  return safe.length === 0 ? "jw-agent-download" : safe;
}

function formatFileBytes(value: number): string {
  if (value < 1_024) return `${String(value)} B`;
  if (value < 1_024 * 1_024) return `${(value / 1_024).toFixed(value < 10 * 1_024 ? 1 : 0)} KiB`;
  return `${(value / (1_024 * 1_024)).toFixed(value < 10 * 1_024 * 1_024 ? 1 : 0)} MiB`;
}

function fileErrorMessage(error: unknown): string {
  if (!(error instanceof ApiError)) return "파일 요청을 완료하지 못했습니다. 잠시 후 다시 시도해 주세요.";
  const copy: Record<string, string> = {
    invalid_credentials: "Linux 비밀번호를 확인해 주세요.",
    file_session_busy: "이미 열린 파일 세션을 먼저 종료해 주세요.",
    file_session_expired: "파일 세션이 만료되었습니다. 다시 인증해 주세요.",
    file_session_rejected: "파일 세션이 철회되었거나 현재 로그인과 일치하지 않습니다.",
    files_unavailable: "OpenSSH 또는 보안 권한이 준비되지 않았습니다.",
    path_invalid: "상대 경로 형식이 안전하지 않아 거부했습니다.",
    path_outside_home: "홈 디렉터리 밖으로 이어지는 경로를 차단했습니다.",
    permission_denied: "Linux 계정에 이 파일을 읽을 권한이 없습니다.",
    not_found: "파일이나 디렉터리를 찾지 못했습니다.",
    not_directory: "디렉터리가 아닙니다.",
    not_regular_file: "일반 파일만 읽거나 내려받을 수 있습니다.",
    text_too_large: "텍스트 미리보기 제한을 넘었습니다. 제한 안의 파일만 다운로드할 수 있습니다.",
    download_too_large: "다운로드 제한을 넘었습니다.",
    binary_text: "바이너리 파일은 텍스트로 표시하지 않습니다. 다운로드를 사용해 주세요.",
    file_audit_unavailable: "감사 기록을 보장할 수 없어 파일 요청을 차단했습니다.",
  };
  return copy[error.code] ?? "SFTP 연결 또는 파일 검증에 실패했습니다. 기존 SSH 서비스는 변경하지 않았습니다.";
}
