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
  Pencil,
  Save,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { type ChangeEvent, useEffect, useRef, useState } from "react";

import {
  ApiError,
  applyFileUpload,
  closeFileSession,
  createFileSession,
  downloadFile,
  listFiles,
  planFileUpload,
  readTextFile,
} from "../../shared/api/client";
import { fileCapabilityQueryOptions } from "../../shared/api/queries";
import type {
  FileEntryView,
  FileListView,
  FileSessionView,
  FileTextView,
  FileUploadPlanView,
} from "../../shared/api/types";
import { AssuranceDetails } from "../../shared/ui/assurance";
import { Button } from "../../shared/ui/button";
import { cn } from "../../shared/ui/cn";
import { Input } from "../../shared/ui/input";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";

type WorkState = "idle" | "connecting" | "loading" | "planning" | "applying" | "ready" | "error";

type WriteDraft =
  | { kind: "file"; path: string; label: string; bytes: Uint8Array<ArrayBuffer>; targetExists: boolean }
  | { kind: "text"; path: string; label: string; text: string; lineEnding: string; targetExists: true };

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
  const [writeDraft, setWriteDraft] = useState<WriteDraft | null>(null);
  const [uploadPlan, setUploadPlan] = useState<FileUploadPlanView | null>(null);
  const [uploadPassword, setUploadPassword] = useState("");
  const [writeRiskConfirmed, setWriteRiskConfirmed] = useState(false);
  const [overwriteConfirmed, setOverwriteConfirmed] = useState(false);

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
      resetWrite();
      setState("ready");
      setMessage("홈 디렉터리를 열었습니다. 조회는 G0이며 파일 쓰기는 별도 G1 계획과 재인증이 필요합니다.");
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
      resetWrite();
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
      resetWrite();
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
    if (error instanceof ApiError && (error.status === 401 || error.code === "files_unavailable")) {
      setSession(null);
      setListing(null);
      setPreview(null);
      resetWrite();
    }
    setState("error");
    setMessage(fileErrorMessage(error));
  }

  async function disconnect(): Promise<void> {
    const active = session;
    setSession(null);
    setListing(null);
    setPreview(null);
    resetWrite();
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

  function resetWrite(): void {
    setWriteDraft(null);
    setUploadPlan(null);
    setUploadPassword("");
    setWriteRiskConfirmed(false);
    setOverwriteConfirmed(false);
  }

  async function chooseUpload(event: ChangeEvent<HTMLInputElement>): Promise<void> {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = "";
    if (file === undefined || listing === null) return;
    if (file.size > capability.limits.maxUploadBytes) {
      setState("error");
      setMessage(`업로드 상한 ${formatFileBytes(capability.limits.maxUploadBytes)}를 넘었습니다.`);
      return;
    }
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const path = joinFilePath(listing.path, file.name);
      const targetExists = listing.entries.some((entry) => entry.path === path);
      setWriteDraft({ kind: "file", path, label: file.name, bytes, targetExists });
      setUploadPlan(null);
      setUploadPassword("");
      setWriteRiskConfirmed(false);
      setOverwriteConfirmed(false);
      setState("ready");
      setMessage(`${file.name}을 메모리에 준비했습니다. 아직 서버에는 쓰지 않았습니다.`);
    } catch {
      setState("error");
      setMessage("선택한 파일을 브라우저 메모리에서 읽지 못했습니다.");
    }
  }

  function beginTextEdit(): void {
    if (preview === null) return;
    setWriteDraft({
      kind: "text",
      path: preview.path,
      label: preview.path.split("/").at(-1) ?? preview.path,
      text: preview.content,
      lineEnding: preview.lineEnding,
      targetExists: true,
    });
    setUploadPlan(null);
    setUploadPassword("");
    setWriteRiskConfirmed(false);
    setOverwriteConfirmed(false);
    setMessage("편집 내용은 브라우저 메모리에만 있습니다. 계획 승인 전에는 서버를 변경하지 않습니다.");
  }

  async function createUploadPlan(): Promise<void> {
    if (
      session === null
      || writeDraft === null
      || uploadPassword.length === 0
      || !writeRiskConfirmed
      || (writeDraft.targetExists && !overwriteConfirmed)
      || state === "planning"
    ) return;
    const bytes = writeDraftBytes(writeDraft);
    if (bytes.byteLength > capability.limits.maxUploadBytes) {
      setState("error");
      setMessage(`업로드 상한 ${formatFileBytes(capability.limits.maxUploadBytes)}를 넘었습니다.`);
      return;
    }
    if (writeDraft.kind === "text" && bytes.byteLength > capability.limits.maxTextBytes) {
      setState("error");
      setMessage(`텍스트 편집 상한 ${formatFileBytes(capability.limits.maxTextBytes)}를 넘었습니다.`);
      return;
    }
    setState("planning");
    setMessage(null);
    try {
      const contentDigest = await sha256Digest(bytes);
      const plan = await planFileUpload({
        sessionToken: session.sessionToken,
        path: writeDraft.path,
        contentBytes: bytes.byteLength,
        contentDigest,
        password: uploadPassword,
        nonReversibleConfirmed: true,
        overwriteConfirmed,
      });
      setUploadPassword("");
      setUploadPlan(plan);
      setState("ready");
      setMessage("G1 업로드 계획을 만들었습니다. 대상·digest·원복 불가 범위를 확인한 뒤 적용하세요.");
    } catch (error) {
      setUploadPassword("");
      handleOperationError(error);
    }
  }

  async function applyUploadPlan(): Promise<void> {
    if (session === null || listing === null || writeDraft === null || uploadPlan === null) return;
    const bytes = writeDraftBytes(writeDraft);
    setState("applying");
    setMessage(null);
    try {
      const result = await applyFileUpload({
        sessionToken: session.sessionToken,
        planToken: uploadPlan.planToken,
        content: bytes,
      });
      const refreshed = await listFiles({ sessionToken: session.sessionToken, path: listing.path });
      setListing(refreshed);
      setPreview(null);
      resetWrite();
      setState("ready");
      setMessage(`${result.path} 저장 후 size와 SHA-256 read-back 검증을 통과했습니다.`);
    } catch (error) {
      setUploadPlan(null);
      handleOperationError(error);
    }
  }

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Manual access / OpenSSH SFTP"
        title="홈 파일"
        description="홈 조회는 G0, 일반 파일 생성·교체는 별도 재인증이 필요한 G1으로 분리합니다."
        action={<StatusMark label="G0 조회 · G1 쓰기" tone="warning" />}
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
            <Limit label="원자 업로드" value={formatFileBytes(capability.limits.maxUploadBytes)} />
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
              <span>이 세션의 기본 조회는 G0이며, 파일 생성·교체는 별도 G1 계획·PAM 재인증 없이는 실행되지 않음을 확인했습니다.</span>
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

          <div className="mt-5 border-l-2 border-warning bg-warning/5 px-4 py-5" aria-labelledby="file-upload-heading">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 id="file-upload-heading" className="text-sm font-semibold text-text">G1 원자 업로드·텍스트 저장</h3>
                <p className="mt-1 text-sm leading-6 text-muted">
                  같은 디렉터리 임시파일에 쓴 뒤 fsync와 원자 교체를 사용하지만, 이전 파일 자동 백업·원복은 제공하지 않습니다.
                </p>
              </div>
              <StatusMark label="G1 · 자동 원복 없음" tone="warning" />
            </div>
            <div className="mt-4"><AssuranceDetails assurance={capability.uploadAssurance} /></div>

            {writeDraft === null ? (
              <div className="mt-5 max-w-xl">
                <label htmlFor="file-upload-input" className="text-sm font-semibold text-text">현재 디렉터리에 파일 선택</label>
                <Input
                  id="file-upload-input"
                  className="mt-2"
                  type="file"
                  disabled={!capability.uploadAssurance.operationAvailable || state === "loading"}
                  onChange={(event) => void chooseUpload(event)}
                />
                <p className="mt-2 text-xs leading-5 text-muted">최대 {formatFileBytes(capability.limits.maxUploadBytes)} · 재귀 전송, 삭제, 이동, chmod는 지원하지 않습니다.</p>
              </div>
            ) : (
              <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(18rem,0.8fr)]">
                <div className="min-w-0">
                  <dl className="grid gap-3 text-sm sm:grid-cols-2">
                    <PlanFact label="대상" value={writeDraft.path} />
                    <PlanFact label="작업" value={writeDraft.targetExists ? "기존 파일 교체" : "새 파일 생성"} />
                    <PlanFact label="크기" value={formatFileBytes(writeDraftBytes(writeDraft).byteLength)} />
                    <PlanFact label="자동 원복" value="지원하지 않음" danger />
                  </dl>
                  {writeDraft.kind === "text" ? (
                    <div className="mt-4">
                      <label htmlFor="file-text-editor" className="text-sm font-semibold text-text">UTF-8 내용 편집</label>
                      <textarea
                        id="file-text-editor"
                        className="mt-2 min-h-64 w-full resize-y rounded-control border border-border bg-surface px-3 py-3 font-mono text-sm leading-6 text-text outline-none focus:border-action focus:ring-2 focus:ring-action/20 disabled:opacity-60"
                        value={writeDraft.text}
                        disabled={uploadPlan !== null || state === "planning" || state === "applying"}
                        onChange={(event) => setWriteDraft({ ...writeDraft, text: event.target.value })}
                      />
                      <p className="mt-2 text-xs text-muted">원문 줄바꿈 {writeDraft.lineEnding.toUpperCase()} 유지 · 편집 상한 {formatFileBytes(capability.limits.maxTextBytes)}</p>
                    </div>
                  ) : null}
                </div>

                {uploadPlan === null ? (
                  <div className="min-w-0 border-t border-warning/40 pt-4 xl:border-l xl:border-t-0 xl:pl-5 xl:pt-0">
                    <label htmlFor="file-upload-password" className="text-sm font-semibold text-text">Linux 비밀번호 재확인</label>
                    <Input
                      id="file-upload-password"
                      className="mt-2"
                      type="password"
                      autoComplete="current-password"
                      value={uploadPassword}
                      onChange={(event) => setUploadPassword(event.target.value)}
                    />
                    <label className="mt-4 flex cursor-pointer items-start gap-3 text-sm leading-6 text-text">
                      <input
                        type="checkbox"
                        className="mt-1 size-4 shrink-0 accent-action"
                        checked={writeRiskConfirmed}
                        onChange={(event) => setWriteRiskConfirmed(event.target.checked)}
                      />
                      <span>이 작업은 자동 원복되지 않으며 실패 시 SSH로 직접 확인해야 할 수 있음을 이해했습니다.</span>
                    </label>
                    {writeDraft.targetExists ? (
                      <label className="mt-3 flex cursor-pointer items-start gap-3 text-sm leading-6 text-text">
                        <input
                          type="checkbox"
                          className="mt-1 size-4 shrink-0 accent-action"
                          checked={overwriteConfirmed}
                          onChange={(event) => setOverwriteConfirmed(event.target.checked)}
                        />
                        <span>기존 파일을 교체합니다. 이전 내용의 자동 백업이 없음을 확인했습니다.</span>
                      </label>
                    ) : null}
                    <div className="mt-4 flex flex-wrap gap-2">
                      <Button
                        disabled={
                          uploadPassword.length === 0
                          || !writeRiskConfirmed
                          || (writeDraft.targetExists && !overwriteConfirmed)
                          || state === "planning"
                        }
                        onClick={() => void createUploadPlan()}
                      >
                        <KeyRound aria-hidden="true" className="size-4" />
                        {state === "planning" ? "계획 검증 중" : "재인증 후 계획 만들기"}
                      </Button>
                      <Button variant="secondary" disabled={state === "planning"} onClick={resetWrite}>준비 취소</Button>
                    </div>
                  </div>
                ) : (
                  <div className="min-w-0 border-t border-warning/40 pt-4 xl:border-l xl:border-t-0 xl:pl-5 xl:pt-0">
                    <p className="text-sm font-semibold text-text">적용 직전 계획</p>
                    <dl className="mt-3 space-y-3 text-sm">
                      <PlanFact label="대상 상태" value={uploadPlan.targetState === "replace" ? "기존 digest 일치 시 교체" : "대상이 계속 없을 때 생성"} />
                      <PlanFact label="현재 digest" value={uploadPlan.beforeDigest?.slice(0, 23) ?? "대상 없음"} />
                      <PlanFact label="새 digest" value={uploadPlan.afterDigest.slice(0, 23)} />
                      <PlanFact label="계획 만료" value={new Date(uploadPlan.expiresAt).toLocaleTimeString("ko-KR")} />
                    </dl>
                    <p className="mt-4 text-xs leading-5 text-danger">적용 후 이전 파일 자동 원복은 불가능합니다. 결과 불명확 시 성공으로 표시하지 않습니다.</p>
                    <div className="mt-4 flex flex-wrap gap-2">
                      <Button disabled={state === "applying"} onClick={() => void applyUploadPlan()}>
                        <Save aria-hidden="true" className="size-4" />
                        {state === "applying" ? "쓰기·검증 중" : "계획대로 원자 업로드"}
                      </Button>
                      <Button variant="secondary" disabled={state === "applying"} onClick={() => void disconnect()}>
                        계획 폐기·세션 종료
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            )}
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
                      <div className="flex items-center gap-2">
                        <StatusMark label="UTF-8" tone="neutral" />
                        <Button size="compact" variant="secondary" disabled={uploadPlan !== null || state === "applying"} onClick={beginTextEdit}>
                          <Pencil aria-hidden="true" className="size-4" />편집 준비
                        </Button>
                      </div>
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

function PlanFact({ label, value, danger = false }: { label: string; value: string; danger?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-medium text-muted">{label}</dt>
      <dd className={cn("mt-1 break-words font-medium", danger ? "text-danger" : "text-text")}>{value}</dd>
    </div>
  );
}

function joinFilePath(directory: string, name: string): string {
  return directory.length === 0 ? name : `${directory}/${name}`;
}

function writeDraftBytes(draft: WriteDraft): Uint8Array<ArrayBuffer> {
  if (draft.kind === "file") return draft.bytes;
  const normalized = draft.lineEnding === "crlf"
    ? draft.text.replace(/\r?\n/g, "\r\n")
    : draft.text.replace(/\r\n/g, "\n");
  return new TextEncoder().encode(normalized);
}

async function sha256Digest(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return `sha256:${Array.from(digest, (value) => value.toString(16).padStart(2, "0")).join("")}`;
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
    upload_path_invalid: "업로드 대상 이름이나 상대 경로가 허용 범위를 벗어났습니다.",
    upload_too_large: "업로드 크기 상한을 넘었습니다.",
    upload_target_too_large: "기존 파일이 충돌 검사용 읽기 상한을 넘어 교체할 수 없습니다.",
    upload_length_invalid: "업로드 길이 정보를 확인할 수 없습니다.",
    upload_length_mismatch: "계획한 크기와 전송 크기가 달라 쓰기를 차단했습니다.",
    upload_digest_mismatch: "계획한 SHA-256과 전송 내용이 달라 쓰기를 차단했습니다.",
    overwrite_confirmation_required: "기존 파일 교체 동의가 필요합니다.",
    target_changed: "계획 뒤 대상 파일이 바뀌었습니다. 새로 읽고 다시 계획해 주세요.",
    target_symlink_denied: "심볼릭 링크 대상은 교체하지 않습니다.",
    target_type_unsupported: "일반 파일이 아닌 대상은 교체하지 않습니다.",
    sftp_write_extension_unavailable: "OpenSSH 원자 업로드 확장을 확인할 수 없어 쓰기를 차단했습니다.",
    temporary_cleanup_failed: "임시파일 정리를 확인하지 못했습니다. SSH로 홈 디렉터리를 점검해 주세요.",
    manual_recovery_required: "원자 교체 결과가 불명확합니다. 성공으로 간주하지 말고 SSH로 대상 파일을 확인해 주세요.",
  };
  return copy[error.code] ?? "SFTP 연결 또는 파일 검증에 실패했습니다. 기존 SSH 서비스는 변경하지 않았습니다.";
}
