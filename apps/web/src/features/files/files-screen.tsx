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
  Upload,
} from "lucide-react";
import { type ChangeEvent, useState } from "react";

import {
  ApiError,
  applyFileUpload,
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
  FileTextView,
  FileUploadPlanView,
} from "../../shared/api/types";
import { AssuranceDetails } from "../../shared/ui/assurance";
import { Button } from "../../shared/ui/button";
import { CodeEditor } from "../../shared/ui/code-editor";
import { cn } from "../../shared/ui/cn";
import { Input } from "../../shared/ui/input";
import { Skeleton } from "../../shared/ui/skeleton";
import { Sheet } from "../../shared/ui/sheet";
import { StatusMark } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";
import { useFileSession } from "./file-session";

type WorkState = "idle" | "connecting" | "loading" | "planning" | "applying" | "ready" | "error";

type WriteDraft =
  | { kind: "file"; path: string; label: string; bytes: Uint8Array<ArrayBuffer>; targetExists: boolean }
  | { kind: "text"; path: string; label: string; text: string; lineEnding: string; targetExists: true };

export function FilesScreen() {
  const capabilityQuery = useQuery(fileCapabilityQueryOptions);
  const fileSession = useFileSession();
  const { adopt, discard, listing, rememberListing, session } = fileSession;
  const [password, setPassword] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [preview, setPreview] = useState<FileTextView | null>(null);
  const [state, setState] = useState<WorkState>(session !== null && listing !== null ? "ready" : "idle");
  const [message, setMessage] = useState<string | null>(null);
  const [writeDraft, setWriteDraft] = useState<WriteDraft | null>(null);
  const [uploadPlan, setUploadPlan] = useState<FileUploadPlanView | null>(null);
  const [uploadPassword, setUploadPassword] = useState("");
  const [writeRiskConfirmed, setWriteRiskConfirmed] = useState(false);
  const [overwriteConfirmed, setOverwriteConfirmed] = useState(false);
  const [connectOpen, setConnectOpen] = useState(false);
  const [writeOpen, setWriteOpen] = useState(false);

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
      setConnectOpen(false);
      adopt(issued);
      const root = await listFiles({ sessionToken: issued.sessionToken, path: "" });
      rememberListing(root);
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
      rememberListing(next);
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
      discard();
      setPreview(null);
      resetWrite();
    }
    setState("error");
    setMessage(fileErrorMessage(error));
  }

  async function disconnect(): Promise<void> {
    setPreview(null);
    resetWrite();
    setState("idle");
    setMessage(null);
    if (!(await fileSession.disconnect())) {
      setMessage("브라우저 세션은 비웠지만 서버 종료 확인에 실패했습니다. 최대 2분 안에 자동 만료됩니다.");
    }
  }

  function resetWrite(): void {
    setWriteDraft(null);
    setUploadPlan(null);
    setUploadPassword("");
    setWriteRiskConfirmed(false);
    setOverwriteConfirmed(false);
    setWriteOpen(false);
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
      setWriteOpen(true);
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
    setWriteOpen(true);
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
      rememberListing(refreshed);
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
        title="SFTP"
        description={`${capability.username} 계정의 홈 디렉터리를 탐색하고 파일을 전송합니다.`}
        action={
          session === null ? (
            <Button disabled={!capability.available} onClick={() => setConnectOpen(true)}>
              <KeyRound aria-hidden="true" className="size-4" />홈에 연결
            </Button>
          ) : (
            <div className="flex flex-wrap gap-2">
              <label className={cn(
                "inline-flex min-h-10 cursor-pointer items-center justify-center gap-2 rounded-control bg-action px-3 text-sm font-semibold text-white",
                !capability.uploadAssurance.operationAvailable && "pointer-events-none opacity-50",
              )}>
                <Upload aria-hidden="true" className="size-4" />업로드
                <input
                  className="sr-only"
                  type="file"
                  disabled={!capability.uploadAssurance.operationAvailable || state === "loading"}
                  onChange={(event) => void chooseUpload(event)}
                />
              </label>
              <Button variant="secondary" onClick={() => void disconnect()}>
                <CircleStop aria-hidden="true" className="size-4" />세션 종료
              </Button>
            </div>
          )
        }
      />

      {!capability.available ? (
        <SurfaceState
          kind="unsupported"
          title="파일 세션을 열 수 없습니다"
          description={capability.reason ?? "OpenSSH와 계정 권한을 확인해 주세요."}
        />
      ) : session === null || listing === null ? (
        <section className="grid min-h-[32rem] place-content-center justify-items-center gap-4 py-8 text-center">
          <div className="grid size-16 place-content-center rounded-full bg-action/10 text-action">
            <FolderOpen aria-hidden="true" className="size-8" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-text">홈 디렉터리에 연결하세요</h2>
            <p className="mt-2 max-w-md text-sm leading-6 text-muted">연결 후 폴더 트리, 파일 목록, 텍스트 미리보기를 한 화면에서 사용할 수 있습니다.</p>
          </div>
          <Button onClick={() => setConnectOpen(true)}>
            <KeyRound aria-hidden="true" className="size-4" />SFTP 연결
          </Button>
        </section>
      ) : (
        <section className="py-5" aria-labelledby="file-browser-heading">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 id="file-browser-heading" className="text-sm font-semibold text-text">{capability.rootLabel}</h2>
              <p className="mt-1 text-xs text-muted">홈 경계 · G0 조회</p>
            </div>
            <StatusMark label={state === "loading" ? "불러오는 중" : "SFTP 연결됨"} tone={state === "error" ? "danger" : "success"} />
          </div>

          <div className="grid min-h-[35rem] min-w-0 overflow-hidden rounded-panel border border-border bg-surface lg:grid-cols-[13rem_minmax(20rem,0.9fr)_minmax(0,1.1fr)]">
            <DirectoryTree listing={listing} disabled={state === "loading"} onOpen={openDirectory} />
            <div className="min-w-0 border-border lg:border-l">
              <Breadcrumb path={listing.path} onOpen={(path) => void openDirectory(path)} />
              <div className="divide-y divide-border" role="list" aria-label="SFTP 파일 목록">
                {listing.entries.length === 0 ? (
                  <p className="px-4 py-12 text-center text-sm text-muted">이 디렉터리는 비어 있습니다.</p>
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

            <div className="min-w-0 border-t border-border lg:border-l lg:border-t-0">
              {preview === null ? (
                <div className="grid min-h-72 place-content-center justify-items-center gap-3 p-8 text-center text-sm text-muted">
                  <FileCode2 aria-hidden="true" className="size-7" />
                  <p>파일을 선택하면 이곳에서 UTF-8 내용을 미리 봅니다.</p>
                </div>
              ) : (
                <div>
                  <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-semibold text-text">{preview.path}</p>
                      <p className="mt-0.5 text-xs text-muted">{formatFileBytes(preview.sizeBytes)} · {preview.lineEnding.toUpperCase()} · {preview.digest.slice(0, 19)}…</p>
                    </div>
                    <Button size="compact" variant="secondary" disabled={state === "applying"} onClick={beginTextEdit}>
                      <Pencil aria-hidden="true" className="size-4" />편집
                    </Button>
                  </div>
                  <pre className="max-h-[38rem] overflow-auto whitespace-pre-wrap break-words p-4 font-mono text-xs leading-6 text-text">{preview.content}</pre>
                </div>
              )}
            </div>
          </div>
        </section>
      )}

      {message !== null ? (
        <p className={cn("mt-4 flex items-start gap-2 text-sm", state === "error" ? "text-danger" : "text-muted")} role={state === "error" ? "alert" : "status"}>
          <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />{message}
        </p>
      ) : null}

      <details className="mt-5 border-t border-border py-5">
        <summary className="cursor-pointer text-sm font-semibold text-text">SFTP 보안 경계와 제한 보기</summary>
        <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_19rem]">
          <div>
            <div className="flex items-start gap-3">
              <ShieldCheck aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-success" />
              <p className="text-sm leading-6 text-muted">
                {capability.rootLabel} 아래만 허용하며 홈 밖을 가리키는 링크는 서버가 거부합니다. 삭제·이동·권한 변경·재귀 전송은 지원하지 않습니다.
              </p>
            </div>
            <div className="mt-5"><AssuranceDetails assurance={capability.assurance} /></div>
          </div>
          <dl className="divide-y divide-border border-y border-border text-sm">
            <Limit label="Idle 종료" value={`${String(capability.limits.idleTimeoutSeconds / 60)}분`} />
            <Limit label="최대 세션" value={`${String(capability.limits.maxLifetimeSeconds / 60)}분`} />
            <Limit label="텍스트" value={formatFileBytes(capability.limits.maxTextBytes)} />
            <Limit label="다운로드" value={formatFileBytes(capability.limits.maxDownloadBytes)} />
            <Limit label="업로드" value={formatFileBytes(capability.limits.maxUploadBytes)} />
          </dl>
        </div>
      </details>

      <Sheet
        open={connectOpen}
        onOpenChange={setConnectOpen}
        side="right"
        title="SFTP 연결"
        description={`${capability.username} 계정의 홈 디렉터리를 엽니다.`}
      >
        <StatusMark label="G0 조회 · 쓰기는 별도 G1" tone="success" />
        <label htmlFor="file-password" className="mt-6 block text-sm font-semibold text-text">Linux 비밀번호 재확인</label>
        <Input
          id="file-password"
          className="mt-2"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
        />
        <label className="mt-5 flex cursor-pointer items-start gap-3 text-sm leading-6 text-text">
          <input
            type="checkbox"
            className="mt-1 size-4 shrink-0 accent-action"
            checked={confirmed}
            onChange={(event) => setConfirmed(event.target.checked)}
          />
          <span>홈 조회만 열리며 쓰기는 별도 계획과 재인증 없이는 실행되지 않음을 확인했습니다.</span>
        </label>
        <Button className="mt-6 w-full" disabled={!confirmed || password.length === 0 || state === "connecting"} onClick={() => void connect()}>
          <KeyRound aria-hidden="true" className="size-4" />
          {state === "connecting" ? "OpenSSH 확인 중" : "재인증 후 홈 열기"}
        </Button>
        <p className="mt-3 text-xs leading-5 text-muted">비밀번호는 OpenSSH 인증 직후 폐기하며 파일 내용은 감사 로그에 저장하지 않습니다.</p>
      </Sheet>

      <Sheet
        open={writeOpen}
        onOpenChange={(open) => open ? setWriteOpen(true) : resetWrite()}
        side="right"
        size="wide"
        title={writeDraft?.kind === "text" ? "텍스트 편집" : "파일 업로드"}
        description="적용 전 대상과 원복 불가 범위를 확인합니다."
      >
        {writeDraft === null ? null : (
          <div>
            <div className="flex items-center justify-between gap-3">
              <StatusMark label="G1 · 자동 원복 없음" tone="warning" />
              <span className="text-xs text-muted">최대 {formatFileBytes(capability.limits.maxUploadBytes)}</span>
            </div>
            <dl className="mt-6 grid gap-4 text-sm sm:grid-cols-2">
              <PlanFact label="대상" value={writeDraft.path} />
              <PlanFact label="작업" value={writeDraft.targetExists ? "기존 파일 교체" : "새 파일 생성"} />
              <PlanFact label="크기" value={formatFileBytes(writeDraftBytes(writeDraft).byteLength)} />
              <PlanFact label="자동 원복" value="지원하지 않음" danger />
            </dl>
            {writeDraft.kind === "text" ? (
              <div className="mt-5">
                <p className="text-sm font-semibold text-text">UTF-8 내용</p>
                <CodeEditor
                  ariaLabel="SFTP UTF-8 내용"
                  className="mt-2"
                  value={writeDraft.text}
                  readOnly={uploadPlan !== null || state === "planning" || state === "applying"}
                  onChange={(text) => setWriteDraft({ ...writeDraft, text })}
                />
              </div>
            ) : null}
            <div className="mt-5"><AssuranceDetails assurance={capability.uploadAssurance} /></div>
            {uploadPlan === null ? (
              <div className="mt-6 border-t border-border pt-5">
                <label htmlFor="file-upload-password" className="text-sm font-semibold text-text">Linux 비밀번호 재확인</label>
                <Input id="file-upload-password" className="mt-2" type="password" autoComplete="current-password" value={uploadPassword} onChange={(event) => setUploadPassword(event.target.value)} />
                <label className="mt-4 flex cursor-pointer items-start gap-3 text-sm leading-6 text-text">
                  <input type="checkbox" className="mt-1 size-4 shrink-0 accent-action" checked={writeRiskConfirmed} onChange={(event) => setWriteRiskConfirmed(event.target.checked)} />
                  <span>이 쓰기는 자동 원복되지 않으며 실패 시 SSH로 직접 확인해야 할 수 있음을 이해했습니다.</span>
                </label>
                {writeDraft.targetExists ? (
                  <label className="mt-3 flex cursor-pointer items-start gap-3 text-sm leading-6 text-text">
                    <input type="checkbox" className="mt-1 size-4 shrink-0 accent-action" checked={overwriteConfirmed} onChange={(event) => setOverwriteConfirmed(event.target.checked)} />
                    <span>기존 파일을 교체하며 이전 내용의 자동 백업이 없음을 확인했습니다.</span>
                  </label>
                ) : null}
                <Button className="mt-5" disabled={uploadPassword.length === 0 || !writeRiskConfirmed || (writeDraft.targetExists && !overwriteConfirmed) || state === "planning"} onClick={() => void createUploadPlan()}>
                  <KeyRound aria-hidden="true" className="size-4" />{state === "planning" ? "계획 검증 중" : "재인증 후 계획 만들기"}
                </Button>
              </div>
            ) : (
              <div className="mt-6 border-t border-warning/40 pt-5">
                <p className="text-sm font-semibold text-text">적용 직전 계획</p>
                <dl className="mt-4 grid gap-4 text-sm sm:grid-cols-2">
                  <PlanFact label="대상 상태" value={uploadPlan.targetState === "replace" ? "기존 digest 일치 시 교체" : "대상이 계속 없을 때 생성"} />
                  <PlanFact label="현재 digest" value={uploadPlan.beforeDigest?.slice(0, 23) ?? "대상 없음"} />
                  <PlanFact label="새 digest" value={uploadPlan.afterDigest.slice(0, 23)} />
                  <PlanFact label="계획 만료" value={new Date(uploadPlan.expiresAt).toLocaleTimeString("ko-KR")} />
                </dl>
                <p className="mt-4 text-xs leading-5 text-danger">이전 파일 자동 원복은 불가능합니다. 결과가 불명확하면 성공으로 표시하지 않습니다.</p>
                <Button className="mt-5" disabled={state === "applying"} onClick={() => void applyUploadPlan()}>
                  <Save aria-hidden="true" className="size-4" />{state === "applying" ? "쓰기·검증 중" : "계획대로 원자 업로드"}
                </Button>
              </div>
            )}
          </div>
        )}
      </Sheet>
    </div>
  );
}

function DirectoryTree({ listing, disabled, onOpen }: {
  listing: FileListView;
  disabled: boolean;
  onOpen: (path: string) => Promise<void>;
}) {
  const parts = listing.path === "" ? [] : listing.path.split("/");
  const children = listing.entries.filter((entry) => entry.kind === "directory");
  return (
    <aside className="hidden min-w-0 bg-subtle/40 p-3 lg:block" aria-label="디렉터리 트리">
      <p className="px-2 pb-2 text-xs font-semibold uppercase tracking-[0.12em] text-muted">Folders</p>
      <button
        type="button"
        className="flex w-full items-center gap-2 rounded-control px-2 py-2 text-left text-sm font-semibold text-text hover:bg-surface"
        disabled={disabled}
        onClick={() => void onOpen("")}
      >
        <FolderOpen aria-hidden="true" className="size-4 text-action" />~
      </button>
      {parts.map((part, index) => {
        const target = parts.slice(0, index + 1).join("/");
        return (
          <button
            key={target}
            type="button"
            className="flex w-full items-center gap-2 rounded-control py-2 pr-2 text-left text-sm text-text hover:bg-surface"
            style={{ paddingLeft: `${String(1.25 + index * 0.75)}rem` }}
            disabled={disabled}
            onClick={() => void onOpen(target)}
          >
            <FolderOpen aria-hidden="true" className="size-4 shrink-0 text-action" />
            <span className="truncate">{part}</span>
          </button>
        );
      })}
      {children.length > 0 ? <div className="my-2 border-t border-border" /> : null}
      {children.slice(0, 20).map((entry) => (
        <button
          key={entry.path}
          type="button"
          className="flex w-full items-center gap-2 rounded-control px-2 py-2 text-left text-sm text-muted hover:bg-surface hover:text-text"
          disabled={disabled}
          onClick={() => void onOpen(entry.path)}
        >
          <Folder aria-hidden="true" className="size-4 shrink-0" />
          <span className="truncate">{entry.name}</span>
        </button>
      ))}
    </aside>
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
