import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Ban,
  BrickWall,
  CheckCircle2,
  LoaderCircle,
  Plus,
  ShieldCheck,
  Trash2,
  TriangleAlert,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";

import {
  ApiError,
  approveUfwRule,
  getOperationReceipt,
  planUfwRule,
  watchOperationEvents,
} from "../../shared/api/client";
import type {
  OperationAcceptedView,
  OperationReceiptView,
  OperationStage,
  UfwProtocol,
  UfwRuleMutation,
  UfwRuleView,
} from "../../shared/api/types";
import { queryKeys, sessionQueryOptions, ufwQueryOptions } from "../../shared/api/queries";
import { formatDateTime } from "../../shared/domain/format";
import { Button } from "../../shared/ui/button";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";
import { useAdministrativeAccess } from "../auth/administrative-access";

interface RuleDraft {
  mutation: Exclude<UfwRuleMutation, "delete">;
  protocol: UfwProtocol;
  port: string;
  source: string;
}

const INITIAL_DRAFT: RuleDraft = {
  mutation: "allow",
  protocol: "tcp",
  port: "",
  source: "",
};

export function UfwScreen() {
  const inventory = useQuery(ufwQueryOptions);
  const session = useQuery(sessionQueryOptions).data;
  const queryClient = useQueryClient();
  const { requestAccess } = useAdministrativeAccess();
  const [draft, setDraft] = useState<RuleDraft>(INITIAL_DRAFT);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [accepted, setAccepted] = useState<OperationAcceptedView | null>(null);
  const [receipt, setReceipt] = useState<OperationReceiptView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const operationKey = useRef<string | null>(null);

  useEffect(() => {
    if (accepted === null) return;
    const operation = accepted;
    const controller = new AbortController();
    let closeStream = (): void => undefined;
    async function refresh(): Promise<void> {
      try {
        const next = await getOperationReceipt(operation.operationId, controller.signal);
        setReceipt(next);
        if (terminal(next.terminalState)) {
          closeStream();
          setAccepted(null);
          await queryClient.invalidateQueries({ queryKey: queryKeys.ufw });
        }
      } catch (reason) {
        if (!(reason instanceof DOMException && reason.name === "AbortError")) {
          setError(errorCopy(reason));
        }
      }
    }
    closeStream = watchOperationEvents(operation.eventStream, () => void refresh(), () => void refresh());
    void refresh();
    return () => {
      controller.abort();
      closeStream();
    };
  }, [accepted, queryClient]);

  async function saveRule(administrativeConfirmed = false): Promise<void> {
    if (!administrativeConfirmed && session?.administrativeAccess !== "administrative") {
      requestAccess(() => void saveRule(true));
      return;
    }
    const port = Number.parseInt(draft.port, 10);
    if (!Number.isInteger(port) || port < 1 || port > 65_535) {
      setError("포트는 1~65535 사이 숫자로 입력해 주세요.");
      return;
    }
    await execute({
      mutation: draft.mutation,
      protocol: draft.protocol,
      port,
      source: draft.source.trim() || null,
      ruleId: null,
    });
  }

  async function deleteRule(rule: UfwRuleView, administrativeConfirmed = false): Promise<void> {
    if (rule.ruleId == null || !rule.owned || rule.protected) return;
    if (deleteConfirm !== rule.ruleId) {
      setDeleteConfirm(rule.ruleId);
      return;
    }
    if (!administrativeConfirmed && session?.administrativeAccess !== "administrative") {
      requestAccess(() => void deleteRule(rule, true));
      return;
    }
    await execute({
      mutation: "delete",
      protocol: null,
      port: null,
      source: null,
      ruleId: rule.ruleId,
    });
  }

  async function execute(input: {
    mutation: UfwRuleMutation;
    protocol: UfwProtocol | null;
    port: number | null;
    source: string | null;
    ruleId: string | null;
  }): Promise<void> {
    if (inventory.data == null || busy) return;
    setBusy(true);
    setError(null);
    setReceipt(null);
    const idempotencyKey = `web_${crypto.randomUUID()}`;
    operationKey.current = idempotencyKey;
    try {
      const plan = await planUfwRule({
        schemaVersion: 1,
        operationType: "ufw.rule.set/v1",
        mutation: input.mutation,
        protocol: input.protocol,
        port: input.port,
        source: input.source,
        ruleId: input.ruleId,
        expectedStateDigest: inventory.data.stateDigest,
        idempotencyKey,
      });
      setAccepted(await approveUfwRule({
        schemaVersion: plan.schemaVersion,
        planId: plan.planId,
        planHash: plan.planHash,
        idempotencyKey,
        impactConfirmed: true,
      }));
      setDraft(INITIAL_DRAFT);
      setDeleteConfirm(null);
    } catch (reason) {
      setError(errorCopy(reason));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Security / Firewall"
        title="UFW 방화벽"
        description="현재 규칙을 확인하고 JW Agent가 만든 제한 규칙만 안전하게 추가·삭제합니다."
        action={inventory.data ? (
          <div className="text-left sm:text-right">
            <p className="text-xs text-muted">마지막 관찰</p>
            <p className="mt-1 text-sm font-medium text-text">{formatDateTime(inventory.data.observedAt)}</p>
          </div>
        ) : null}
      />

      {inventory.isPending ? (
        <div className="grid gap-4 py-6 lg:grid-cols-2"><Skeleton className="h-56" /><Skeleton className="h-56" /></div>
      ) : inventory.isError ? (
        <SurfaceState kind="offline" title="UFW 상태를 불러오지 못했습니다" description="root 관찰 helper와 UFW 설치 상태를 확인해 주세요." action={{ label: "다시 관찰", onClick: () => void inventory.refetch() }} />
      ) : (
        <div className="grid gap-5 py-6 xl:grid-cols-[minmax(18rem,0.7fr)_minmax(0,1.3fr)]">
          <section className="rounded-panel border border-border bg-surface p-5" aria-labelledby="ufw-state-heading">
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-start gap-3">
                <span className="grid size-10 place-items-center rounded-control bg-subtle text-action"><BrickWall aria-hidden="true" className="size-5" /></span>
                <div>
                  <h2 id="ufw-state-heading" className="font-semibold text-text">방화벽 상태</h2>
                  <p className="mt-1 text-sm text-muted">UFW {statusLabel(inventory.data.status)}</p>
                </div>
              </div>
              <StatusMark label={inventory.data.status === "active" ? "활성" : "변경 차단"} tone={inventory.data.status === "active" ? "success" : "warning"} />
            </div>

            <form className="mt-6 border-t border-border pt-5" onSubmit={(event) => { event.preventDefault(); void saveRule(); }}>
              <h3 className="text-sm font-semibold text-text">규칙 추가</h3>
              <div className="mt-3 grid gap-3 sm:grid-cols-2">
                <label className="text-sm text-text">동작
                  <select className="mt-1 min-h-11 w-full rounded-control border border-border bg-surface px-3" value={draft.mutation} onChange={(event) => setDraft((current) => ({ ...current, mutation: event.target.value as RuleDraft["mutation"] }))}>
                    <option value="allow">허용</option>
                    <option value="deny">차단</option>
                  </select>
                </label>
                <label className="text-sm text-text">프로토콜
                  <select className="mt-1 min-h-11 w-full rounded-control border border-border bg-surface px-3" value={draft.protocol} onChange={(event) => setDraft((current) => ({ ...current, protocol: event.target.value as UfwProtocol }))}>
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                  </select>
                </label>
                <label className="text-sm text-text">포트
                  <input className="mt-1 min-h-11 w-full rounded-control border border-border bg-surface px-3" inputMode="numeric" placeholder="예: 8080" value={draft.port} onChange={(event) => setDraft((current) => ({ ...current, port: event.target.value }))} />
                </label>
                <label className="text-sm text-text">접속 원본 <span className="text-muted">(선택)</span>
                  <input className="mt-1 min-h-11 w-full rounded-control border border-border bg-surface px-3" placeholder="203.0.113.0/24" value={draft.source} onChange={(event) => setDraft((current) => ({ ...current, source: event.target.value }))} />
                </label>
              </div>
              <p className="mt-3 text-xs leading-5 text-muted">22·443·9443/TCP 차단과 기존 규칙 삭제는 서버가 거부합니다.</p>
              <Button className="mt-4 w-full" disabled={!inventory.data.mutationAvailable || busy || accepted !== null} type="submit">
                {busy || accepted !== null ? <LoaderCircle aria-hidden="true" className="size-4 animate-spin" /> : <Plus aria-hidden="true" className="size-4" />}
                {busy || accepted !== null ? "적용 확인 중" : "규칙 추가"}
              </Button>
            </form>
            {error ? <p role="alert" className="mt-4 rounded-control border border-danger/30 bg-danger/5 p-3 text-sm text-danger">{error}</p> : null}
            {receipt && terminal(receipt.terminalState) ? <ResultCard receipt={receipt} /> : null}
          </section>

          <section className="rounded-panel border border-border bg-surface p-5" aria-labelledby="ufw-rules-heading">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 id="ufw-rules-heading" className="font-semibold text-text">현재 규칙 {inventory.data.rules.length}개</h2>
                <p className="mt-1 text-sm text-muted">제품 소유 규칙만 삭제 버튼이 표시됩니다.</p>
              </div>
              <ShieldCheck aria-hidden="true" className="size-5 text-success" />
            </div>
            {inventory.data.rules.length === 0 ? (
              <p className="mt-5 rounded-control bg-subtle p-5 text-sm text-muted">등록된 UFW 규칙이 없습니다.</p>
            ) : (
              <ul className="mt-5 grid gap-3 md:grid-cols-2">
                {inventory.data.rules.map((rule) => (
                  <li key={`${String(rule.sequence)}-${rule.summary}`} className="rounded-control border border-border bg-subtle/25 p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex min-w-0 items-start gap-3">
                        {rule.action === "deny" ? <Ban aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-danger" /> : <ShieldCheck aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-success" />}
                        <div className="min-w-0">
                          <p className="font-semibold text-text">{rule.action === "deny" ? "차단" : rule.action === "allow" ? "허용" : rule.action.toUpperCase()} · {rule.destination}</p>
                          <p className="mt-1 truncate text-sm text-muted">{rule.source}</p>
                        </div>
                      </div>
                      <StatusMark label={rule.owned ? "JW Agent" : "기존 규칙"} tone={rule.owned ? "info" : "neutral"} />
                    </div>
                    {rule.owned && !rule.protected ? (
                      <Button className="mt-4" size="compact" variant={deleteConfirm === rule.ruleId ? "danger" : "secondary"} disabled={busy || accepted !== null} onClick={() => void deleteRule(rule)}>
                        <Trash2 aria-hidden="true" className="size-4" />
                        {deleteConfirm === rule.ruleId ? "한 번 더 눌러 삭제" : "삭제"}
                      </Button>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      )}
    </div>
  );
}

function ResultCard({ receipt }: { receipt: OperationReceiptView }) {
  const success = receipt.terminalState === "SUCCEEDED";
  return (
    <div className={success ? "mt-4 rounded-control border border-success/30 bg-success/5 p-3" : "mt-4 rounded-control border border-warning/30 bg-warning/5 p-3"}>
      <div className="flex items-start gap-2">
        {success ? <CheckCircle2 aria-hidden="true" className="size-5 text-success" /> : <TriangleAlert aria-hidden="true" className="size-5 text-warning" />}
        <p className="text-sm font-medium text-text">{success ? "방화벽 규칙 적용 완료" : receipt.terminalState === "ROLLED_BACK" ? "실패 후 이전 규칙 복구 완료" : "수동 확인이 필요합니다"}</p>
      </div>
    </div>
  );
}

function statusLabel(status: string): string {
  if (status === "active") return "활성";
  if (status === "inactive") return "비활성";
  if (status === "not_installed") return "미설치";
  return "확인 불가";
}

function terminal(stage: OperationStage): boolean {
  return ["SUCCEEDED", "ROLLED_BACK", "RECOVERY_REQUIRED", "REJECTED", "EXPIRED", "CANCELLED_BEFORE_APPLY"].includes(stage);
}

function errorCopy(reason: unknown): string {
  if (!(reason instanceof ApiError)) return "방화벽 작업을 완료하지 못했습니다.";
  if (reason.code === "protected_management_rule") return "SSH 또는 관리 접속 포트는 차단하거나 삭제할 수 없습니다.";
  if (reason.code === "invalid_source") return "접속 원본은 정확한 IP 또는 CIDR로 입력해 주세요.";
  if (reason.status === 409) return "규칙이 바뀌었습니다. 새로 관찰한 뒤 다시 시도해 주세요.";
  if (reason.status === 423) return "감사 원장 무결성 잠금으로 변경이 차단되었습니다.";
  return reason.message;
}
