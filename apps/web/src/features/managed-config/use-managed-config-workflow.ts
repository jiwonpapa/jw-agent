import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

import {
  ApiError,
  approveManagedConfig,
  getManagedConfigResource,
  getOperationReceipt,
  planManagedConfig,
  planManagedConfigRestore,
  watchOperationEvents,
} from "../../shared/api/client";
import type {
  ManagedConfigPlanView,
  ManagedConfigResourceView,
  OperationAcceptedView,
  OperationReceiptView,
  OperationStage,
} from "../../shared/api/types";
import { managedConfigSyntaxDiagnosticLine } from "../../shared/domain/managed-config-diagnostic";
import { activityQueryOptions, sessionQueryOptions } from "../../shared/api/queries";
import { useAdministrativeAccess } from "../auth/administrative-access";

export interface ManagedConfigCapability {
  resourceId: string;
  operationType: string;
  schemaVersion: number;
  serviceAction?: "reload" | "validate_only";
}

export function useManagedConfigWorkflow(refreshQueryKey: readonly unknown[]) {
  const queryClient = useQueryClient();
  const session = useQuery(sessionQueryOptions).data;
  const { requestAccess } = useAdministrativeAccess();
  const [resource, setResource] = useState<ManagedConfigResourceView | null>(null);
  const activity = useQuery({
    ...activityQueryOptions,
    enabled: resource !== null,
  });
  const [draft, setDraft] = useState("");
  const [plan, setPlan] = useState<ManagedConfigPlanView | null>(null);
  const [accepted, setAccepted] = useState<OperationAcceptedView | null>(null);
  const [receipt, setReceipt] = useState<OperationReceiptView | null>(null);
  const [diagnosticLine, setDiagnosticLine] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [planning, setPlanning] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [restoreSource, setRestoreSource] = useState<OperationReceiptView | null>(null);
  const [restorePlan, setRestorePlan] = useState<ManagedConfigPlanView | null>(null);
  const [restoreAccepted, setRestoreAccepted] = useState<OperationAcceptedView | null>(null);
  const [restoreReceipt, setRestoreReceipt] = useState<OperationReceiptView | null>(null);
  const [restoreBusy, setRestoreBusy] = useState(false);
  const [restoreError, setRestoreError] = useState<string | null>(null);
  const requestInFlight = useRef(false);
  const restoreKey = useRef<string | null>(null);
  const activeResourceId = resource?.resourceId ?? null;

  useEffect(() => {
    if (accepted === null) return;
    const operation = accepted;
    const controller = new AbortController();
    let closeStream: () => void = () => undefined;
    let refreshQueue = Promise.resolve();
    function refreshReceipt(): void {
      refreshQueue = refreshQueue.then(async () => {
        try {
          const current = await getOperationReceipt(operation.operationId, controller.signal);
          setReceipt(current);
          if (isTerminalStage(current.terminalState)) {
            setDiagnosticLine(
              managedConfigSyntaxDiagnosticLine(current.stages, resource?.resourceId),
            );
            closeStream();
            setAccepted(null);
            await Promise.all([
              queryClient.invalidateQueries({ queryKey: refreshQueryKey }),
              queryClient.invalidateQueries({ queryKey: activityQueryOptions.queryKey }),
            ]);
          }
        } catch (error) {
          if (!(error instanceof DOMException && error.name === "AbortError")) {
            setErrorMessage(operationErrorCopy(error, "작업 진행 영수증을 불러오지 못했습니다."));
          }
        }
      });
    }
    closeStream = watchOperationEvents(operation.eventStream, refreshReceipt, refreshReceipt);
    refreshReceipt();
    return () => {
      controller.abort();
      closeStream();
    };
  }, [accepted, queryClient, refreshQueryKey, resource?.resourceId]);

  useEffect(() => {
    if (restoreAccepted === null) return;
    const operation = restoreAccepted;
    const controller = new AbortController();
    let closeStream: () => void = () => undefined;
    let refreshQueue = Promise.resolve();
    function refreshRestoreReceipt(): void {
      refreshQueue = refreshQueue.then(async () => {
        try {
          const current = await getOperationReceipt(operation.operationId, controller.signal);
          setRestoreReceipt(current);
          if (isTerminalStage(current.terminalState)) {
            closeStream();
            setRestoreAccepted(null);
            await Promise.all([
              queryClient.invalidateQueries({ queryKey: refreshQueryKey }),
              queryClient.invalidateQueries({ queryKey: activityQueryOptions.queryKey }),
            ]);
            if (current.terminalState === "SUCCEEDED" && activeResourceId !== null) {
              const refreshed = await getManagedConfigResource(
                activeResourceId,
                controller.signal,
              );
              setResource(refreshed);
              setDraft(refreshed.content);
            }
          }
        } catch (error) {
          if (!(error instanceof DOMException && error.name === "AbortError")) {
            setRestoreError(operationErrorCopy(error, "복원 작업 영수증을 불러오지 못했습니다."));
          }
        }
      });
    }
    closeStream = watchOperationEvents(
      operation.eventStream,
      refreshRestoreReceipt,
      refreshRestoreReceipt,
    );
    refreshRestoreReceipt();
    return () => {
      controller.abort();
      closeStream();
    };
  }, [activeResourceId, queryClient, refreshQueryKey, restoreAccepted]);

  async function open(
    capability: ManagedConfigCapability,
    administrativeConfirmed = false,
  ): Promise<void> {
    if (!administrativeConfirmed && session?.administrativeAccess !== "administrative") {
      requestAccess(() => void open(capability, true));
      return;
    }
    if (requestInFlight.current || accepted !== null || restoreAccepted !== null) return;
    requestInFlight.current = true;
    setLoading(true);
    resetResult();
    resetRestore();
    try {
      const current = await getManagedConfigResource(capability.resourceId);
      setResource(current);
      setDraft(current.content);
    } catch (error) {
      setErrorMessage(operationErrorCopy(error, "설정 파일을 안전하게 불러오지 못했습니다."));
    } finally {
      requestInFlight.current = false;
      setLoading(false);
    }
  }

  async function save(
    capability: ManagedConfigCapability,
    administrativeConfirmed = false,
  ): Promise<void> {
    if (!administrativeConfirmed && session?.administrativeAccess !== "administrative") {
      requestAccess(() => void save(capability, true));
      return;
    }
    if (requestInFlight.current || resource === null || draft === resource.content) return;
    requestInFlight.current = true;
    setPlanning(true);
    setErrorMessage(null);
    setAccepted(null);
    setReceipt(null);
    try {
      const idempotencyKey = `web_${crypto.randomUUID()}`;
      const nextPlan = await planManagedConfig({
        schemaVersion: capability.schemaVersion,
        operationType: capability.operationType,
        resourceId: capability.resourceId,
        expectedContentDigest: resource.contentDigest,
        expectedMetadataDigest: resource.metadataDigest,
        proposedContent: draft,
        serviceAction:
          capability.serviceAction ??
          (resource.allowedServiceActions.includes("reload") ? "reload" : "validate_only"),
        idempotencyKey,
      });
      setPlan(nextPlan);
      setPlanning(false);
      setExecuting(true);
      setAccepted(await approveManagedConfig({
        schemaVersion: nextPlan.schemaVersion,
        planId: nextPlan.planId,
        planHash: nextPlan.planHash,
        idempotencyKey,
        reauthToken: null,
        additionalAuthClaim: null,
        approvalIntent: {
          validationConfirmed: true,
          serviceActionConfirmed: true,
        },
      }));
    } catch (error) {
      setDiagnosticLine(operationDiagnosticLine(error));
      setErrorMessage(operationErrorCopy(error, "설정을 검증하거나 저장하지 못했습니다."));
      await queryClient.invalidateQueries({ queryKey: refreshQueryKey });
    } finally {
      requestInFlight.current = false;
      setPlanning(false);
      setExecuting(false);
    }
  }

  function changeDraft(value: string): void {
    setDiagnosticLine(null);
    setPlan(null);
    setAccepted(null);
    setReceipt(null);
    setErrorMessage(null);
    resetRestore();
    setDraft(value);
  }

  function revise(line: number | null): void {
    setDiagnosticLine(line);
    setPlan(null);
    setAccepted(null);
    setReceipt(null);
    setErrorMessage(null);
  }

  async function selectRestore(
    source: OperationReceiptView,
    administrativeConfirmed = false,
  ): Promise<void> {
    if (!administrativeConfirmed && session?.administrativeAccess !== "administrative") {
      requestAccess(() => void selectRestore(source, true));
      return;
    }
    if (
      restoreBusy ||
      restoreAccepted !== null ||
      resource === null ||
      draft !== resource.content ||
      !source.restoreAvailable ||
      source.resourceId !== resource.resourceId
    ) {
      return;
    }
    setRestoreSource(source);
    setRestorePlan(null);
    setRestoreReceipt(null);
    setRestoreError(null);
    setRestoreBusy(true);
    const idempotencyKey = `web_${crypto.randomUUID()}`;
    restoreKey.current = idempotencyKey;
    try {
      const current = await getManagedConfigResource(resource.resourceId);
      setResource(current);
      setDraft(current.content);
      setRestorePlan(await planManagedConfigRestore({
        schemaVersion: current.schemaVersion,
        operationType: "service.config_file.restore/v1",
        sourceOperationId: source.operationId,
        expectedContentDigest: current.contentDigest,
        expectedMetadataDigest: current.metadataDigest,
        idempotencyKey,
      }));
    } catch (error) {
      setRestoreError(operationErrorCopy(error, "변경 전 상태를 확인하지 못했습니다."));
    } finally {
      setRestoreBusy(false);
    }
  }

  async function applyRestore(): Promise<void> {
    if (
      restoreBusy ||
      restoreAccepted !== null ||
      restorePlan === null ||
      restoreKey.current === null ||
      resource === null ||
      draft !== resource.content
    ) {
      return;
    }
    setRestoreBusy(true);
    setRestoreError(null);
    try {
      setRestoreAccepted(await approveManagedConfig({
        schemaVersion: restorePlan.schemaVersion,
        planId: restorePlan.planId,
        planHash: restorePlan.planHash,
        idempotencyKey: restoreKey.current,
        reauthToken: null,
        additionalAuthClaim: null,
        approvalIntent: {
          validationConfirmed: true,
          serviceActionConfirmed: true,
        },
      }));
    } catch (error) {
      setRestoreError(operationErrorCopy(error, "설정을 복원하지 못했습니다."));
    } finally {
      setRestoreBusy(false);
    }
  }

  function cancelRestore(): void {
    if (restoreAccepted !== null) return;
    resetRestore();
  }

  function resetRestore(): void {
    setRestoreSource(null);
    setRestorePlan(null);
    setRestoreReceipt(null);
    setRestoreError(null);
    restoreKey.current = null;
  }

  function close(): void {
    setResource(null);
    setDraft("");
    resetResult();
    cancelRestore();
  }

  function resetResult(): void {
    setPlan(null);
    setAccepted(null);
    setReceipt(null);
    setDiagnosticLine(null);
    setErrorMessage(null);
  }

  return {
    resource,
    draft,
    plan,
    accepted,
    receipt,
    diagnosticLine,
    loading,
    planning,
    executing,
    errorMessage,
    history: (activity.data?.operations ?? []).filter(
      (operation) =>
        operation.resourceId === resource?.resourceId &&
        operation.restoreAvailable &&
        operation.terminalState === "SUCCEEDED",
    ),
    historyLoading: activity.isPending && resource !== null,
    historyError: activity.isError,
    restoreSource,
    restorePlan,
    restoreAccepted,
    restoreReceipt,
    restoreBusy,
    restoreError,
    open,
    save,
    changeDraft,
    revise,
    selectRestore,
    applyRestore,
    cancelRestore,
    close,
  };
}

function isTerminalStage(stage: OperationStage): boolean {
  return ["SUCCEEDED", "ROLLED_BACK", "RECOVERY_REQUIRED", "REJECTED", "EXPIRED", "CANCELLED_BEFORE_APPLY"].includes(stage);
}

function operationErrorCopy(error: unknown, fallback: string): string {
  if (!(error instanceof ApiError)) return fallback;
  if (error.code === "empty_config") return "빈 설정 파일은 적용할 수 없습니다. 필수 설정을 복원한 뒤 다시 검증하세요.";
  if (error.code.startsWith("ignored_directive_line_")) return "설정으로 해석되지 않는 줄이 있습니다. 표시된 줄을 수정하거나 주석으로 바꾸세요.";
  if (error.code.startsWith("unknown_directive_line_")) return "현재 설치된 PHP가 알지 못하는 설정 항목입니다. 표시된 줄의 이름을 확인하세요.";
  if (error.code.startsWith("invalid_directive_line_")) return "설정 형식이 올바르지 않습니다. 표시된 줄을 ‘항목 = 값’ 형식으로 수정하세요.";
  if (error.status === 401) return "재인증에 실패했거나 세션이 만료되었습니다.";
  if (error.status === 403) return "관리 모드가 만료되었거나 현재 계정에 변경 권한이 없습니다.";
  if (error.status === 409) return "계획이 만료·변경되었거나 다른 작업이 진행 중입니다. 상태를 다시 확인하세요.";
  if (error.status === 423) return "감사 원장 무결성 잠금으로 모든 변경이 차단되었습니다.";
  if (error.status === 428) return "설정된 추가 인증 수단을 사용할 수 없어 변경이 차단되었습니다.";
  return fallback;
}

function operationDiagnosticLine(error: unknown): number | null {
  if (!(error instanceof ApiError)) return null;
  const match = error.code.match(/_(?:line_)?(\d+)$/u);
  if (match === null) return null;
  const line = Number.parseInt(match[1] ?? "", 10);
  return Number.isFinite(line) && line > 0 ? line : null;
}
