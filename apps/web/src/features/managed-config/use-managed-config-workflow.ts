import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

import {
  ApiError,
  approveManagedConfig,
  getManagedConfigResource,
  getOperationReceipt,
  planManagedConfig,
  reauthenticateForOperation,
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
import { queryKeys, sessionQueryOptions } from "../../shared/api/queries";
import { useAdministrativeAccess } from "../auth/administrative-access";

export interface ManagedConfigCapability {
  resourceId: string;
  operationType: string;
  schemaVersion: number;
}

export function useManagedConfigWorkflow(refreshQueryKey: readonly unknown[]) {
  const queryClient = useQueryClient();
  const session = useQuery(sessionQueryOptions).data;
  const { requestAccess } = useAdministrativeAccess();
  const [resource, setResource] = useState<ManagedConfigResourceView | null>(null);
  const [draft, setDraft] = useState("");
  const [plan, setPlan] = useState<ManagedConfigPlanView | null>(null);
  const [accepted, setAccepted] = useState<OperationAcceptedView | null>(null);
  const [receipt, setReceipt] = useState<OperationReceiptView | null>(null);
  const [diagnosticLine, setDiagnosticLine] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [planning, setPlanning] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const requestInFlight = useRef(false);
  const approvalKey = useRef<string | null>(null);

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
            setDiagnosticLine(managedConfigSyntaxDiagnosticLine(current.stages));
            closeStream();
            setAccepted(null);
            await queryClient.invalidateQueries({ queryKey: refreshQueryKey });
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
  }, [accepted, queryClient, refreshQueryKey]);

  async function open(
    capability: ManagedConfigCapability,
    administrativeConfirmed = false,
  ): Promise<void> {
    if (!administrativeConfirmed && session?.administrativeAccess !== "administrative") {
      requestAccess(() => void open(capability, true));
      return;
    }
    if (requestInFlight.current) return;
    requestInFlight.current = true;
    setLoading(true);
    resetResult();
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

  async function createPlan(
    capability: ManagedConfigCapability,
    administrativeConfirmed = false,
  ): Promise<void> {
    if (!administrativeConfirmed && session?.administrativeAccess !== "administrative") {
      requestAccess(() => void createPlan(capability, true));
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
        serviceAction: "reload",
        idempotencyKey,
      });
      approvalKey.current = idempotencyKey;
      setPlan(nextPlan);
    } catch (error) {
      setErrorMessage(operationErrorCopy(error, "설정 변경 계획을 만들지 못했습니다."));
      await queryClient.invalidateQueries({ queryKey: refreshQueryKey });
    } finally {
      requestInFlight.current = false;
      setPlanning(false);
    }
  }

  async function approve(password: string, additionalAuthCode: string): Promise<void> {
    if (requestInFlight.current || plan === null || approvalKey.current === null) return;
    requestInFlight.current = true;
    setExecuting(true);
    setErrorMessage(null);
    try {
      const reauth = await reauthenticateForOperation({
        password,
        planHash: plan.planHash,
        additionalAuthCode,
      });
      queryClient.setQueryData(queryKeys.session, reauth.session);
      setAccepted(await approveManagedConfig({
        schemaVersion: plan.schemaVersion,
        planId: plan.planId,
        planHash: plan.planHash,
        idempotencyKey: approvalKey.current,
        reauthToken: reauth.reauthToken,
        additionalAuthClaim: reauth.additionalAuthClaim ?? null,
        approvalIntent: {
          validationConfirmed: true,
          serviceActionConfirmed: true,
        },
      }));
    } catch (error) {
      setErrorMessage(operationErrorCopy(error, "승인한 설정 작업을 완료하지 못했습니다."));
    } finally {
      requestInFlight.current = false;
      setExecuting(false);
    }
  }

  function changeDraft(value: string): void {
    setDiagnosticLine(null);
    setDraft(value);
  }

  function revise(line: number | null): void {
    setDiagnosticLine(line);
    setPlan(null);
    setAccepted(null);
    setReceipt(null);
    setErrorMessage(null);
  }

  function close(): void {
    setResource(null);
    setDraft("");
    resetResult();
  }

  function resetResult(): void {
    setPlan(null);
    setAccepted(null);
    setReceipt(null);
    setDiagnosticLine(null);
    setErrorMessage(null);
    approvalKey.current = null;
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
    open,
    createPlan,
    approve,
    changeDraft,
    revise,
    close,
  };
}

function isTerminalStage(stage: OperationStage): boolean {
  return ["SUCCEEDED", "ROLLED_BACK", "RECOVERY_REQUIRED", "REJECTED", "EXPIRED", "CANCELLED_BEFORE_APPLY"].includes(stage);
}

function operationErrorCopy(error: unknown, fallback: string): string {
  if (!(error instanceof ApiError)) return fallback;
  if (error.status === 401) return "재인증에 실패했거나 세션이 만료되었습니다.";
  if (error.status === 403) return "현재 계정 또는 exact-plan 재인증으로 승인할 수 없습니다.";
  if (error.status === 409) return "계획이 만료·변경되었거나 다른 작업이 진행 중입니다. 상태를 다시 확인하세요.";
  if (error.status === 423) return "감사 원장 무결성 잠금으로 모든 변경이 차단되었습니다.";
  if (error.status === 428) return "설정된 추가 인증 수단을 사용할 수 없어 변경이 차단되었습니다.";
  return fallback;
}
