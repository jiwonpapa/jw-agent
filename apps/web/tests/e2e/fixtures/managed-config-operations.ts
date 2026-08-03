import type {
  ManagedConfigPlanView,
  OperationAcceptedView,
  OperationReceiptView,
} from "../../../src/shared/api/types";

interface FixtureInput {
  baseReceipt: OperationReceiptView;
  basePlan: ManagedConfigPlanView;
  baseAccepted: OperationAcceptedView;
  resourceId: string;
  contentDigest: string;
  planHash: string;
}

export function managedConfigInventoryFixture(resourceId: string) {
  return {
    observedAt: "2026-07-21T02:10:00Z",
    status: "observed",
    serviceKey: "nginx",
    unitName: "nginx.service",
    displayName: "Nginx",
    configs: [
      {
        resourceId,
        operationType: "service.config_file.set/v1",
        schemaVersion: 1,
        displayName: "example.com",
        maskedPath: "/etc/nginx/sites-available/example.com",
        relativePath: "sites-available/example.com",
        loaded: true,
        serviceActive: true,
        available: true,
        blockedReason: null,
      },
      {
        resourceId: "ngf_protectedFixture1234567",
        operationType: "service.config_file.set/v1",
        schemaVersion: 1,
        displayName: "private-token.conf",
        maskedPath: "/etc/nginx/private-token.conf",
        relativePath: "private-token.conf",
        loaded: false,
        serviceActive: true,
        available: false,
        blockedReason: "protected_resource",
      },
    ],
    truncated: false,
  };
}

export function managedConfigOperationFixtures(input: FixtureInput) {
  const restorableReceipt: OperationReceiptView = {
    ...input.baseReceipt,
    operationId: "op_config_history",
    displayName: "example.com 설정 저장",
    recordedAt: "2026-07-21T01:50:00Z",
    restoreAvailable: true,
  };
  const restorePlan: ManagedConfigPlanView = {
    ...input.basePlan,
    operationType: "service.config_file.restore/v1",
    planId: "plan_config_restore_fixture",
    planHash: `sha256:${"8".repeat(64)}`,
    proposedContentDigest: `sha256:${"9".repeat(64)}`,
    addedLines: 0,
    removedLines: 1,
    diffSummary: ["-  client_max_body_size 20m;"],
    impact: ["선택한 작업 직전 snapshot으로 설정 파일을 복원합니다."],
  };
  const restoreReceipt: OperationReceiptView = {
    ...input.baseReceipt,
    operationType: "service.config_file.restore/v1",
    planId: restorePlan.planId,
    planHash: restorePlan.planHash,
    displayName: "example.com 설정 복원",
    afterDigest: restorePlan.proposedContentDigest,
    restoreAvailable: true,
  };
  const restoreAccepted: OperationAcceptedView = {
    ...input.baseAccepted,
    operationType: "service.config_file.restore/v1",
    planId: restorePlan.planId,
    planHash: restorePlan.planHash,
  };
  const syntaxFailureReceipt: OperationReceiptView = {
    ...input.baseReceipt,
    terminalState: "ROLLED_BACK",
    afterDigest: input.contentDigest,
    rollbackResult: "verified",
    stages: [
      { sequence: 1, stage: "APPROVED", recordedAt: "2026-07-21T02:12:00Z", resultCode: "approved", evidenceDigest: input.planHash, diagnostics: [] },
      { sequence: 2, stage: "SNAPSHOTTED", recordedAt: "2026-07-21T02:12:01Z", resultCode: "snapshot_durable", evidenceDigest: input.contentDigest, diagnostics: [] },
      { sequence: 3, stage: "APPLYING", recordedAt: "2026-07-21T02:12:02Z", resultCode: "config_replaced", evidenceDigest: input.contentDigest, diagnostics: [] },
      {
        sequence: 4,
        stage: "ROLLING_BACK",
        recordedAt: "2026-07-21T02:12:03Z",
        resultCode: "nginx_config_test_failed:line=3",
        evidenceDigest: input.contentDigest,
        command: {
          class: "nginx_config_test",
          success: false,
          exitCode: 1,
          timedOut: false,
          stdoutDigest: `sha256:${"a".repeat(64)}`,
          stdoutTruncated: false,
          stderrDigest: `sha256:${"b".repeat(64)}`,
          stderrTruncated: true,
        },
        diagnostics: [{
          service: "nginx",
          validator: "nginx_config_test",
          resourceId: input.resourceId,
          maskedPath: "/etc/nginx/sites-available/example.com",
          line: 3,
          column: null,
          severity: "error",
          code: "unknown_directive",
          message: "Nginx가 해석을 중단한 위치입니다.",
          relatedChangedLines: [3],
          causeCandidateLines: [2],
        }],
      },
      { sequence: 5, stage: "ROLLED_BACK", recordedAt: "2026-07-21T02:12:04Z", resultCode: "rollback_verified", evidenceDigest: input.contentDigest, diagnostics: [] },
    ],
  };
  return {
    restorableReceipt,
    restorePlan,
    restoreReceipt,
    restoreAccepted,
    syntaxFailureReceipt,
  };
}
