import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  Clock3,
  HardDrive,
  MemoryStick,
  Server,
  ShieldCheck,
  Timer,
  TriangleAlert,
} from "lucide-react";

import {
  activityQueryOptions,
  hostQueryOptions,
  nginxSitesQueryOptions,
  servicesQueryOptions,
  sessionQueryOptions,
} from "../../shared/api/queries";
import type { OperationStage } from "../../shared/api/types";
import { OBSERVATION_LABELS, ROLE_LABELS } from "../../shared/content/copy";
import { formatBytes, formatDateTime, formatDuration } from "../../shared/domain/format";
import { AssuranceMark } from "../../shared/ui/assurance";
import { Button } from "../../shared/ui/button";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark, type StatusTone } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";
import { ServiceOverview } from "../services/service-overview";

const observationTone = {
  observed: "success",
  partial: "warning",
  not_installed: "neutral",
  unsupported_platform: "stale",
} as const satisfies Record<string, StatusTone>;

export function OverviewScreen() {
  const host = useQuery(hostQueryOptions);
  const nginx = useQuery(nginxSitesQueryOptions);
  const services = useQuery(servicesQueryOptions);
  const activity = useQuery(activityQueryOptions);
  const session = useQuery(sessionQueryOptions).data;
  const memoryUsage = host.data?.memory === null || host.data?.memory === undefined
    ? null
    : usagePercent(host.data.memory.totalBytes, host.data.memory.availableBytes);
  const diskUsage = host.data?.rootDisk === null || host.data?.rootDisk === undefined
    ? null
    : usagePercent(host.data.rootDisk.totalBytes, host.data.rootDisk.availableBytes);
  const failedServices = services.data?.services.filter((service) => service.runtimeState === "failed") ?? [];

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Overview"
        title="서버 개요"
        description="자원 사용률과 조치가 필요한 문제를 한 화면에서 확인합니다."
        action={
          host.data ? (
            <div className="text-left sm:text-right">
              <p className="text-xs text-muted">마지막 관찰</p>
              <p className="mt-1 text-sm font-medium text-text">{formatDateTime(host.data.observedAt)}</p>
            </div>
          ) : null
        }
      />

      {session === undefined ? null : (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-border py-3 text-xs text-muted">
          <span className="inline-flex items-center gap-2 font-medium text-text">
            <ShieldCheck aria-hidden="true" className="size-4 text-action" />
            {session.subject.username} · JW Agent {ROLE_LABELS[session.subject.role]}
          </span>
          <span>Linux UID {String(session.subject.uid)} · 비-root</span>
          <span>{session.ingress === "public" ? "공개 HTTPS" : "SSH 복구 접속"}</span>
        </div>
      )}

      <section className="py-7" aria-labelledby="identity-heading">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 id="identity-heading" className="text-sm font-semibold text-text">
              서버 상태 요약
            </h2>
            <p className="mt-1 text-sm text-muted">호스트 identity와 관찰 완전성입니다.</p>
          </div>
          {host.data ? (
            <StatusMark
              label={OBSERVATION_LABELS[host.data.status]}
              tone={observationTone[host.data.status]}
            />
          ) : null}
        </div>

        {host.isPending ? (
          <div className="mt-5 grid gap-px overflow-hidden rounded-panel border border-border bg-border sm:grid-cols-2 lg:grid-cols-4">
            {Array.from({ length: 4 }).map((_, index) => (
              <div key={index} className="bg-surface p-4">
                <Skeleton className="h-4 w-20" />
                <Skeleton className="mt-3 h-6 w-28" />
              </div>
            ))}
          </div>
        ) : host.isError ? (
          <SurfaceState
            kind="offline"
            title="호스트 관찰을 불러오지 못했습니다"
            description="이 화면은 이전 값을 정상값으로 대체하지 않습니다."
            action={{ label: "다시 관찰", onClick: () => void host.refetch() }}
          />
        ) : (
          <dl className="mt-5 grid gap-px overflow-hidden rounded-panel border border-border bg-border sm:grid-cols-2 lg:grid-cols-4">
            <Metric
              icon={Server}
              label="호스트"
              value={host.data.hostname ?? "알 수 없음"}
              detail={host.data.osPrettyName ?? host.data.osId ?? "OS 정보 없음"}
            />
            <Metric
              icon={MemoryStick}
              label="메모리"
              value={memoryUsage === null ? "알 수 없음" : `${String(Math.round(memoryUsage))}% 사용`}
              detail={
                host.data.memory
                  ? `${formatBytes(host.data.memory.availableBytes)} 사용 가능`
                  : "관찰값 없음"
              }
              meterValue={memoryUsage}
              meterTone={usageTone(memoryUsage, 88, 96)}
            />
            <Metric
              icon={HardDrive}
              label="루트 디스크"
              value={diskUsage === null ? "알 수 없음" : `${String(Math.round(diskUsage))}% 사용`}
              detail={
                host.data.rootDisk
                  ? `${formatBytes(host.data.rootDisk.availableBytes)} 사용 가능`
                  : "관찰값 없음"
              }
              meterValue={diskUsage}
              meterTone={usageTone(diskUsage, 80, 90)}
            />
            <Metric
              icon={Timer}
              label="업타임"
              value={formatDuration(host.data.uptimeSeconds)}
              detail={
                host.data.loadAverageOne === null || host.data.loadAverageOne === undefined
                  ? "부하 관찰값 없음"
                  : `1분 부하 ${host.data.loadAverageOne.toFixed(2)}`
              }
            />
          </dl>
        )}
      </section>

      <section className="border-t border-border py-7" aria-labelledby="attention-heading">
        <div className="flex items-center gap-3">
          <TriangleAlert aria-hidden="true" className="size-5 text-muted" />
          <div>
            <h2 id="attention-heading" className="text-sm font-semibold text-text">
              주의 및 권장 조치
            </h2>
            <p className="mt-1 text-sm text-muted">현재 관찰값에서 운영자가 확인할 문제만 표시합니다.</p>
          </div>
        </div>

        {host.isPending || services.isPending ? (
          <div className="mt-5 border-y border-border py-5 text-sm text-muted">호스트와 서비스 상태를 확인하고 있습니다.</div>
        ) : host.isError || services.isError ? (
          <AttentionItem
            icon={AlertCircle}
            title="일부 관찰 결과를 불러오지 못했습니다"
            description="알 수 없는 상태를 정상으로 처리하지 않습니다. 개별 화면에서 다시 관찰해 주세요."
            tone="warning"
          />
        ) : host.data.status === "partial" ? (
          <div className="mt-5 flex flex-col gap-4 border-y border-warning/35 py-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-sm font-semibold text-text">호스트 정보가 일부만 관찰되었습니다</p>
              <p className="mt-1 text-sm text-muted">누락된 항목을 0 또는 정상으로 해석하지 않습니다.</p>
            </div>
            <StatusMark label="부분 관찰" tone="warning" />
          </div>
        ) : host.data.status === "unsupported_platform" ? (
          <div className="mt-5">
            <SurfaceState
              kind="unsupported"
              title="지원하지 않는 플랫폼입니다"
              description="Ubuntu 24.04 LTS 지원 프로필과 일치하지 않아 변경 기능을 제공하지 않습니다."
            />
          </div>
        ) : diskUsage !== null && diskUsage >= 90 ? (
          <AttentionItem
            icon={HardDrive}
            title={`루트 디스크 사용률 ${String(Math.round(diskUsage))}%`}
            description="90% 이상입니다. 로그·백업·임시파일 증가 원인을 확인해 주세요."
            tone="danger"
          />
        ) : failedServices.length > 0 ? (
          <AttentionItem
            icon={AlertCircle}
            title={`실패한 서비스 ${String(failedServices.length)}개`}
            description={failedServices.slice(0, 3).map((service) => service.displayName).join(" · ")}
            tone="danger"
            href="/services"
          />
        ) : (
          <div className="mt-5 flex items-center gap-2 border-y border-border py-5 text-sm text-muted">
            <CheckCircle2 aria-hidden="true" className="size-4 text-success" />
            현재 즉시 확인할 문제가 없습니다.
          </div>
        )}
      </section>

      <ServiceOverview />

      <section className="border-t border-border py-7" aria-labelledby="nginx-heading">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h2 id="nginx-heading" className="text-sm font-semibold text-text">
              웹 서버 · Nginx 사이트
            </h2>
            <p className="mt-1 text-sm text-muted">웹 서버 서비스에 연결된 site와 변경 보장 범위입니다.</p>
          </div>
          <Button asChild variant="secondary" size="compact">
            <Link to="/services/nginx">
              전체 보기
              <ArrowRight aria-hidden="true" className="size-4" />
            </Link>
          </Button>
        </div>

        {nginx.isPending ? (
          <div className="mt-5 space-y-2">
            <Skeleton className="h-12 w-full" />
            <Skeleton className="h-12 w-full" />
          </div>
        ) : nginx.isError ? (
          <SurfaceState
            kind="error"
            title="Nginx 상태를 불러오지 못했습니다"
            description="호스트 상태와 별개로 Nginx 관찰 요청이 실패했습니다."
            action={{ label: "다시 불러오기", onClick: () => void nginx.refetch() }}
          />
        ) : nginx.data.status === "not_installed" ? (
          <SurfaceState
            kind="empty"
            title="Nginx가 설치되지 않았습니다"
            description="설치 작업은 P1 읽기 전용 범위에 포함되지 않습니다."
          />
        ) : nginx.data.status === "unsupported_platform" ? (
          <SurfaceState
            kind="unsupported"
            title="이 Nginx 구성을 지원하지 않습니다"
            description="사이트 경로를 추측하지 않고 관찰을 중단했습니다."
          />
        ) : nginx.data.sites.length === 0 ? (
          <SurfaceState kind="empty" title="발견된 사이트가 없습니다" description="Nginx는 관찰됐지만 site 항목이 비어 있습니다." />
        ) : (
          <div className="mt-5 divide-y divide-border border-y border-border">
            {nginx.data.sites.slice(0, 4).map((site) => (
              <div key={site.name} className="flex min-h-14 items-center justify-between gap-4 py-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-text">{site.name}</p>
                  <p className="mt-0.5 text-xs text-muted">
                    {site.protected ? "JW Agent 보호 리소스" : "일반 Nginx 사이트"}
                  </p>
                </div>
                <div className="flex shrink-0 flex-col items-end gap-1.5">
                  <StatusMark label={site.enabled ? "활성" : "비활성"} tone={site.enabled ? "success" : "neutral"} />
                  <AssuranceMark assurance={site.assurance} />
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="border-t border-border py-7" aria-labelledby="ledger-heading">
        <div className="flex items-center gap-3">
          <Clock3 aria-hidden="true" className="size-5 text-muted" />
          <div>
            <h2 id="ledger-heading" className="text-sm font-semibold text-text">
              최근 작업
            </h2>
            <p className="mt-1 text-sm text-muted">현재 Linux 계정이 실행한 typed operation의 최신 결과입니다.</p>
          </div>
        </div>
        {activity.isPending ? (
          <div className="mt-5 space-y-2">
            <Skeleton className="h-14 w-full" />
            <Skeleton className="h-14 w-full" />
          </div>
        ) : activity.isError ? (
          <SurfaceState
            kind="error"
            title="작업 이력을 불러오지 못했습니다"
            description="원장 연결 실패를 빈 이력으로 표시하지 않습니다."
            action={{ label: "다시 불러오기", onClick: () => void activity.refetch() }}
          />
        ) : activity.data.operations.length === 0 ? (
          <div className="mt-5 border-y border-border py-5 text-sm text-muted">아직 실행된 typed operation이 없습니다.</div>
        ) : (
          <ul className="mt-5 divide-y divide-border border-y border-border">
            {activity.data.operations.map((operation) => (
              <li key={operation.operationId} className="flex min-h-16 items-center justify-between gap-4 py-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-semibold text-text">{operation.displayName}</p>
                  <p className="mt-1 truncate text-xs text-muted">
                    {operation.actor.username} · {formatDateTime(operation.recordedAt)} · {operation.operationType}
                  </p>
                </div>
                <StatusMark label={operationStageLabel(operation.terminalState)} tone={operationStageTone(operation.terminalState)} />
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function Metric({
  icon: Icon,
  label,
  value,
  detail,
  meterValue,
  meterTone = "info",
}: {
  icon: typeof Server;
  label: string;
  value: string;
  detail: string;
  meterValue?: number | null;
  meterTone?: "info" | "warning" | "danger";
}) {
  return (
    <div className="bg-surface p-4">
      <dt className="flex items-center gap-2 text-xs font-medium text-muted">
        <Icon aria-hidden="true" className="size-4" />
        {label}
      </dt>
      <dd className="mt-3 truncate text-lg font-semibold text-text">{value}</dd>
      <p className="mt-1 truncate text-xs text-muted">{detail}</p>
      {meterValue === undefined || meterValue === null ? null : (
        <progress
          className="resource-meter mt-3 w-full"
          data-tone={meterTone}
          value={meterValue}
          max={100}
          aria-label={`${label} 사용률`}
        >
          {String(Math.round(meterValue))}%
        </progress>
      )}
    </div>
  );
}

function AttentionItem({
  icon: Icon,
  title,
  description,
  tone,
  href,
}: {
  icon: typeof AlertCircle;
  title: string;
  description: string;
  tone: "warning" | "danger";
  href?: "/services";
}) {
  return (
    <div className="mt-5 flex flex-col gap-4 border-y border-border py-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex min-w-0 items-start gap-3">
        <Icon aria-hidden="true" className={tone === "danger" ? "mt-0.5 size-5 shrink-0 text-danger" : "mt-0.5 size-5 shrink-0 text-warning"} />
        <div className="min-w-0">
          <p className="text-sm font-semibold text-text">{title}</p>
          <p className="mt-1 text-sm text-muted">{description}</p>
        </div>
      </div>
      {href === undefined ? (
        <StatusMark label="확인 필요" tone={tone} />
      ) : (
        <Button asChild variant="secondary" size="compact">
          <Link to={href}>서비스 확인<ArrowRight aria-hidden="true" className="size-4" /></Link>
        </Button>
      )}
    </div>
  );
}

function usagePercent(total: number, available: number): number | null {
  if (!Number.isFinite(total) || !Number.isFinite(available) || total <= 0 || available < 0 || available > total) {
    return null;
  }
  return ((total - available) / total) * 100;
}

function usageTone(value: number | null, warning: number, danger: number): "info" | "warning" | "danger" {
  if (value === null) return "info";
  if (value >= danger) return "danger";
  if (value >= warning) return "warning";
  return "info";
}

function operationStageLabel(stage: OperationStage): string {
  const labels: Record<OperationStage, string> = {
    PLANNED: "계획됨",
    APPROVED: "승인됨",
    SNAPSHOTTED: "백업 완료",
    APPLYING: "적용 중",
    VALIDATING: "문법 검사 중",
    RELOADING: "서비스 재적용 중",
    VERIFYING: "검증 중",
    SUCCEEDED: "성공",
    ROLLING_BACK: "원복 중",
    ROLLED_BACK: "원복 완료",
    RECOVERY_REQUIRED: "복구 필요",
    REJECTED: "거부됨",
    EXPIRED: "만료됨",
    CANCELLED_BEFORE_APPLY: "적용 전 취소",
  };
  return labels[stage];
}

function operationStageTone(stage: OperationStage): StatusTone {
  if (stage === "SUCCEEDED") return "success";
  if (stage === "RECOVERY_REQUIRED" || stage === "REJECTED") return "danger";
  if (stage === "ROLLED_BACK" || stage === "ROLLING_BACK") return "warning";
  if (stage === "EXPIRED" || stage === "CANCELLED_BEFORE_APPLY") return "neutral";
  return "info";
}
