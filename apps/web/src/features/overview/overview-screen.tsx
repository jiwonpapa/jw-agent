import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  Clock3,
  Cpu,
  HardDrive,
  MemoryStick,
  RotateCcw,
  Server,
  SlidersHorizontal,
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
import { OBSERVATION_LABELS } from "../../shared/content/copy";
import { formatBytes, formatDateTime, formatDuration } from "../../shared/domain/format";
import { AssuranceMark } from "../../shared/ui/assurance";
import { Button } from "../../shared/ui/button";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark, type StatusTone } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";
import { SessionAccessPanel } from "../auth/administrative-access";
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
        <div className="mt-6"><SessionAccessPanel session={session} observedAt={host.data?.observedAt} /></div>
      )}

      <section className="mt-6 rounded-panel border border-border bg-surface p-5" aria-labelledby="identity-heading">
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
            {Array.from({ length: 5 }).map((_, index) => (
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
          <dl className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
            <Metric
              icon={Server}
              label="호스트"
              value={host.data.hostname ?? "알 수 없음"}
              detail={host.data.osPrettyName ?? host.data.osId ?? "OS 정보 없음"}
            />
            <Metric
              icon={Cpu}
              label="CPU"
              value={host.data.cpuUsagePercent == null ? "알 수 없음" : `${String(Math.round(host.data.cpuUsagePercent))}% 사용`}
              detail={host.data.logicalCpuCount == null
                ? "논리 CPU 수 없음"
                : `${String(host.data.logicalCpuCount)} vCPU · 1분 부하 ${host.data.loadAverageOne?.toFixed(2) ?? "없음"}`}
              meterValue={host.data.cpuUsagePercent ?? null}
              meterTone={usageTone(host.data.cpuUsagePercent ?? null, 80, 95)}
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
                host.data.kernelRelease ?? "커널 정보 없음"
              }
            />
          </dl>
        )}
      </section>

      <section className="mt-6 rounded-panel border border-border bg-surface p-5" aria-labelledby="attention-heading">
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
        ) : host.data.status === "unsupported_platform" ? (
          <div className="mt-5">
            <SurfaceState
              kind="unsupported"
              title="지원하지 않는 플랫폼입니다"
              description="Ubuntu 24.04 LTS 지원 프로필과 일치하지 않아 변경 기능을 제공하지 않습니다."
            />
          </div>
        ) : (
          <AttentionQueue
            partial={host.data.status === "partial"}
            cpuUsage={host.data.cpuUsagePercent ?? null}
            memoryUsage={memoryUsage}
            diskUsage={diskUsage}
            failedServices={failedServices.map((service) => service.displayName)}
          />
        )}
      </section>

      <ServiceOverview />

      <section className="mt-6 rounded-panel border border-border bg-surface p-5" aria-labelledby="nginx-heading">
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
          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            {nginx.data.sites.slice(0, 4).map((site) => (
              <div key={site.name} className="flex min-h-16 items-center justify-between gap-4 rounded-control border border-border bg-subtle/35 p-3">
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

      <section className="mt-6 rounded-panel border border-border bg-surface p-5" aria-labelledby="ledger-heading">
        <div className="flex items-center gap-3">
          <Clock3 aria-hidden="true" className="size-5 text-muted" />
          <div>
            <h2 id="ledger-heading" className="text-sm font-semibold text-text">
              최근 작업
            </h2>
            <p className="mt-1 text-sm text-muted">현재 Linux 계정이 실행한 typed operation의 최신 결과입니다.</p>
          </div>
        </div>
        <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="지원되는 관리 작업">
          <ActionLink to="/services/nginx" title="웹 서버 설정" description="Nginx site 상태·설정 파일" />
          <ActionLink to="/services/php-fpm" title="PHP runtime 설정" description="php.ini·문법 검사" />
          <ActionLink to="/certificates" title="TLS 수명 주기" description="인증서 발급·연결·갱신 시험" />
          <ActionLink to="/files" title="파일 안전 업로드" description="SFTP 홈 조회·원자적 업로드" />
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
          <ul className="mt-5 grid gap-3 lg:grid-cols-2">
            {activity.data.operations.map((operation) => (
              <li key={operation.operationId} className="min-w-0 rounded-control border border-border bg-subtle/30">
                <details className="group">
                  <summary className="flex min-h-20 cursor-pointer list-none items-center justify-between gap-4 p-4 [&::-webkit-details-marker]:hidden">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-semibold text-text">{operation.displayName}</p>
                      <p className="mt-1 truncate text-xs text-muted">
                        {operation.actor.username} · {formatDateTime(operation.recordedAt)}
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-3">
                      <StatusMark label={operationStageLabel(operation.terminalState)} tone={operationStageTone(operation.terminalState)} />
                      <ChevronDown aria-hidden="true" className="size-4 text-muted transition-transform group-open:rotate-180" />
                    </div>
                  </summary>
                  <div className="border-t border-border p-4 text-xs text-muted">
                    <dl className="grid gap-3 sm:grid-cols-2">
                      <OperationField label="작업 유형" value={operation.operationType} mono />
                      <OperationField label="작업 ID" value={operation.operationId} mono />
                      <OperationField label="변경 전 digest" value={operation.beforeDigest} mono />
                      <OperationField label="변경 후 digest" value={operation.afterDigest} mono />
                    </dl>
                    <ol className="mt-4 space-y-2 border-l border-border pl-4">
                      {operation.stages.map((stage) => (
                        <li key={stage.sequence} className="flex items-center justify-between gap-3">
                          <span>{operationStageLabel(stage.stage)} · {stage.resultCode}</span>
                          <time className="shrink-0">{formatDateTime(stage.recordedAt)}</time>
                        </li>
                      ))}
                    </ol>
                    {operation.rollbackResult ? (
                      <p className="mt-4 flex items-center gap-2 text-warning"><RotateCcw aria-hidden="true" className="size-4" />원복 결과: {operation.rollbackResult}</p>
                    ) : null}
                  </div>
                </details>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function ActionLink({ to, title, description }: {
  to: "/services/nginx" | "/services/php-fpm" | "/certificates" | "/files";
  title: string;
  description: string;
}) {
  return (
    <Link to={to} aria-label={`${title} 관리 화면`} className="group flex min-h-20 items-center gap-3 rounded-control border border-border bg-subtle/30 p-3 transition-colors hover:border-action/40 hover:bg-action/5">
      <span className="grid size-9 shrink-0 place-items-center rounded-control bg-surface text-action ring-1 ring-border"><SlidersHorizontal aria-hidden="true" className="size-4" /></span>
      <span className="min-w-0 flex-1"><span className="block text-sm font-semibold text-text">{title}</span><span className="mt-1 block truncate text-xs text-muted">{description}</span></span>
      <ArrowRight aria-hidden="true" className="size-4 shrink-0 text-muted transition-transform group-hover:translate-x-0.5 group-hover:text-action" />
    </Link>
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
    <div className="min-w-0 rounded-control border border-border bg-subtle/35 p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <dt className="flex items-center gap-2 text-xs font-medium text-muted">
            <Icon aria-hidden="true" className="size-4" />
            {label}
          </dt>
          <dd className="mt-3 truncate text-lg font-semibold text-text">{value}</dd>
          <p className="mt-1 truncate text-xs text-muted">{detail}</p>
        </div>
        {meterValue === undefined || meterValue === null ? null : <ResourceRing value={meterValue} tone={meterTone} label={label} />}
      </div>
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

function ResourceRing({ value, tone, label }: { value: number; tone: "info" | "warning" | "danger"; label: string }) {
  const bounded = Math.min(100, Math.max(0, value));
  const circumference = 2 * Math.PI * 18;
  const color = tone === "danger" ? "text-danger" : tone === "warning" ? "text-warning" : "text-info";
  return (
    <div className="relative grid size-12 shrink-0 place-items-center" role="img" aria-label={`${label} ${String(Math.round(bounded))}%`}>
      <svg viewBox="0 0 44 44" className="size-12 -rotate-90" aria-hidden="true">
        <circle cx="22" cy="22" r="18" fill="none" stroke="currentColor" strokeWidth="4" className="text-border" />
        <circle cx="22" cy="22" r="18" fill="none" stroke="currentColor" strokeWidth="4" strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={circumference * (1 - bounded / 100)} className={color} />
      </svg>
      <span className="absolute text-[0.625rem] font-semibold text-text">{Math.round(bounded)}%</span>
    </div>
  );
}

function AttentionQueue({ partial, cpuUsage, memoryUsage, diskUsage, failedServices }: {
  partial: boolean;
  cpuUsage: number | null;
  memoryUsage: number | null;
  diskUsage: number | null;
  failedServices: string[];
}) {
  const issues = [
    partial ? { icon: AlertCircle, title: "일부 호스트 정보가 누락됨", description: "원인: 관찰 파일을 읽지 못했습니다. 영향: 누락값을 정상으로 판정할 수 없습니다. 조치: 호스트 상태를 다시 관찰하세요.", tone: "warning" as const } : null,
    diskUsage !== null && diskUsage >= 80 ? { icon: HardDrive, title: `루트 디스크 ${String(Math.round(diskUsage))}% 사용`, description: diskUsage >= 90 ? "영향: 로그·DB 쓰기 실패로 서비스가 중단될 수 있습니다. 조치: 로그·백업·임시파일 증가 원인을 즉시 확인하세요." : "영향: 여유 공간 감소가 진행 중입니다. 조치: 증가 원인을 확인하고 90% 전에 정리하세요.", tone: diskUsage >= 90 ? "danger" as const : "warning" as const } : null,
    memoryUsage !== null && memoryUsage >= 88 ? { icon: MemoryStick, title: `메모리 ${String(Math.round(memoryUsage))}% 사용`, description: "영향: swap 증가 또는 OOM 종료 가능성이 있습니다. 조치: 사용량이 큰 프로세스와 최근 부하를 확인하세요.", tone: memoryUsage >= 96 ? "danger" as const : "warning" as const } : null,
    cpuUsage !== null && cpuUsage >= 80 ? { icon: Cpu, title: `CPU ${String(Math.round(cpuUsage))}% 사용`, description: "영향: 요청 지연과 timeout이 발생할 수 있습니다. 조치: 터미널에서 상위 프로세스와 트래픽 급증 여부를 확인하세요.", tone: cpuUsage >= 95 ? "danger" as const : "warning" as const } : null,
    failedServices.length > 0 ? { icon: AlertCircle, title: `실패한 서비스 ${String(failedServices.length)}개`, description: `영향: ${failedServices.slice(0, 3).join(" · ")} 기능이 중단됐을 수 있습니다. 조치: 서비스 상세에서 실제 unit 상태를 확인하세요.`, tone: "danger" as const, href: "/services" as const } : null,
  ].filter((issue) => issue !== null);
  if (issues.length === 0) {
    return <div className="mt-5 flex items-center gap-2 rounded-control border border-success/25 bg-success/5 p-4 text-sm text-muted"><CheckCircle2 aria-hidden="true" className="size-4 text-success" />현재 관찰 기준으로 즉시 조치할 문제가 없습니다.</div>;
  }
  return <div className="mt-5 grid gap-3 lg:grid-cols-2">{issues.map((issue) => <AttentionItem key={issue.title} {...issue} />)}</div>;
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
    <div className="flex min-w-0 flex-col gap-4 rounded-control border border-border bg-subtle/35 p-4 sm:flex-row sm:items-center sm:justify-between">
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

function OperationField({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <div className="min-w-0"><dt>{label}</dt><dd className={mono ? "mt-1 truncate font-mono text-text" : "mt-1 text-text"}>{value}</dd></div>;
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
