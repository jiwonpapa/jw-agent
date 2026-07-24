import { useQuery } from "@tanstack/react-query";
import {
  Braces,
  FileCode2,
  Gauge,
  Info,
  LoaderCircle,
  PackageCheck,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import { useState } from "react";

import type { PhpFpmManagedConfigView, PhpFpmRuntimeView } from "../../shared/api/types";
import { phpFpmQueryOptions, queryKeys } from "../../shared/api/queries";
import { formatDateTime } from "../../shared/domain/format";
import { AssuranceDetails, AssuranceMark } from "../../shared/ui/assurance";
import { Button } from "../../shared/ui/button";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";
import { ManagedConfigEditor, type ManagedConfigEditorProfile } from "../managed-config/managed-config-editor";
import { useManagedConfigWorkflow, type ManagedConfigCapability } from "../managed-config/use-managed-config-workflow";
import { stateLabel, stateTone } from "../services/service-presenter";

const EDITOR_PROFILE: ManagedConfigEditorProfile = {
  language: "ini",
  contentLabel: "PHP 8.3 FPM php.ini 설정",
  validatorLabel: "php-fpm8.3 -t",
  serviceLabel: "php8.3-fpm.service",
  backLabel: "PHP-FPM 개요로 돌아가기",
};

export function PhpFpmScreen() {
  const inventory = useQuery(phpFpmQueryOptions);
  const workflow = useManagedConfigWorkflow(queryKeys.phpFpm);
  const [selectedConfig, setSelectedConfig] = useState<PhpFpmManagedConfigView | null>(null);
  const runtime = inventory.data?.runtimes[0] ?? null;

  async function openEditor(config: PhpFpmManagedConfigView): Promise<void> {
    const capability = toCapability(config);
    if (capability === null) return;
    setSelectedConfig(config);
    await workflow.open(capability);
  }

  function closeEditor(): void {
    if (
      workflow.resource !== null &&
      workflow.draft !== workflow.resource.content &&
      workflow.receipt?.terminalState !== "SUCCEEDED" &&
      !window.confirm("적용하지 않은 PHP-FPM 설정 변경이 있습니다. 편집을 종료하시겠습니까?")
    ) {
      return;
    }
    workflow.close();
    setSelectedConfig(null);
  }

  if (selectedConfig !== null) {
    const capability = toCapability(selectedConfig);
    return (
      <div className="animate-state-in">
        <WorkspaceHeader
          eyebrow="Services / Runtime / Configuration"
          title={selectedConfig.displayName}
          description="전체 화면에서 편집합니다. 저장하면 문법 검사·reload·작동 확인을 거치며 실패 시 이전 파일을 복구합니다."
        />
        <section className="my-6 min-h-[75vh] rounded-panel border border-border bg-surface p-3 sm:p-6">
          {workflow.loading ? (
            <div className="flex min-h-72 items-center justify-center gap-3 text-sm text-muted">
              <LoaderCircle aria-hidden="true" className="size-5 animate-spin" />
              설정 파일을 확인하고 있습니다.
            </div>
          ) : workflow.resource !== null && capability !== null ? (
            <ManagedConfigEditor
              profile={EDITOR_PROFILE}
              resource={workflow.resource}
              draft={workflow.draft}
              plan={workflow.plan}
              accepted={workflow.accepted}
              receipt={workflow.receipt}
              planning={workflow.planning}
              executing={workflow.executing}
              errorMessage={workflow.errorMessage}
              diagnosticLine={workflow.diagnosticLine}
              serviceAction="reload"
              onDraftChange={workflow.changeDraft}
              onBack={closeEditor}
              onSave={() => void workflow.save(capability)}
              onRevise={workflow.revise}
            />
          ) : (
            <SurfaceState
              kind="error"
              title="설정 편집기를 열 수 없습니다"
              description={workflow.errorMessage ?? "지원 조건을 다시 관찰한 뒤 시도하세요."}
            />
          )}
        </section>
      </div>
    );
  }

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Services / Runtime"
        title="PHP-FPM"
        description="실행 상태, 활성 extension과 설정 위치를 확인하고 표준 php.ini만 자동 원복 절차로 변경합니다."
        action={runtime === null ? <StatusMark label="상태 확인 중" tone="neutral" /> : <AssuranceMark assurance={runtime.assurance} />}
      />

      {inventory.isPending ? (
        <LoadingState />
      ) : inventory.isError ? (
        <SurfaceState
          kind="offline"
          title="PHP-FPM 상태를 불러오지 못했습니다"
          description="이전 관찰 값을 현재 상태처럼 대신 표시하지 않습니다."
          action={{ label: "다시 관찰", onClick: () => void inventory.refetch() }}
        />
      ) : inventory.data.status === "unsupported_platform" ? (
        <SurfaceState kind="unsupported" title="지원하지 않는 환경입니다" description="Ubuntu 24.04 apt PHP 8.3 FPM 표준 layout만 지원합니다." />
      ) : inventory.data.status === "not_installed" || runtime === null ? (
        <SurfaceState kind="empty" title="PHP-FPM이 설치되지 않았습니다" description="이 화면은 패키지를 자동 설치하지 않습니다. Ubuntu 24.04 apt PHP 8.3 FPM이 발견되면 관리 기능이 열립니다." />
      ) : (
        <RuntimeWorkspace runtime={runtime} observedAt={inventory.data.observedAt} loadingEditor={workflow.loading} onEdit={(config) => void openEditor(config)} />
      )}

    </div>
  );
}

function RuntimeWorkspace({ runtime, observedAt, loadingEditor, onEdit }: {
  runtime: PhpFpmRuntimeView;
  observedAt: string;
  loadingEditor: boolean;
  onEdit: (config: PhpFpmManagedConfigView) => void;
}) {
  return (
    <>
      <section className="mt-6 overflow-hidden rounded-panel border border-border bg-surface" aria-labelledby="php-runtime-heading">
        <div className="flex flex-col gap-5 p-5 lg:flex-row lg:items-start lg:justify-between">
          <div className="flex min-w-0 items-start gap-4">
            <div className="grid size-12 shrink-0 place-items-center rounded-control bg-subtle text-action"><Braces aria-hidden="true" className="size-6" /></div>
            <div className="min-w-0">
              <p className="text-xs font-semibold uppercase tracking-[0.16em] text-muted">Ubuntu apt runtime</p>
              <h2 id="php-runtime-heading" className="mt-1 text-xl font-semibold text-text">PHP {runtime.version} FPM</h2>
              <p className="mt-1 break-all font-mono text-xs text-muted">{runtime.unitName}</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <StatusMark label={stateLabel(runtime.runtimeState)} tone={stateTone(runtime.runtimeState)} />
            <AssuranceMark assurance={runtime.assurance} />
          </div>
        </div>

        <dl className="grid border-t border-border bg-subtle/40 sm:grid-cols-3 sm:divide-x sm:divide-border">
          <Metric icon={Gauge} label="실제 상태" value={`${runtime.activeState} · ${runtime.subState}`} />
          <Metric icon={PackageCheck} label="활성 extension" value={`${String(runtime.extensionCount)}개`} />
          <Metric icon={FileCode2} label="설정 파일" value={runtime.phpIniMaskedPath} mono />
        </dl>
      </section>

      <div className="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <section className="rounded-panel border border-border bg-surface p-5" aria-labelledby="extensions-heading">
          <div className="flex items-start justify-between gap-4">
            <div><h2 id="extensions-heading" className="text-sm font-semibold text-text">활성 extension</h2><p className="mt-1 text-sm text-muted">FPM의 conf.d에서 실제 로드 대상으로 발견된 이름입니다.</p></div>
            <StatusMark label={runtime.extensionsTruncated ? "일부 표시" : `${String(runtime.extensionCount)}개`} tone={runtime.extensionsTruncated ? "warning" : "neutral"} />
          </div>
          {runtime.extensions.length === 0 ? <p className="mt-5 text-sm text-muted">발견된 extension 설정이 없습니다.</p> : <ul className="mt-5 flex flex-wrap gap-2">{runtime.extensions.map((extension) => <li key={extension} className="rounded-control border border-border bg-subtle px-2.5 py-1.5 font-mono text-xs text-text">{extension}</li>)}</ul>}
          <dl className="mt-6 divide-y divide-border border-y border-border text-sm">
            <PathRow label="pool 설정" value={runtime.poolDirectoryMaskedPath} />
            <PathRow label="extension 설정" value={runtime.extensionDirectoryMaskedPath} />
          </dl>
        </section>

        <section className="rounded-panel border border-border bg-surface p-5" aria-labelledby="safe-edit-heading">
          <div className="flex items-start gap-3"><ShieldCheck aria-hidden="true" className="mt-0.5 size-5 text-action" /><div><h2 id="safe-edit-heading" className="text-sm font-semibold text-text">관리 설정</h2><p className="mt-1 text-sm leading-6 text-muted">파일마다 별도 snapshot·검증·reload·자동 원복을 적용합니다.</p></div></div>
          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            {runtime.managedConfigs.map((config) => (
              <article key={config.resourceId} className="rounded-control border border-border bg-subtle/45 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div><h3 className="text-sm font-semibold text-text">{config.displayName}</h3><p className="mt-1 break-all font-mono text-xs text-muted">{config.maskedPath}</p></div>
                  <AssuranceMark assurance={config.assurance} />
                </div>
                {config.available ? (
                  <Button aria-label={`${config.displayName} 편집`} className="mt-4 w-full" size="compact" disabled={loadingEditor} onClick={() => onEdit(config)}>
                    {loadingEditor ? <LoaderCircle aria-hidden="true" className="size-4 animate-spin" /> : <FileCode2 aria-hidden="true" className="size-4" />}
                    편집
                  </Button>
                ) : <BlockedReason reason={config.blockedReason} />}
              </article>
            ))}
          </div>
          <details className="mt-4"><summary className="cursor-pointer text-sm font-semibold text-action">전체 원복 범위 보기</summary><div className="mt-4"><AssuranceDetails assurance={runtime.assurance} /></div></details>
        </section>
      </div>

      <section className="mt-6 flex flex-col gap-3 rounded-panel border border-border bg-subtle/45 p-5 sm:flex-row sm:items-center sm:justify-between" aria-label="관찰 정보">
        <div className="flex items-start gap-3"><Info aria-hidden="true" className="mt-0.5 size-5 text-muted" /><div><p className="text-sm font-semibold text-text">원문 phpinfo는 제공하지 않습니다</p><p className="mt-1 text-sm text-muted">환경 변수·header·secret 노출을 피하고 운영에 필요한 version·extension·경로만 표시합니다.</p></div></div>
        <p className="shrink-0 text-xs text-muted">관찰 {formatDateTime(observedAt)}</p>
      </section>
    </>
  );
}

function Metric({ icon: Icon, label, value, mono = false }: { icon: typeof Gauge; label: string; value: string; mono?: boolean }) {
  return <div className="flex min-w-0 gap-3 p-4"><Icon aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted" /><div className="min-w-0"><dt className="text-xs text-muted">{label}</dt><dd className={mono ? "mt-1 truncate font-mono text-xs text-text" : "mt-1 font-medium text-text"}>{value}</dd></div></div>;
}

function PathRow({ label, value }: { label: string; value: string }) {
  return <div className="py-3"><dt className="text-xs text-muted">{label}</dt><dd className="mt-1 break-all font-mono text-xs text-text">{value}</dd></div>;
}

function BlockedReason({ reason }: { reason: string | null | undefined }) {
  const message = reason === "service_inactive" ? "서비스가 실행 중이 아니어서 변경이 차단되었습니다." : reason === "resource_missing" ? "표준 php.ini를 찾지 못해 변경이 차단되었습니다." : reason === "size_limit" ? "설정 파일이 지원 크기를 초과해 변경이 차단되었습니다." : "지원 layout·권한·원장 상태를 충족하지 않아 변경이 차단되었습니다.";
  return <p role="status" className="mt-5 rounded-control border border-warning/35 bg-warning/5 p-3 text-sm leading-6 text-muted">{message}</p>;
}

function toCapability(config: PhpFpmManagedConfigView): ManagedConfigCapability | null {
  if (!config.available || !config.assurance.operationAvailable || config.assurance.level !== "g2_reversible_config" || config.operationType !== "service.config_file.set/v1") return null;
  return { resourceId: config.resourceId, operationType: config.operationType, schemaVersion: config.schemaVersion };
}

function LoadingState() {
  return <div className="space-y-6 py-6" aria-label="PHP-FPM 상태 불러오는 중"><Skeleton className="h-44 w-full" /><div className="grid gap-6 xl:grid-cols-2"><Skeleton className="h-72 w-full" /><Skeleton className="h-72 w-full" /></div><div className="flex items-center gap-2 text-sm text-muted"><RefreshCw aria-hidden="true" className="size-4 animate-spin" />실제 package·unit·설정 layout을 확인하고 있습니다.</div></div>;
}
