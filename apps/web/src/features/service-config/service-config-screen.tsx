import { useQuery } from "@tanstack/react-query";
import { FileCode2, LoaderCircle, Pencil, ShieldCheck } from "lucide-react";
import { useState } from "react";

import type { ManagedServiceConfigView } from "../../shared/api/types";
import {
  queryKeys,
  serviceConfigurationsQueryOptions,
} from "../../shared/api/queries";
import { formatDateTime } from "../../shared/domain/format";
import { Button } from "../../shared/ui/button";
import { Sheet } from "../../shared/ui/sheet";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";
import {
  ManagedConfigEditor,
  type ManagedConfigEditorProfile,
} from "../managed-config/managed-config-editor";
import { useManagedConfigWorkflow } from "../managed-config/use-managed-config-workflow";

interface ServiceConfigScreenProps {
  serviceKey: "nginx" | "apache";
  title: string;
  unitName: string;
  validatorLabel: string;
  language: ManagedConfigEditorProfile["language"];
}

export function ServiceConfigScreen({
  serviceKey,
  title,
  unitName,
  validatorLabel,
  language,
}: ServiceConfigScreenProps) {
  const inventory = useQuery(serviceConfigurationsQueryOptions(serviceKey));
  const workflow = useManagedConfigWorkflow(queryKeys.serviceConfigurations(serviceKey));
  const [selected, setSelected] = useState<ManagedServiceConfigView | null>(null);
  const editorOpen = selected !== null;
  const profile: ManagedConfigEditorProfile = {
    language,
    contentLabel: `${title} 설정 내용`,
    validatorLabel,
    serviceLabel: unitName,
    backLabel: `${title} 설정 목록으로 돌아가기`,
  };

  async function openEditor(config: ManagedServiceConfigView): Promise<void> {
    if (!config.available) return;
    setSelected(config);
    await workflow.open({
      resourceId: config.resourceId,
      operationType: config.operationType,
      schemaVersion: config.schemaVersion,
    });
  }

  function closeEditor(): void {
    if (workflow.accepted !== null) return;
    workflow.close();
    setSelected(null);
  }

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Services / Web server"
        title={`${title} 설정`}
        description="실제로 적용되는 표준 설정만 편집합니다. 저장하면 문법 검사·reload·상태 확인을 수행하고 실패하면 이전 파일을 복구합니다."
        action={
          inventory.data ? (
            <div className="text-left sm:text-right">
              <p className="text-xs text-muted">마지막 관찰</p>
              <p className="mt-1 text-sm font-medium text-text">{formatDateTime(inventory.data.observedAt)}</p>
            </div>
          ) : null
        }
      />

      {inventory.isPending ? (
        <div className="grid gap-3 py-6 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 5 }).map((_, index) => <Skeleton key={index} className="h-36 w-full" />)}
        </div>
      ) : inventory.isError ? (
        <SurfaceState
          kind="offline"
          title={`${title} 설정을 불러오지 못했습니다`}
          description="이전 목록을 현재 상태처럼 표시하지 않습니다."
          action={{ label: "다시 관찰", onClick: () => void inventory.refetch() }}
        />
      ) : inventory.data.status === "not_installed" ? (
        <SurfaceState kind="empty" title={`${title}이 설치되지 않았습니다`} description={`${unitName}이 발견되면 관리 가능한 설정을 표시합니다.`} />
      ) : inventory.data.status === "unsupported_platform" ? (
        <SurfaceState kind="unsupported" title="지원하지 않는 환경입니다" description="Ubuntu 24.04 표준 패키지 layout만 지원합니다." />
      ) : (
        <section className="py-6" aria-labelledby="managed-configs-heading">
          <div className="rounded-panel border border-border bg-surface p-5">
            <div className="flex items-start gap-3">
              <ShieldCheck aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-action" />
              <div>
                <h2 id="managed-configs-heading" className="text-sm font-semibold text-text">적용되는 설정 파일</h2>
                <p className="mt-1 text-sm leading-6 text-muted">비활성 설정과 임의 경로는 편집 버튼을 열지 않습니다.</p>
              </div>
            </div>
            {inventory.data.configs.length === 0 ? (
              <p className="mt-5 border-t border-border pt-5 text-sm text-muted">관리 가능한 설정 파일이 없습니다.</p>
            ) : (
              <ul className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {inventory.data.configs.map((config) => (
                  <li key={config.resourceId} className="flex min-h-36 flex-col rounded-control border border-border bg-subtle/25 p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex min-w-0 items-start gap-3">
                        <span className="grid size-9 shrink-0 place-items-center rounded-control bg-surface text-action">
                          <FileCode2 aria-hidden="true" className="size-4" />
                        </span>
                        <div className="min-w-0">
                          <h3 className="truncate text-sm font-semibold text-text">{config.displayName}</h3>
                          <p className="mt-1 truncate font-mono text-xs text-muted">{config.maskedPath}</p>
                        </div>
                      </div>
                      <StatusMark label={config.available ? "편집 가능" : "변경 차단"} tone={config.available ? "success" : "warning"} />
                    </div>
                    <p className="mt-3 text-xs leading-5 text-muted">
                      {config.available ? `${validatorLabel} 후 ${unitName} reload` : blockedReason(config.blockedReason)}
                    </p>
                    <Button
                      className="mt-auto self-start"
                      size="compact"
                      variant="secondary"
                      disabled={!config.available || workflow.loading}
                      onClick={() => void openEditor(config)}
                    >
                      {workflow.loading && selected?.resourceId === config.resourceId
                        ? <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />
                        : <Pencil aria-hidden="true" className="size-4" />}
                      편집
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>
      )}

      <Sheet
        open={editorOpen}
        onOpenChange={(open) => { if (!open) closeEditor(); }}
        title={selected?.displayName ?? `${title} 설정`}
        description="저장 → 문법 검사 → reload → 실패 시 자동 복구"
        side="right"
        size="fullscreen"
      >
        {workflow.loading ? (
          <div className="flex items-center gap-3 text-sm text-muted">
            <LoaderCircle aria-hidden="true" className="size-5 animate-spin" />
            설정과 안전 조건을 확인하고 있습니다.
          </div>
        ) : workflow.resource !== null && selected !== null ? (
          <ManagedConfigEditor
            profile={profile}
            resource={workflow.resource}
            draft={workflow.draft}
            plan={workflow.plan}
            accepted={workflow.accepted}
            receipt={workflow.receipt}
            planning={workflow.planning}
            executing={workflow.executing}
            errorMessage={workflow.errorMessage}
            diagnosticLine={workflow.diagnosticLine}
            onDraftChange={workflow.changeDraft}
            onBack={closeEditor}
            onSave={() => void workflow.save({
              resourceId: selected.resourceId,
              operationType: selected.operationType,
              schemaVersion: selected.schemaVersion,
            })}
            onRevise={workflow.revise}
          />
        ) : (
          <SurfaceState kind="error" title="설정 편집기를 열 수 없습니다" description={workflow.errorMessage ?? "설정 목록을 다시 관찰해 주세요."} />
        )}
      </Sheet>
    </div>
  );
}

function blockedReason(reason: string | null | undefined): string {
  if (reason === "service_inactive") return "서비스가 중지되어 있어 자동 검증·reload를 수행할 수 없습니다.";
  if (reason === "resource_not_active" || reason === "include_not_active") return "현재 서비스가 읽는 설정이 아니어서 변경을 차단했습니다.";
  if (reason === "resource_missing") return "표준 설정 파일이 없습니다.";
  return "파일 형식·소유권·경로가 안전 조건을 충족하지 않습니다.";
}
