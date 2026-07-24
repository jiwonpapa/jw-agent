import { useQuery } from "@tanstack/react-query";
import {
  FileCode2,
  Folder,
  LoaderCircle,
  LockKeyhole,
  Search,
} from "lucide-react";
import { useMemo, useState } from "react";

import type { ManagedServiceConfigView } from "../../shared/api/types";
import {
  queryKeys,
  serviceConfigurationsQueryOptions,
} from "../../shared/api/queries";
import { formatDateTime } from "../../shared/domain/format";
import { Button } from "../../shared/ui/button";
import { cn } from "../../shared/ui/cn";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";
import {
  ManagedConfigEditor,
  type ManagedConfigEditorProfile,
} from "../managed-config/managed-config-editor";
import {
  type ManagedConfigCapability,
  useManagedConfigWorkflow,
} from "../managed-config/use-managed-config-workflow";

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
  const [search, setSearch] = useState("");
  const profile: ManagedConfigEditorProfile = {
    language,
    contentLabel: `${title} 설정 내용`,
    validatorLabel,
    serviceLabel: unitName,
    backLabel: `${title} 설정 파일 선택으로 돌아가기`,
  };
  const configs = useMemo(() => inventory.data?.configs ?? [], [inventory.data?.configs]);
  const filtered = useMemo(() => {
    const needle = search.trim().toLocaleLowerCase();
    if (needle === "") return configs;
    return configs.filter((config) =>
      `${config.displayName} ${config.relativePath}`.toLocaleLowerCase().includes(needle),
    );
  }, [configs, search]);

  async function openEditor(config: ManagedServiceConfigView): Promise<void> {
    if (!config.available) return;
    setSelected(config);
    await workflow.open(toCapability(config));
  }

  function closeEditor(): void {
    if (
      workflow.resource !== null &&
      workflow.draft !== workflow.resource.content &&
      workflow.receipt?.terminalState !== "SUCCEEDED" &&
      !window.confirm("저장하지 않은 설정 변경이 있습니다. 파일 선택으로 돌아가시겠습니까?")
    ) {
      return;
    }
    workflow.close();
    setSelected(null);
  }

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Services / Web server"
        title={`${title} 설정`}
        description={`${rootLabel(serviceKey)} 아래 기존 설정 파일을 선택해 편집합니다. 저장하면 서버가 문법 검사와 필요한 반영·자동 복구를 처리합니다.`}
        action={
          inventory.data ? (
            <div className="text-left sm:text-right">
              <p className="text-xs text-muted">마지막 관찰</p>
              <p className="mt-1 text-sm font-medium text-text">
                {formatDateTime(inventory.data.observedAt)}
              </p>
            </div>
          ) : null
        }
      />

      {inventory.isPending ? (
        <div className="grid gap-4 py-6 lg:grid-cols-[20rem_minmax(0,1fr)]">
          <Skeleton className="h-[70vh] w-full" />
          <Skeleton className="h-[70vh] w-full" />
        </div>
      ) : inventory.isError ? (
        <SurfaceState
          kind="offline"
          title={`${title} 설정을 불러오지 못했습니다`}
          description="이전 목록을 현재 상태처럼 표시하지 않습니다."
          action={{ label: "다시 관찰", onClick: () => void inventory.refetch() }}
        />
      ) : inventory.data.status === "not_installed" ? (
        <SurfaceState
          kind="empty"
          title={`${title}이 설치되지 않았습니다`}
          description={`${unitName}이 발견되면 설정 파일 트리를 표시합니다.`}
        />
      ) : inventory.data.status === "unsupported_platform" ? (
        <SurfaceState
          kind="unsupported"
          title="지원하지 않는 환경입니다"
          description="Ubuntu 24.04 표준 패키지 layout만 지원합니다."
        />
      ) : (
        <section
          className="my-6 grid min-h-[72vh] overflow-hidden rounded-panel border border-border bg-surface lg:grid-cols-[20rem_minmax(0,1fr)]"
          aria-label={`${title} 설정 workspace`}
        >
          <aside className="border-b border-border bg-subtle/30 lg:border-b-0 lg:border-r">
            <div className="border-b border-border p-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h2 className="text-sm font-semibold text-text">설정 파일</h2>
                  <p className="mt-1 text-xs text-muted">
                    {String(configs.length)}개 · {inventory.data.truncated ? "일부 표시" : "전체 표시"}
                  </p>
                </div>
                <StatusMark
                  label={inventory.data.configs.some((config) => config.serviceActive) ? "실행 중" : "중지"}
                  tone={inventory.data.configs.some((config) => config.serviceActive) ? "success" : "neutral"}
                />
              </div>
              <label className="mt-4 flex items-center gap-2 rounded-control border border-border bg-surface px-3 py-2">
                <Search aria-hidden="true" className="size-4 text-muted" />
                <span className="sr-only">설정 파일 검색</span>
                <input
                  className="min-w-0 flex-1 bg-transparent text-sm text-text outline-none placeholder:text-muted"
                  value={search}
                  placeholder="파일명 또는 경로 검색"
                  onChange={(event) => setSearch(event.currentTarget.value)}
                />
              </label>
            </div>
            <ConfigTree
              configs={filtered}
              selectedId={selected?.resourceId ?? null}
              loadingId={workflow.loading ? selected?.resourceId ?? null : null}
              onSelect={(config) => void openEditor(config)}
            />
          </aside>

          <main className="min-w-0 bg-canvas p-3 sm:p-5">
            {workflow.loading ? (
              <div className="flex min-h-72 items-center justify-center gap-3 text-sm text-muted">
                <LoaderCircle aria-hidden="true" className="size-5 animate-spin" />
                설정 파일을 확인하고 있습니다.
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
                serviceAction={selected.serviceActive ? "reload" : "validate_only"}
                onDraftChange={workflow.changeDraft}
                onBack={closeEditor}
                onSave={() => void workflow.save(toCapability(selected))}
                onRevise={workflow.revise}
              />
            ) : (
              <div className="grid min-h-[60vh] place-items-center">
                <SurfaceState
                  kind="empty"
                  title="편집할 설정 파일을 선택하세요"
                  description="왼쪽 파일 트리에서 파일을 선택하면 이 공간 전체에서 편집할 수 있습니다."
                />
              </div>
            )}
          </main>
        </section>
      )}
    </div>
  );
}

function ConfigTree({
  configs,
  selectedId,
  loadingId,
  onSelect,
}: {
  configs: ManagedServiceConfigView[];
  selectedId: string | null;
  loadingId: string | null;
  onSelect: (config: ManagedServiceConfigView) => void;
}) {
  const groups = groupByDirectory(configs);
  if (configs.length === 0) {
    return <p className="p-4 text-sm text-muted">조건에 맞는 설정 파일이 없습니다.</p>;
  }
  return (
    <div className="max-h-[64vh] overflow-auto p-2 lg:max-h-[72vh]">
      {groups.map((group) => (
        <section key={group.directory} className="mb-2">
          <div className="flex items-center gap-2 px-2 py-1.5 text-xs font-semibold text-muted">
            <Folder aria-hidden="true" className="size-3.5" />
            <span className="truncate">{group.directory}</span>
          </div>
          <ul>
            {group.configs.map((config) => {
              const active = selectedId === config.resourceId;
              return (
                <li key={config.resourceId}>
                  <Button
                    className={cn(
                      "h-auto w-full justify-start gap-2 px-2 py-2 text-left",
                      active && "bg-action/10 text-action",
                    )}
                    variant="ghost"
                    disabled={!config.available || loadingId !== null}
                    title={config.available ? config.maskedPath : blockedReason(config.blockedReason)}
                    onClick={() => onSelect(config)}
                  >
                    {loadingId === config.resourceId ? (
                      <LoaderCircle aria-hidden="true" className="size-4 shrink-0 animate-spin" />
                    ) : config.available ? (
                      <FileCode2 aria-hidden="true" className="size-4 shrink-0" />
                    ) : (
                      <LockKeyhole aria-hidden="true" className="size-4 shrink-0 text-warning" />
                    )}
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium">{config.displayName}</span>
                      <span className="mt-0.5 block truncate text-[11px] text-muted">
                        {config.loaded ? "현재 적용 경로" : config.available ? "현재 미적용" : blockedReason(config.blockedReason)}
                      </span>
                    </span>
                  </Button>
                </li>
              );
            })}
          </ul>
        </section>
      ))}
    </div>
  );
}

function groupByDirectory(configs: ManagedServiceConfigView[]) {
  const groups = new Map<string, ManagedServiceConfigView[]>();
  for (const config of configs) {
    const separator = config.relativePath.lastIndexOf("/");
    const directory = separator === -1 ? "/" : config.relativePath.slice(0, separator);
    const current = groups.get(directory) ?? [];
    current.push(config);
    groups.set(directory, current);
  }
  return [...groups.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([directory, entries]) => ({
      directory,
      configs: entries.sort((left, right) => left.displayName.localeCompare(right.displayName)),
    }));
}

function toCapability(config: ManagedServiceConfigView): ManagedConfigCapability {
  return {
    resourceId: config.resourceId,
    operationType: config.operationType,
    schemaVersion: config.schemaVersion,
    serviceAction: config.serviceActive ? "reload" : "validate_only",
  };
}

function rootLabel(serviceKey: "nginx" | "apache"): string {
  return serviceKey === "nginx" ? "/etc/nginx" : "/etc/apache2";
}

function blockedReason(reason: string | null | undefined): string {
  if (reason === "protected_resource") return "비밀값 또는 개인키 후보라 편집할 수 없습니다.";
  if (reason === "resource_missing") return "파일이 사라져 다시 관찰해야 합니다.";
  if (reason === "size_limit") return "지원 크기를 초과했습니다.";
  if (reason === "invalid_encoding") return "UTF-8 텍스트 설정 파일이 아닙니다.";
  return "소유권·권한·경로 안전 조건을 충족하지 않습니다.";
}
