import type { ServiceRuntimeState, ServiceSummary } from "../../shared/api/types";
import {
  SERVICE_CATEGORY_LABELS,
  SERVICE_STATE_LABELS,
  SERVICE_SUPPORT_LABELS,
} from "../../shared/content/copy";
import type { StatusTone } from "../../shared/ui/status-mark";

export type ServiceFilter = "all" | "running" | "failed" | "stopped";

export const SERVICE_FILTERS: ReadonlyArray<{ value: ServiceFilter; label: string }> = [
  { value: "all", label: "전체" },
  { value: "running", label: "실행" },
  { value: "failed", label: "실패" },
  { value: "stopped", label: "중지" },
];

export function stateLabel(state: ServiceRuntimeState): string {
  return SERVICE_STATE_LABELS[state];
}

export function stateTone(state: ServiceRuntimeState): StatusTone {
  if (state === "running" || state === "active") return "success";
  if (state === "failed") return "danger";
  if (state === "transitioning") return "warning";
  if (state === "unknown") return "stale";
  return "neutral";
}

export function categoryLabel(service: ServiceSummary): string {
  return SERVICE_CATEGORY_LABELS[service.category];
}

export function supportLabel(service: ServiceSummary): string {
  return SERVICE_SUPPORT_LABELS[service.support];
}

export function matchesFilter(service: ServiceSummary, filter: ServiceFilter): boolean {
  if (filter === "all") return true;
  if (filter === "running") {
    return service.runtimeState === "running" || service.runtimeState === "active";
  }
  return service.runtimeState === filter;
}
