import { ChevronDown } from "lucide-react";

import type { ServiceSummary } from "../../shared/api/types";
import { StatusMark } from "../../shared/ui/status-mark";
import { categoryLabel, stateLabel, stateTone, supportLabel } from "./service-presenter";

export function ServiceList({
  title,
  description,
  services,
  emptyLabel,
}: {
  title: string;
  description: string;
  services: ServiceSummary[];
  emptyLabel: string;
}) {
  const headingId = `service-${title.replaceAll(" ", "-")}`;
  return (
    <section className="border-t border-border py-7" aria-labelledby={headingId}>
      <div>
        <h2 id={headingId} className="text-sm font-semibold text-text">{title}</h2>
        <p className="mt-1 text-sm text-muted">{description}</p>
      </div>
      {services.length === 0 ? (
        <p className="mt-5 border-y border-border py-5 text-sm text-muted">{emptyLabel}</p>
      ) : (
        <ul className="mt-5 divide-y divide-border border-y border-border">
          {services.map((service) => (
            <li key={service.serviceId}><ServiceRow service={service} /></li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function ServiceRow({ service }: { service: ServiceSummary }) {
  return (
    <details className="group">
      <summary className="flex min-h-16 cursor-pointer list-none items-center gap-3 py-3 transition-colors hover:bg-subtle/70 [&::-webkit-details-marker]:hidden">
        <div className="min-w-0 flex-1">
          <div className="flex min-w-0 flex-wrap items-baseline gap-x-3 gap-y-1">
            <p className="truncate text-sm font-semibold text-text">{service.displayName}</p>
            <span className="text-xs text-muted">{categoryLabel(service)}</span>
          </div>
          <p className="mt-1 line-clamp-2 text-sm text-muted">{service.purpose}</p>
        </div>
        <div className="flex shrink-0 items-center gap-3">
          <StatusMark label={stateLabel(service.runtimeState)} tone={stateTone(service.runtimeState)} />
          <ChevronDown aria-hidden="true" className="size-4 text-muted transition-transform duration-150 group-open:rotate-180" />
        </div>
      </summary>
      <dl className="grid gap-x-8 gap-y-4 border-t border-border bg-subtle/45 px-3 py-4 text-sm sm:grid-cols-2 lg:grid-cols-4">
        <Detail label="systemd unit" value={service.unitName} mono />
        <Detail label="자동 시작" value={unitFileLabel(service.unitFileState)} />
        <Detail label="실제 상태" value={`${service.activeState} · ${service.subState}`} mono />
        <Detail label="JW Agent 범위" value={supportLabel(service)} />
      </dl>
    </details>
  );
}

function Detail({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted">{label}</dt>
      <dd className={mono ? "mt-1 break-words font-mono text-xs text-text" : "mt-1 break-words text-sm text-text"}>{value}</dd>
    </div>
  );
}

function unitFileLabel(value: string | null | undefined): string {
  if (value === "enabled" || value === "enabled-runtime") return "부팅 시 시작";
  if (value === "disabled") return "자동 시작 꺼짐";
  if (value === "masked") return "실행 차단(masked)";
  if (value === "static") return "다른 unit에서 호출";
  return value ?? "확인되지 않음";
}
