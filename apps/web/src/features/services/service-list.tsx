import { ArrowRight, ChevronDown } from "lucide-react";
import { Link } from "@tanstack/react-router";

import type { ManagedServiceAction, ServiceSummary } from "../../shared/api/types";
import { Button } from "../../shared/ui/button";
import { StatusMark } from "../../shared/ui/status-mark";
import { ServiceIcon } from "./service-icon";
import {
  aggregateServiceState,
  categoryLabel,
  serviceFamilyKey,
  stateLabel,
  stateTone,
  supportLabel,
} from "./service-presenter";

export function PrimaryServiceGrid({ services, onAction }: { services: ServiceSummary[]; onAction?: ((service: ServiceSummary, action: ManagedServiceAction) => void) | undefined }) {
  const families = Array.from(
    services.reduce<Map<string, ServiceSummary[]>>((groups, service) => {
      const key = serviceFamilyKey(service);
      const current = groups.get(key) ?? [];
      current.push(service);
      groups.set(key, current);
      return groups;
    }, new Map()),
  );
  if (families.length === 0) {
    return <p className="mt-5 border-y border-border py-5 text-sm text-muted">현재 필터에 해당하는 주요 서비스가 없습니다.</p>;
  }
  return (
    <ul className="mt-5 grid gap-3 md:grid-cols-2 2xl:grid-cols-3">
      {families.map(([key, family]) => (
        <li key={key}><ServiceFamilyCard services={family} onAction={onAction} /></li>
      ))}
    </ul>
  );
}

function ServiceFamilyCard({ services, onAction }: { services: ServiceSummary[]; onAction?: ((service: ServiceSummary, action: ManagedServiceAction) => void) | undefined }) {
  const lead = services[0];
  if (lead === undefined) return null;
  const state = aggregateServiceState(services);
  const href = lead.templateId === "nginx"
    ? "/services/nginx"
    : lead.templateId === "php-fpm"
      ? "/services/php-fpm"
    : lead.templateId === "certbot"
      ? "/certificates"
      : null;
  return (
    <details className="group h-full rounded-panel border border-border bg-surface transition-colors open:border-action/35 hover:border-action/30">
      <summary className="flex min-h-36 cursor-pointer list-none flex-col p-4 [&::-webkit-details-marker]:hidden">
        <div className="flex items-start gap-3">
          <ServiceIcon service={lead} />
          <div className="min-w-0 flex-1">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold text-text">{lead.displayName}</p>
                <p className="mt-0.5 text-xs text-muted">{categoryLabel(lead)}</p>
              </div>
              <StatusMark label={stateLabel(state)} tone={stateTone(state)} />
            </div>
          </div>
        </div>
        <p className="mt-3 line-clamp-2 text-sm leading-5 text-muted">{lead.purpose}</p>
        <div className="mt-auto flex items-center justify-between pt-3 text-xs text-muted">
          <span>{services.length === 1 ? lead.unitName : `${String(services.length)}개 unit`}</span>
          <ChevronDown aria-hidden="true" className="size-4 transition-transform duration-150 group-open:rotate-180" />
        </div>
      </summary>
      <div className="border-t border-border px-4 py-3">
        <ul className="space-y-3">
          {services.map((service) => (
            <li key={service.serviceId} className="flex min-w-0 items-center justify-between gap-3 text-xs">
              <span className="truncate font-mono text-muted">{service.unitName}</span>
              <StatusMark label={stateLabel(service.runtimeState)} tone={stateTone(service.runtimeState)} />
            </li>
          ))}
        </ul>
        <p className="mt-3 text-xs text-muted">{supportLabel(lead)}</p>
        {onAction ? services.map((service) => (
          service.allowedActions.length === 0 ? null : (
            <div key={`${service.serviceId}-actions`} className="mt-3 flex flex-wrap gap-2">
              {service.allowedActions.map((action) => (
                <Button key={action} size="compact" variant={action === "stop" ? "danger" : "secondary"} onClick={() => onAction(service, action)}>
                  {actionLabel(action)}
                </Button>
              ))}
            </div>
          )
        )) : null}
        {href !== null ? (
          <Link to={href} className="mt-3 inline-flex min-h-9 items-center gap-2 rounded-control text-sm font-semibold text-action hover:underline">
            관리 화면
            <ArrowRight aria-hidden="true" className="size-4" />
          </Link>
        ) : null}
      </div>
    </details>
  );
}

export function ServiceList({
  title,
  description,
  services,
  emptyLabel,
  onAction,
}: {
  title: string;
  description: string;
  services: ServiceSummary[];
  emptyLabel: string;
  onAction?: ((service: ServiceSummary, action: ManagedServiceAction) => void) | undefined;
}) {
  const headingId = `service-${title.replaceAll(" ", "-")}`;
  return (
    <section className="mt-6 rounded-panel border border-border bg-surface p-5" aria-labelledby={headingId}>
      <div>
        <h2 id={headingId} className="text-sm font-semibold text-text">{title}</h2>
        <p className="mt-1 text-sm text-muted">{description}</p>
      </div>
      {services.length === 0 ? (
        <p className="mt-5 border-y border-border py-5 text-sm text-muted">{emptyLabel}</p>
      ) : (
        <ul className="mt-5 grid gap-3 md:grid-cols-2 2xl:grid-cols-3">
          {services.map((service) => (
            <li key={service.serviceId} className="min-w-0 rounded-control border border-border bg-subtle/25"><ServiceRow service={service} onAction={onAction} /></li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function ServiceRow({ service, compact = false, onAction }: { service: ServiceSummary; compact?: boolean; onAction?: ((service: ServiceSummary, action: ManagedServiceAction) => void) | undefined }) {
  return (
    <details className="group">
      <summary className={compact
        ? "flex min-h-14 cursor-pointer list-none items-center gap-3 px-3 py-2 transition-colors hover:bg-subtle/70 [&::-webkit-details-marker]:hidden"
        : "flex min-h-16 cursor-pointer list-none items-center gap-3 py-3 transition-colors hover:bg-subtle/70 [&::-webkit-details-marker]:hidden"}>
        {compact ? (
          <ServiceIcon service={service} className="size-8 rounded-control [&_img]:size-5 [&_svg]:size-4" />
        ) : (
          <ServiceIcon service={service} />
        )}
        <div className="min-w-0 flex-1">
          <div className="flex min-w-0 flex-wrap items-baseline gap-x-3 gap-y-1">
            <p className="truncate text-sm font-semibold text-text">{service.displayName}</p>
            <span className="text-xs text-muted">{categoryLabel(service)}</span>
          </div>
          <p className={compact ? "mt-0.5 truncate text-xs text-muted" : "mt-1 line-clamp-2 text-sm text-muted"}>{service.purpose}</p>
        </div>
        <div className="flex shrink-0 items-center gap-3">
          <StatusMark label={stateLabel(service.runtimeState)} tone={stateTone(service.runtimeState)} />
          <ChevronDown aria-hidden="true" className="size-4 text-muted transition-transform duration-150 group-open:rotate-180" />
        </div>
      </summary>
      <dl className={compact
        ? "grid gap-3 border-t border-border bg-subtle/45 px-3 py-3 text-sm sm:grid-cols-2"
        : "grid gap-x-8 gap-y-4 border-t border-border bg-subtle/45 px-3 py-4 text-sm sm:grid-cols-2 lg:grid-cols-4"}>
        <Detail label="systemd unit" value={service.unitName} mono />
        <Detail label="자동 시작" value={unitFileLabel(service.unitFileState)} />
        <Detail label="실제 상태" value={`${service.activeState} · ${service.subState}`} mono />
        <Detail label="JW Agent 범위" value={supportLabel(service)} />
        {onAction && service.allowedActions.length > 0 ? (
          <div className="flex flex-wrap gap-2 sm:col-span-2 lg:col-span-4">
            {service.allowedActions.map((action) => (
              <Button key={action} size="compact" variant={action === "stop" ? "danger" : "secondary"} onClick={() => onAction(service, action)}>{actionLabel(action)}</Button>
            ))}
          </div>
        ) : null}
      </dl>
    </details>
  );
}

function actionLabel(action: ManagedServiceAction): string {
  if (action === "start") return "시작";
  if (action === "stop") return "중지";
  if (action === "restart") return "재시작";
  return "reload";
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
