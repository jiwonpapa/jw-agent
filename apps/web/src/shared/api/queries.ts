import { queryOptions } from "@tanstack/react-query";

import {
  getAccessSettings,
  getCertificates,
  getFileCapability,
  getHealth,
  getHost,
  getIntegrations,
  getNginxSites,
  getServiceConfigurations,
  getPhpFpm,
  getRecentOperations,
  getSession,
  getServices,
  getTerminalCapability,
  getUfw,
} from "./client";

export const queryKeys = {
  health: ["health"] as const,
  session: ["session"] as const,
  host: ["host"] as const,
  services: ["services"] as const,
  activity: ["activity"] as const,
  nginxSites: ["services", "nginx", "sites"] as const,
  serviceConfigurations: (serviceKey: "nginx" | "apache") =>
    ["services", serviceKey, "configurations"] as const,
  phpFpm: ["services", "php-fpm"] as const,
  certificates: ["certificates"] as const,
  integrations: ["integrations"] as const,
  accessSettings: ["settings", "access"] as const,
  terminal: ["terminal", "capability"] as const,
  files: ["files", "capability"] as const,
  ufw: ["firewall", "ufw"] as const,
};

export const healthQueryOptions = queryOptions({
  queryKey: queryKeys.health,
  queryFn: ({ signal }) => getHealth(signal),
  staleTime: 30_000,
  retry: 1,
});

export const sessionQueryOptions = queryOptions({
  queryKey: queryKeys.session,
  queryFn: ({ signal }) => getSession(signal),
  staleTime: 15_000,
  retry: false,
});

export const hostQueryOptions = queryOptions({
  queryKey: queryKeys.host,
  queryFn: ({ signal }) => getHost(signal),
  staleTime: 15_000,
  retry: 1,
});

export const servicesQueryOptions = queryOptions({
  queryKey: queryKeys.services,
  queryFn: ({ signal }) => getServices(signal),
  staleTime: 15_000,
  retry: 1,
});

export const activityQueryOptions = queryOptions({
  queryKey: queryKeys.activity,
  queryFn: ({ signal }) => getRecentOperations(signal),
  staleTime: 10_000,
  retry: 1,
});

export const nginxSitesQueryOptions = queryOptions({
  queryKey: queryKeys.nginxSites,
  queryFn: ({ signal }) => getNginxSites(signal),
  staleTime: 15_000,
  retry: 1,
});

export function serviceConfigurationsQueryOptions(serviceKey: "nginx" | "apache") {
  return queryOptions({
    queryKey: queryKeys.serviceConfigurations(serviceKey),
    queryFn: ({ signal }) => getServiceConfigurations(serviceKey, signal),
    staleTime: 15_000,
    retry: 1,
  });
}

export const phpFpmQueryOptions = queryOptions({
  queryKey: queryKeys.phpFpm,
  queryFn: ({ signal }) => getPhpFpm(signal),
  staleTime: 15_000,
  retry: 1,
});

export const certificatesQueryOptions = queryOptions({
  queryKey: queryKeys.certificates,
  queryFn: ({ signal }) => getCertificates(signal),
  staleTime: 30_000,
  retry: 1,
});

export const integrationsQueryOptions = queryOptions({
  queryKey: queryKeys.integrations,
  queryFn: ({ signal }) => getIntegrations(signal),
  staleTime: 30_000,
  retry: 1,
});

export const accessSettingsQueryOptions = queryOptions({
  queryKey: queryKeys.accessSettings,
  queryFn: ({ signal }) => getAccessSettings(signal),
  staleTime: 15_000,
  retry: 1,
});

export const terminalQueryOptions = queryOptions({
  queryKey: queryKeys.terminal,
  queryFn: ({ signal }) => getTerminalCapability(signal),
  staleTime: 10_000,
  retry: 1,
});

export const fileCapabilityQueryOptions = queryOptions({
  queryKey: queryKeys.files,
  queryFn: ({ signal }) => getFileCapability(signal),
  staleTime: 10_000,
  retry: 1,
});

export const ufwQueryOptions = queryOptions({
  queryKey: queryKeys.ufw,
  queryFn: ({ signal }) => getUfw(signal),
  staleTime: 10_000,
  retry: 1,
});
