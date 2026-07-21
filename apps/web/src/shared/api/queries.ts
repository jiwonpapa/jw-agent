import { queryOptions } from "@tanstack/react-query";

import {
  getAccessSettings,
  getHealth,
  getHost,
  getIntegrations,
  getNginxSites,
  getSession,
} from "./client";

export const queryKeys = {
  health: ["health"] as const,
  session: ["session"] as const,
  host: ["host"] as const,
  nginxSites: ["services", "nginx", "sites"] as const,
  integrations: ["integrations"] as const,
  accessSettings: ["settings", "access"] as const,
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

export const nginxSitesQueryOptions = queryOptions({
  queryKey: queryKeys.nginxSites,
  queryFn: ({ signal }) => getNginxSites(signal),
  staleTime: 15_000,
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
