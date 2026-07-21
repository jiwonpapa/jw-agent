import { createRouter } from "@tanstack/react-router";

import { routeTree } from "../routeTree.gen";
import type { QueryClient } from "@tanstack/react-query";

export interface RouterContext {
  queryClient: QueryClient;
}

export function createAppRouter(context: RouterContext) {
  return createRouter({
    routeTree,
    context,
    defaultPreload: "intent",
    defaultPreloadStaleTime: 0,
    scrollRestoration: true,
  });
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof createAppRouter>;
  }
}
