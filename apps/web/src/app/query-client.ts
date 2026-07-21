import { QueryClient } from "@tanstack/react-query";

export function createAppQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        refetchOnWindowFocus: true,
        retry: 1,
      },
      mutations: {
        retry: false,
      },
    },
  });
}
