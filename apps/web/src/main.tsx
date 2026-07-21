import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { createAppQueryClient } from "./app/query-client";
import { createAppRouter } from "./app/router";
import "./styles/generated.css";

const rootElement = document.getElementById("root");

if (rootElement === null) {
  throw new Error("JW Agent root element is missing");
}

const queryClient = createAppQueryClient();
const router = createAppRouter({ queryClient });

createRoot(rootElement).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} context={{ queryClient }} />
    </QueryClientProvider>
  </StrictMode>,
);
