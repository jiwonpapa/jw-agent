import { createFileRoute } from "@tanstack/react-router";

import { NginxScreen } from "../features/nginx/nginx-screen";

export const Route = createFileRoute("/_authenticated/services/nginx")({
  component: NginxScreen,
});
