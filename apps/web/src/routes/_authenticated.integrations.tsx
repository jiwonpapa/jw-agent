import { createFileRoute } from "@tanstack/react-router";

import { IntegrationsScreen } from "../features/integrations/integrations-screen";

export const Route = createFileRoute("/_authenticated/integrations")({
  component: IntegrationsScreen,
});
