import { createFileRoute } from "@tanstack/react-router";

import { OverviewScreen } from "../features/overview/overview-screen";

export const Route = createFileRoute("/_authenticated/overview")({
  component: OverviewScreen,
});
