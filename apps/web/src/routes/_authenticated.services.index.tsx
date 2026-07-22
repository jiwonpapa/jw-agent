import { createFileRoute } from "@tanstack/react-router";

import { ServicesScreen } from "../features/services/services-screen";

export const Route = createFileRoute("/_authenticated/services/")({
  component: ServicesScreen,
});
