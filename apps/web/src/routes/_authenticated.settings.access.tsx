import { createFileRoute } from "@tanstack/react-router";

import { AccessScreen } from "../features/access/access-screen";

export const Route = createFileRoute("/_authenticated/settings/access")({
  component: AccessScreen,
});
