import { createFileRoute } from "@tanstack/react-router";

import { UfwScreen } from "../features/firewall/ufw-screen";

export const Route = createFileRoute("/_authenticated/firewall")({
  component: UfwScreen,
});
