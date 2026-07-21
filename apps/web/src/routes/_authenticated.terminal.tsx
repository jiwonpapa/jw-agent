import { createFileRoute } from "@tanstack/react-router";

import { TerminalScreen } from "../features/terminal/terminal-screen";

export const Route = createFileRoute("/_authenticated/terminal")({
  component: TerminalScreen,
});
