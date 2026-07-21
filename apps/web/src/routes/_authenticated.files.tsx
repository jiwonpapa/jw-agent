import { createFileRoute } from "@tanstack/react-router";

import { FilesScreen } from "../features/files/files-screen";

export const Route = createFileRoute("/_authenticated/files")({
  component: FilesScreen,
});
