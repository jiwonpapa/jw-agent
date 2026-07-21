import { createFileRoute } from "@tanstack/react-router";

import { CertificatesScreen } from "../features/certificates/certificates-screen";

export const Route = createFileRoute("/_authenticated/certificates")({
  component: CertificatesScreen,
});
