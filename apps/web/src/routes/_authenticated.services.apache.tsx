import { createFileRoute } from "@tanstack/react-router";

import { ServiceConfigScreen } from "../features/service-config/service-config-screen";

export const Route = createFileRoute("/_authenticated/services/apache")({
  component: ApacheConfigRoute,
});

function ApacheConfigRoute() {
  return (
    <ServiceConfigScreen
      serviceKey="apache"
      title="Apache"
      unitName="apache2.service"
      validatorLabel="apache2ctl configtest"
      language="plain"
    />
  );
}
