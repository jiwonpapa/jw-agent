import { createFileRoute } from "@tanstack/react-router";

import { ServiceConfigScreen } from "../features/service-config/service-config-screen";

export const Route = createFileRoute("/_authenticated/services/nginx/configurations")({
  component: NginxConfigurationsRoute,
});

function NginxConfigurationsRoute() {
  return (
    <ServiceConfigScreen
      serviceKey="nginx"
      title="Nginx"
      unitName="nginx.service"
      validatorLabel="nginx -t"
      language="nginx"
    />
  );
}
