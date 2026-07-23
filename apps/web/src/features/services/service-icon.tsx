import {
  Box,
  Braces,
  Database,
  Globe2,
  HardDrive,
  KeyRound,
  Network,
  Package,
  ServerCog,
  Shield,
  type LucideIcon,
} from "lucide-react";

import type { ServiceCategory, ServiceSummary } from "../../shared/api/types";
import { cn } from "../../shared/ui/cn";

const BRAND_ICON_PATHS: Readonly<Record<string, string>> = {
  nginx: "/service-icons/nginx.svg",
  "apache-httpd": "/service-icons/apache.svg",
  caddy: "/service-icons/caddy.svg",
  "php-fpm": "/service-icons/php.svg",
  mysql: "/service-icons/mysql.svg",
  mariadb: "/service-icons/mariadb.svg",
  postgresql: "/service-icons/postgresql.svg",
  redis: "/service-icons/redis.svg",
  certbot: "/service-icons/letsencrypt.svg",
  docker: "/service-icons/docker.svg",
};

const CATEGORY_ICONS: Readonly<Record<ServiceCategory, LucideIcon>> = {
  web: Globe2,
  runtime: Braces,
  database: Database,
  cache: HardDrive,
  access: KeyRound,
  security: Shield,
  certificate: Shield,
  container: Box,
  monitoring: Network,
  custom: Package,
  system: ServerCog,
  other: Package,
};

export function ServiceIcon({ service, className }: { service: ServiceSummary; className?: string }) {
  const brandPath = service.templateId === null || service.templateId === undefined
    ? undefined
    : BRAND_ICON_PATHS[service.templateId];
  if (brandPath !== undefined) {
    return (
      <span className={cn("grid size-10 shrink-0 place-items-center rounded-panel bg-surface ring-1 ring-border", className)}>
        <img src={brandPath} alt="" aria-hidden="true" className="size-6 object-contain dark:invert" />
      </span>
    );
  }
  const Icon = CATEGORY_ICONS[service.category];
  return (
    <span className={cn("grid size-10 shrink-0 place-items-center rounded-panel bg-subtle text-muted", className)}>
      <Icon aria-hidden="true" className="size-5" />
    </span>
  );
}
