import { createFileRoute } from "@tanstack/react-router";

import { PhpFpmScreen } from "../features/php-fpm/php-fpm-screen";

export const Route = createFileRoute("/_authenticated/services/php-fpm")({
  component: PhpFpmScreen,
});
