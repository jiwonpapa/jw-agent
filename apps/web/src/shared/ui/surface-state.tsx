import { AlertTriangle, CircleSlash2, RefreshCw, ServerOff } from "lucide-react";
import type { ReactNode } from "react";

import { Button } from "./button";

type SurfaceStateKind = "error" | "empty" | "unsupported" | "offline";

const icons: Record<SurfaceStateKind, typeof AlertTriangle> = {
  error: AlertTriangle,
  empty: CircleSlash2,
  unsupported: CircleSlash2,
  offline: ServerOff,
};

interface SurfaceStateProps {
  kind: SurfaceStateKind;
  title: string;
  description: string;
  action?: { label: string; onClick: () => void };
  detail?: ReactNode;
}

export function SurfaceState({ kind, title, description, action, detail }: SurfaceStateProps) {
  const Icon = icons[kind];
  return (
    <section className="animate-state-in border-y border-border py-10" aria-live="polite">
      <div className="max-w-xl">
        <Icon aria-hidden="true" className="mb-4 size-5 text-muted" />
        <h2 className="text-lg font-semibold text-text">{title}</h2>
        <p className="mt-2 text-sm leading-6 text-muted">{description}</p>
        {detail ? <div className="mt-4 text-sm text-muted">{detail}</div> : null}
        {action ? (
          <Button className="mt-5" variant="secondary" onClick={action.onClick}>
            <RefreshCw aria-hidden="true" className="size-4" />
            {action.label}
          </Button>
        ) : null}
      </div>
    </section>
  );
}
