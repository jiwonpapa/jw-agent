import type { ReactNode } from "react";

interface WorkspaceHeaderProps {
  eyebrow?: string;
  title: string;
  description: string;
  action?: ReactNode;
}

export function WorkspaceHeader({ eyebrow, title, description, action }: WorkspaceHeaderProps) {
  return (
    <header className="flex flex-col gap-5 border-b border-border pb-6 sm:flex-row sm:items-end sm:justify-between">
      <div>
        {eyebrow ? (
          <p className="text-xs font-semibold uppercase tracking-widest text-muted">{eyebrow}</p>
        ) : null}
        <h1 className="mt-2 text-2xl font-semibold tracking-tight text-text sm:text-3xl">{title}</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-muted">{description}</p>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </header>
  );
}
