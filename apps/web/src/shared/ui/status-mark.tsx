import { Circle } from "lucide-react";

import { cn } from "./cn";

export type StatusTone = "success" | "warning" | "danger" | "info" | "stale" | "neutral";

const toneClasses: Record<StatusTone, string> = {
  success: "text-success",
  warning: "text-warning",
  danger: "text-danger",
  info: "text-info",
  stale: "text-stale",
  neutral: "text-muted",
};

export function StatusMark({ label, tone = "neutral" }: { label: string; tone?: StatusTone }) {
  return (
    <span className="inline-flex items-center gap-2 text-sm text-text">
      <Circle aria-hidden="true" className={cn("size-2.5 fill-current", toneClasses[tone])} />
      <span>{label}</span>
    </span>
  );
}
