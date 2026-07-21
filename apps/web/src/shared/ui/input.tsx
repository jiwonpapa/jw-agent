import type { InputHTMLAttributes } from "react";

import { cn } from "./cn";

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "h-11 w-full rounded-control border border-border bg-surface px-3 text-base text-text shadow-none transition-colors placeholder:text-muted disabled:cursor-not-allowed disabled:bg-subtle disabled:opacity-70 md:text-sm",
        className,
      )}
      {...props}
    />
  );
}
