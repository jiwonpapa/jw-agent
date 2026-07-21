import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import type { ButtonHTMLAttributes } from "react";

import { cn } from "./cn";

const buttonVariants = cva(
  "inline-flex min-h-11 items-center justify-center gap-2 rounded-control px-4 text-sm font-semibold transition-colors duration-150 disabled:pointer-events-none disabled:opacity-45",
  {
    variants: {
      variant: {
        primary: "bg-action text-action-foreground hover:brightness-95",
        secondary: "border border-border bg-surface text-text hover:bg-subtle",
        ghost: "text-muted hover:bg-subtle hover:text-text",
        danger: "bg-danger text-action-foreground hover:brightness-95",
      },
      size: {
        default: "h-11",
        compact: "h-9 min-h-9 px-3",
        icon: "size-11 px-0",
      },
    },
    defaultVariants: {
      variant: "primary",
      size: "default",
    },
  },
);

interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export function Button({ asChild = false, className, variant, size, ...props }: ButtonProps) {
  const Component = asChild ? Slot : "button";
  return <Component className={cn(buttonVariants({ variant, size }), className)} {...props} />;
}
