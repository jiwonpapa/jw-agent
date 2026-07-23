import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import type { ReactNode } from "react";

import { cn } from "./cn";

interface SheetProps {
  children: ReactNode;
  title: string;
  description?: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  side?: "left" | "right";
  size?: "default" | "wide" | "fullscreen";
}

export function Sheet({
  children,
  title,
  description,
  open,
  onOpenChange,
  side = "left",
  size = "default",
}: SheetProps) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 animate-overlay-in bg-text/35 backdrop-blur-sm" />
        <Dialog.Content
          className={cn(
            "fixed z-50 w-full animate-sheet-in overflow-y-auto border-border bg-surface p-5 shadow-xl",
            size === "fullscreen"
              ? "inset-0 max-w-none sm:p-7"
              : cn(
                  "inset-y-0",
                  size === "wide" ? "max-w-2xl" : "max-w-sm",
                  side === "left" ? "left-0 border-r" : "right-0 border-l",
                ),
          )}
        >
          <div className="mb-6 flex min-h-11 items-start justify-between gap-4">
            <div>
              <Dialog.Title className="text-base font-semibold text-text">{title}</Dialog.Title>
              {description ? (
                <Dialog.Description className="mt-1 text-sm leading-5 text-muted">
                  {description}
                </Dialog.Description>
              ) : null}
            </div>
            <Dialog.Close className="inline-flex size-11 shrink-0 items-center justify-center rounded-control text-muted hover:bg-subtle hover:text-text">
              <X aria-hidden="true" className="size-5" />
              <span className="sr-only">닫기</span>
            </Dialog.Close>
          </div>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
