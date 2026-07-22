import type { OperationStage } from "../api/types";

export function BulletList({ values }: { values: string[] }) {
  return (
    <ul className="mt-2 space-y-1 text-sm leading-6 text-muted">
      {values.map((value) => (
        <li key={value} className="flex gap-2">
          <span aria-hidden="true">·</span>
          <span>{value}</span>
        </li>
      ))}
    </ul>
  );
}

export function isTerminalStage(stage: OperationStage): boolean {
  return [
    "SUCCEEDED",
    "ROLLED_BACK",
    "RECOVERY_REQUIRED",
    "REJECTED",
    "EXPIRED",
    "CANCELLED_BEFORE_APPLY",
  ].includes(stage);
}
