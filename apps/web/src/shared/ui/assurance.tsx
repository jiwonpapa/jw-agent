import { RotateCcw, ShieldQuestion } from "lucide-react";

import type { AssuranceView } from "../api/types";
import { assuranceCopy } from "../domain/assurance";
import { StatusMark } from "./status-mark";

export function AssuranceMark({ assurance }: { assurance: AssuranceView }) {
  const copy = assuranceCopy(assurance);
  return <StatusMark label={`${copy.shortLabel} · ${copy.label}`} tone={copy.tone} />;
}

export function AssuranceDetails({ assurance }: { assurance: AssuranceView }) {
  const copy = assuranceCopy(assurance);
  return (
    <div className="border-y border-border py-4">
      <div className="flex items-start gap-3">
        {assurance.operationAvailable ? (
          <RotateCcw aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-action" />
        ) : (
          <ShieldQuestion aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-muted" />
        )}
        <div className="min-w-0 flex-1">
          <AssuranceMark assurance={assurance} />
          <p className="mt-2 text-sm leading-6 text-muted">{copy.description}</p>
          {assurance.reason ? (
            <p className="mt-2 text-sm font-medium leading-6 text-text">{assurance.reason}</p>
          ) : null}
        </div>
      </div>

      <dl className="mt-4 grid gap-4 text-sm sm:grid-cols-2">
        <AssuranceList label="보장 범위" values={assurance.scope} empty="보장 범위 없음" />
        <AssuranceList
          label="원복 제외"
          values={assurance.excludedEffects}
          empty="제외 효과 없음"
        />
        <AssuranceList
          label="적용 검증"
          values={assurance.applyVerifier}
          empty="적용 작업 없음"
        />
        <AssuranceList
          label="원복 검증"
          values={assurance.rollbackVerifier}
          empty="원복 작업 없음"
        />
      </dl>
    </div>
  );
}

function AssuranceList({
  label,
  values,
  empty,
}: {
  label: string;
  values: string[];
  empty: string;
}) {
  return (
    <div>
      <dt className="text-xs font-semibold text-muted">{label}</dt>
      <dd className="mt-1 leading-6 text-text">{values.length === 0 ? empty : values.join(" · ")}</dd>
    </div>
  );
}
