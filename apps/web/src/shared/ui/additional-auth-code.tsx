import { useQuery } from "@tanstack/react-query";

import { sessionQueryOptions } from "../api/queries";
import { Input } from "./input";

export function useAdditionalAuthRequired(): boolean {
  const session = useQuery(sessionQueryOptions).data;
  return session !== undefined && session.additionalAuthPolicy !== "disabled";
}

export function AdditionalAuthCodeField({ id, value, onChange, disabled = false }: {
  id: string;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
}) {
  const required = useAdditionalAuthRequired();
  if (!required) return null;
  return (
    <div className="mt-4">
      <label htmlFor={id} className="mb-2 block text-sm font-medium text-text">인증 앱 6자리 코드</label>
      <Input
        id={id}
        className="font-mono tracking-[0.3em]"
        inputMode="numeric"
        autoComplete="one-time-code"
        maxLength={6}
        required
        disabled={disabled}
        value={value}
        onChange={(event) => onChange(event.currentTarget.value.replace(/\D/g, "").slice(0, 6))}
      />
      <p className="mt-2 text-xs leading-5 text-muted">코드는 이 exact plan과 현재 세션에만 결합되며 재사용할 수 없습니다.</p>
    </div>
  );
}
