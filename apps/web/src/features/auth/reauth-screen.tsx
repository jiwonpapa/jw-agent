import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { KeyRound } from "lucide-react";
import { useEffect, useRef, useState, type SyntheticEvent } from "react";

import { ApiError, reauthenticateForPolicy, updateAdditionalAuthPolicy } from "../../shared/api/client";
import { queryKeys } from "../../shared/api/queries";
import type { AdditionalAuthPolicy } from "../../shared/api/types";
import { POLICY_LABELS } from "../../shared/content/copy";
import { safeReturnTo } from "../../shared/domain/return-to";
import { Button } from "../../shared/ui/button";
import { Input } from "../../shared/ui/input";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";

export function ReauthScreen({ targetPolicy, returnTo }: { targetPolicy: AdditionalAuthPolicy; returnTo: string }) {
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const errorRef = useRef<HTMLParagraphElement>(null);
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  useEffect(() => {
    if (errorMessage !== null) errorRef.current?.focus();
  }, [errorMessage]);

  async function handleSubmit(event: SyntheticEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setSubmitting(true);
    setErrorMessage(null);
    try {
      const reauth = await reauthenticateForPolicy({ password, targetPolicy });
      setPassword("");
      const settings = await updateAdditionalAuthPolicy({ policy: targetPolicy, reauthToken: reauth.reauthToken });
      queryClient.setQueryData(queryKeys.session, reauth.session);
      queryClient.setQueryData(queryKeys.accessSettings, settings);
      await navigate({ to: safeReturnTo(returnTo), replace: true });
    } catch (error) {
      setPassword("");
      setErrorMessage(
        error instanceof ApiError && error.status === 401
          ? "재인증에 실패했습니다. 계정 정보를 확인해 주세요."
          : "보안 정책을 변경하지 못했습니다.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="animate-state-in max-w-2xl">
      <WorkspaceHeader
        eyebrow="Session / Reauthentication"
        title="PAM 재인증"
        description="인증 정책을 변경하기 전에 현재 Linux 계정의 비밀번호를 다시 확인합니다."
      />
      <section className="py-7">
        <div className="border-y border-border py-4">
          <p className="text-xs text-muted">변경할 정책</p>
          <p className="mt-1 text-sm font-semibold text-text">{POLICY_LABELS[targetPolicy].label}</p>
        </div>
        {errorMessage ? (
          <p ref={errorRef} tabIndex={-1} role="alert" className="mt-5 text-sm font-medium text-danger">{errorMessage}</p>
        ) : null}
        <form className="mt-6" onSubmit={(event) => void handleSubmit(event)}>
          <label htmlFor="reauth-password" className="mb-2 block text-sm font-medium text-text">비밀번호</label>
          <Input
            id="reauth-password"
            type="password"
            name="password"
            autoComplete="current-password"
            maxLength={1024}
            required
            disabled={submitting}
            value={password}
            onChange={(event) => setPassword(event.currentTarget.value)}
          />
          <Button className="mt-5 w-full sm:w-auto" type="submit" disabled={submitting}>
            <KeyRound aria-hidden="true" className="size-4" />
            {submitting ? "확인 중" : "재인증 후 변경"}
          </Button>
        </form>
      </section>
    </div>
  );
}
