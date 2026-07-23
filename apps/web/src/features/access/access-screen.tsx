import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { GlobeLock, KeyRound, LockKeyhole, Network, ShieldCheck, TriangleAlert } from "lucide-react";
import { useState } from "react";

import { accessSettingsQueryOptions, sessionQueryOptions } from "../../shared/api/queries";
import type { AdditionalAuthPolicy } from "../../shared/api/types";
import {
  POLICY_LABELS,
  POLICY_PROVIDER_LABELS,
} from "../../shared/content/copy";
import {
  isPolicyDowngrade,
  providerCanApproveMutations,
  RECOMMENDED_ADDITIONAL_AUTH_POLICY,
} from "../../shared/domain/additional-auth";
import { Button } from "../../shared/ui/button";
import { AssuranceDetails } from "../../shared/ui/assurance";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";
import { TotpEnrollment } from "./totp-enrollment";
import { accessModeLabel, SessionAccessPanel } from "../auth/administrative-access";

const policyOrder: AdditionalAuthPolicy[] = ["disabled", "risky_operations", "all_mutations"];

export function AccessScreen() {
  const settingsQuery = useQuery(accessSettingsQueryOptions);
  const session = useQuery(sessionQueryOptions).data;
  const [selectedPolicy, setSelectedPolicy] = useState<AdditionalAuthPolicy | null>(null);
  const navigate = useNavigate();

  if (settingsQuery.isPending || session === undefined) {
    return (
      <div>
        <Skeleton className="h-9 w-52" />
        <Skeleton className="mt-8 h-40 w-full" />
        <Skeleton className="mt-4 h-72 w-full" />
      </div>
    );
  }

  if (settingsQuery.isError) {
    return (
      <SurfaceState
        kind="error"
        title="접속 설정을 불러오지 못했습니다"
        description="서버 설정을 추측하지 않습니다. canonical 설정을 다시 요청해 주세요."
        action={{ label: "다시 불러오기", onClick: () => void settingsQuery.refetch() }}
      />
    );
  }

  const settings = settingsQuery.data;
  const isAdmin = session.subject.role === "admin";
  const providerReady = providerCanApproveMutations(settings.additionalAuthProvider);
  const effectiveProtection = providerReady && settings.mutationApprovalAvailable;
  const effectiveSelectedPolicy = selectedPolicy ?? settings.additionalAuthPolicy;
  const changed = effectiveSelectedPolicy !== settings.additionalAuthPolicy;

  async function savePolicy(): Promise<void> {
    if (!changed || !isAdmin) return;
    await navigate({
      to: "/session/reauth",
      search: { targetPolicy: effectiveSelectedPolicy, returnTo: "/settings/access" },
    });
  }

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Settings / Access"
        title="접속 및 인증"
        description="현재 접속 경로와 Linux PAM 세션, 추가 인증 정책을 확인합니다. 서버 판정이 최종 권위입니다."
        action={<StatusMark label={accessModeLabel(session)} tone={session.administrativeAccess === "administrative" ? "warning" : isAdmin ? "info" : "neutral"} />}
      />

      <section className="mt-6 rounded-panel border border-border bg-surface p-5" aria-labelledby="access-path-heading">
        <h2 id="access-path-heading" className="text-sm font-semibold text-text">접속 경로</h2>
        <p className="mt-1 text-sm text-muted">공개 HTTPS와 SSH 복구 경로를 분리해 유지합니다.</p>
        <div className="mt-5 grid gap-3 lg:grid-cols-2">
          <AccessRow
            icon={GlobeLock}
            title="공개 HTTPS"
            value={settings.publicHost ?? "비활성"}
            status={settings.publicHost === null ? "설정되지 않음" : "설정됨"}
            tone={settings.publicHost === null ? "neutral" : "success"}
          />
          <AccessRow
            icon={Network}
            title="SSH 복구"
            value={settings.recoveryOrigin}
            status={settings.ingress === "recovery" ? "현재 접속" : "대기 경로"}
            tone="info"
          />
        </div>
      </section>

      <div className="mt-6"><SessionAccessPanel session={session} /></div>

      <section className="mt-6 rounded-panel border border-border bg-surface p-5" aria-labelledby="additional-auth-heading">
        <div className="flex items-start gap-3">
          <ShieldCheck aria-hidden="true" className="mt-0.5 size-5 text-action" />
          <div>
            <h2 id="additional-auth-heading" className="text-sm font-semibold text-text">추가 인증 정책</h2>
            <p className="mt-1 text-sm leading-6 text-muted">
              PAM 로그인은 항상 유지됩니다. 위험 작업 분류와 최종 허용 여부는 백엔드가 판정합니다.
            </p>
          </div>
        </div>

        <div className="mt-5 border-l-2 border-warning bg-warning/5 px-4 py-3">
          <p className="text-sm font-semibold text-text">
            {POLICY_PROVIDER_LABELS[settings.additionalAuthProvider]}
          </p>
          <p className="mt-1 text-sm leading-6 text-muted">
            {effectiveProtection
              ? "추가 인증 승인 기능이 실제로 활성화되어 있습니다."
              : "정책을 선택해도 현재 mutation approval은 사용할 수 없습니다. 보호됨으로 간주하지 마세요."}
          </p>
        </div>

        <fieldset className="mt-6" disabled={!isAdmin}>
          <legend className="sr-only">추가 인증 수준</legend>
          <div className="grid gap-3 lg:grid-cols-3">
            {policyOrder.map((policy) => {
              const copy = POLICY_LABELS[policy];
              const recommended = policy === RECOMMENDED_ADDITIONAL_AUTH_POLICY;
              return (
                <label key={policy} className="flex min-h-24 cursor-pointer items-start gap-4 rounded-control border border-border bg-subtle/30 p-4 disabled:cursor-not-allowed">
                  <input
                    type="radio"
                    name="additional-auth-policy"
                    value={policy}
                    checked={effectiveSelectedPolicy === policy}
                    disabled={policy !== "disabled" && !providerReady}
                    className="mt-1 size-4 accent-action"
                    onChange={() => setSelectedPolicy(policy)}
                  />
                  <span className="flex-1">
                    <span className="flex flex-wrap items-center gap-2 text-sm font-semibold text-text">
                      {copy.label}
                      {recommended ? (
                        <span className="rounded-control bg-action/10 px-2 py-0.5 text-xs font-semibold text-action">권장</span>
                      ) : null}
                    </span>
                    <span className="mt-1 block text-sm leading-6 text-muted">{copy.description}</span>
                  </span>
                </label>
              );
            })}
          </div>
        </fieldset>

        {!isAdmin ? (
          <p className="mt-4 flex items-start gap-2 text-sm text-muted">
            <LockKeyhole aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
            관리자 계정만 정책을 변경할 수 있습니다.
          </p>
        ) : null}

        {changed && isPolicyDowngrade(settings.additionalAuthPolicy, effectiveSelectedPolicy) ? (
          <p className="mt-4 flex items-start gap-2 text-sm text-warning">
            <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
            보안 수준을 낮추면 이후 작업의 추가 인증 범위가 줄어듭니다. 최근 PAM 재인증 후 적용됩니다.
          </p>
        ) : null}

        <div className="mt-6">
          <AssuranceDetails assurance={settings.assurance} />
        </div>

        <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center">
          <Button disabled={!isAdmin || !changed || (effectiveSelectedPolicy !== "disabled" && !providerReady)} onClick={() => void savePolicy()}>
            <KeyRound aria-hidden="true" className="size-4" />
            재인증 후 저장
          </Button>
          <p className="text-xs leading-5 text-muted">화면 제어와 관계없이 서버 role·capability 검사가 적용됩니다.</p>
        </div>
      </section>
      <TotpEnrollment settings={settings} session={session} />
    </div>
  );
}

function AccessRow({ icon: Icon, title, value, status, tone }: {
  icon: typeof GlobeLock;
  title: string;
  value: string;
  status: string;
  tone: "success" | "info" | "neutral";
}) {
  return (
    <div className="flex flex-col gap-3 rounded-control border border-border bg-subtle/30 p-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex min-w-0 items-start gap-3">
        <Icon aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted" />
        <div className="min-w-0">
          <p className="text-sm font-semibold text-text">{title}</p>
          <p className="mt-1 break-all text-sm text-muted">{value}</p>
        </div>
      </div>
      <StatusMark label={status} tone={tone} />
    </div>
  );
}
