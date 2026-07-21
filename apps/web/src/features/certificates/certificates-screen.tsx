import { useQuery } from "@tanstack/react-query";
import { BadgeCheck, Clock3, KeyRound, ShieldAlert } from "lucide-react";

import { certificatesQueryOptions } from "../../shared/api/queries";
import type { CertificateInventoryView, CertificateSummaryView } from "../../shared/api/types";
import { formatDateTime } from "../../shared/domain/format";
import { AssuranceDetails, AssuranceMark } from "../../shared/ui/assurance";
import { Skeleton } from "../../shared/ui/skeleton";
import { StatusMark } from "../../shared/ui/status-mark";
import { SurfaceState } from "../../shared/ui/surface-state";
import { WorkspaceHeader } from "../../shared/ui/workspace-header";

export function CertificatesScreen() {
  const inventory = useQuery(certificatesQueryOptions);

  return (
    <div className="animate-state-in">
      <WorkspaceHeader
        eyebrow="Certificates / Certbot"
        title="TLS 인증서"
        description="Certbot 인증서의 공개 메타데이터와 자동 갱신 timer를 확인합니다. 개인키와 ACME 계정 비밀은 화면으로 가져오지 않습니다."
        action={<StatusMark label="조회 전용" tone="info" />}
      />

      {inventory.isPending ? (
        <div className="space-y-3 py-7" aria-label="인증서 목록 불러오는 중">
          <Skeleton className="h-28 w-full" />
          <Skeleton className="h-40 w-full" />
        </div>
      ) : inventory.isError ? (
        <SurfaceState
          kind="error"
          title="인증서 상태를 불러오지 못했습니다"
          description="root inventory를 추측해서 표시하지 않습니다. canonical 상태를 다시 조회해 주세요."
          action={{ label: "다시 조회", onClick: () => void inventory.refetch() }}
        />
      ) : (
        <CertificateInventory data={inventory.data} />
      )}
    </div>
  );
}

function CertificateInventory({ data }: { data: CertificateInventoryView }) {
  return (
    <>
      <section className="py-7" aria-labelledby="certificate-runtime-heading">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h2 id="certificate-runtime-heading" className="text-sm font-semibold text-text">
              Certbot 갱신 상태
            </h2>
            <p className="mt-1 text-sm text-muted">관찰 시각 {formatDateTime(data.observedAt)}</p>
          </div>
          <AssuranceMark assurance={data.assurance} />
        </div>
        <dl className="mt-5 grid gap-px overflow-hidden rounded-panel border border-border bg-border sm:grid-cols-3">
          <RuntimeValue
            icon={BadgeCheck}
            label="Certbot"
            value={data.certbotInstalled ? "설치됨" : "설치 안 됨"}
            healthy={data.certbotInstalled}
          />
          <RuntimeValue
            icon={Clock3}
            label="갱신 timer"
            value={data.timerEnabled ? "활성화" : "비활성"}
            healthy={data.timerEnabled}
          />
          <RuntimeValue
            icon={Clock3}
            label="timer 실행 상태"
            value={data.timerActive ? "대기 중" : "중지됨"}
            healthy={data.timerActive}
          />
        </dl>
        {data.problems.length > 0 ? (
          <div className="mt-5 rounded-panel border border-warning/35 bg-warning/5 p-4">
            <div className="flex items-start gap-3">
              <ShieldAlert aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-warning" />
              <div>
                <p className="text-sm font-semibold text-text">확인이 필요한 항목</p>
                <ul className="mt-2 space-y-1 text-sm text-muted">
                  {data.problems.map((problem) => <li key={problem}>· {problemLabel(problem)}</li>)}
                </ul>
              </div>
            </div>
          </div>
        ) : null}
      </section>

      <section className="border-t border-border py-7" aria-labelledby="certificate-list-heading">
        <div className="flex items-start gap-3">
          <KeyRound aria-hidden="true" className="mt-0.5 size-5 text-muted" />
          <div>
            <h2 id="certificate-list-heading" className="text-sm font-semibold text-text">
              인증서 lineage
            </h2>
            <p className="mt-1 text-sm leading-6 text-muted">
              SAN·만료·fingerprint만 표시하며 개인키 본문과 실제 root 경로는 숨깁니다.
            </p>
          </div>
        </div>
        {data.certificates.length === 0 ? (
          <SurfaceState
            kind="empty"
            title="관찰 가능한 Certbot 인증서가 없습니다"
            description="발급 기능은 staging·attach fault gate가 끝날 때까지 제공하지 않습니다. 기존 인증서는 /etc/letsencrypt 표준 lineage만 인식합니다."
          />
        ) : (
          <div className="mt-6 grid gap-4 xl:grid-cols-2">
            {data.certificates.map((certificate) => (
              <CertificateCard key={certificate.primaryDomain} certificate={certificate} />
            ))}
          </div>
        )}
      </section>

      <section className="border-t border-border py-7" aria-labelledby="certificate-boundary-heading">
        <h2 id="certificate-boundary-heading" className="text-sm font-semibold text-text">
          현재 안전 경계
        </h2>
        <div className="mt-4 max-w-3xl">
          <AssuranceDetails assurance={data.assurance} />
        </div>
      </section>
    </>
  );
}

function RuntimeValue({
  icon: Icon,
  label,
  value,
  healthy,
}: {
  icon: typeof BadgeCheck;
  label: string;
  value: string;
  healthy: boolean;
}) {
  return (
    <div className="bg-surface p-4">
      <dt className="flex items-center gap-2 text-xs font-medium text-muted">
        <Icon aria-hidden="true" className="size-4" />
        {label}
      </dt>
      <dd className="mt-2"><StatusMark label={value} tone={healthy ? "success" : "warning"} /></dd>
    </div>
  );
}

function CertificateCard({ certificate }: { certificate: CertificateSummaryView }) {
  return (
    <article className="rounded-panel border border-border bg-surface p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold text-text">{certificate.primaryDomain}</h3>
          <p className="mt-1 text-xs text-muted">{certificate.certificatePath}</p>
        </div>
        <StatusMark
          label={certificate.webrootManaged ? "webroot 관리" : "외부 설정"}
          tone={certificate.webrootManaged ? "success" : "warning"}
        />
      </div>
      <dl className="mt-5 grid gap-4 text-sm sm:grid-cols-2">
        <div>
          <dt className="text-xs text-muted">만료</dt>
          <dd className="mt-1 font-medium text-text">{certificate.notAfter}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted">개인키 파일</dt>
          <dd className="mt-1 font-medium text-text">{certificate.privateKeyPresent ? "존재 확인" : "확인 실패"}</dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="text-xs text-muted">SAN</dt>
          <dd className="mt-1 break-words font-medium text-text">{certificate.sans.join(", ")}</dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="text-xs text-muted">SHA-256 fingerprint</dt>
          <dd className="mt-1 break-all font-mono text-xs text-text">{certificate.fingerprintSha256}</dd>
        </div>
      </dl>
    </article>
  );
}

function problemLabel(problem: string): string {
  if (problem === "certbot_not_installed") return "Ubuntu Certbot이 설치되지 않았습니다.";
  if (problem === "certbot_timer_disabled") return "certbot.timer가 활성화되지 않았습니다.";
  if (problem === "certbot_timer_inactive") return "certbot.timer가 현재 대기 상태가 아닙니다.";
  if (problem.startsWith("certificate_invalid:")) return `${problem.slice(20)} lineage를 안전하게 읽지 못했습니다.`;
  return "표준 Certbot lineage가 아닌 항목을 발견했습니다.";
}
