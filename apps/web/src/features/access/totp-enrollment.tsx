import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { Check, Copy, KeyRound, RotateCcw, ShieldCheck } from "lucide-react";
import QRCode from "qrcode";
import { useEffect, useState } from "react";

import {
  ApiError,
  beginTotpEnrollment,
  confirmTotpEnrollment,
  reauthenticateForTotpEnrollment,
  reauthenticateForTotpReset,
  resetTotp,
} from "../../shared/api/client";
import { queryKeys } from "../../shared/api/queries";
import type {
  AccessSettingsView,
  SessionView,
  TotpEnrollmentStartView,
} from "../../shared/api/types";
import { Button } from "../../shared/ui/button";
import { Input } from "../../shared/ui/input";
import { Sheet } from "../../shared/ui/sheet";
import { StatusMark } from "../../shared/ui/status-mark";

type EnrollmentStep = "password" | "scan" | "next_code";

export function TotpEnrollment({ settings, session }: {
  settings: AccessSettingsView;
  session: SessionView;
}) {
  const [open, setOpen] = useState(false);
  const [resetOpen, setResetOpen] = useState(false);
  const [step, setStep] = useState<EnrollmentStep>("password");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [material, setMaterial] = useState<TotpEnrollmentStartView | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [codesSaved, setCodesSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const recoveryAdmin = settings.ingress === "recovery" && session.subject.role === "admin";
  const ready = settings.additionalAuthProvider === "ready";

  useEffect(() => {
    if (material === null) {
      return;
    }
    let current = true;
    void QRCode.toDataURL(material.otpauthUri, {
      errorCorrectionLevel: "M",
      margin: 1,
      width: 232,
      color: { dark: "#15202b", light: "#ffffff" },
    }).then((url) => {
      if (current) setQrDataUrl(url);
    }).catch(() => {
      if (current) setMessage("QR을 만들지 못했습니다. 아래 수동 키로 등록해 주세요.");
    });
    return () => { current = false; };
  }, [material]);

  function clearEnrollment(): void {
    setStep("password");
    setPassword("");
    setCode("");
    setMaterial(null);
    setQrDataUrl(null);
    setCodesSaved(false);
    setMessage(null);
  }

  async function start(): Promise<void> {
    if (!recoveryAdmin || password.length === 0 || busy) return;
    setBusy(true);
    setMessage(null);
    try {
      const reauth = await reauthenticateForTotpEnrollment(password);
      queryClient.setQueryData(queryKeys.session, reauth.session);
      setPassword("");
      setMaterial(await beginTotpEnrollment(reauth.reauthToken));
      setStep("scan");
    } catch (error) {
      setPassword("");
      setMessage(totpErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function confirm(): Promise<void> {
    if (material === null || code.length !== 6 || !codesSaved || busy) return;
    setBusy(true);
    setMessage(null);
    try {
      const result = await confirmTotpEnrollment({ enrollmentId: material.enrollmentId, code });
      setCode("");
      if (result.state === "awaiting_next_code") {
        setStep("next_code");
        setMessage("첫 코드를 확인했습니다. 인증 앱에 다음 30초 코드가 표시되면 입력해 주세요.");
      } else {
        setMaterial(null);
        setOpen(false);
        clearEnrollment();
        await queryClient.invalidateQueries({ queryKey: queryKeys.accessSettings });
      }
    } catch (error) {
      setCode("");
      setMessage(totpErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function removeProvider(): Promise<void> {
    if (!recoveryAdmin || password.length === 0 || recoveryCode.length === 0 || busy) return;
    setBusy(true);
    setMessage(null);
    try {
      const reauth = await reauthenticateForTotpReset(password);
      await resetTotp({ reauthToken: reauth.reauthToken, recoveryCode });
      setPassword("");
      setRecoveryCode("");
      setResetOpen(false);
      queryClient.clear();
      await navigate({ to: "/login", search: { returnTo: "/overview" }, replace: true });
    } catch (error) {
      setPassword("");
      setRecoveryCode("");
      setMessage(totpErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="border-t border-border py-7" aria-labelledby="totp-provider-heading">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex items-start gap-3">
          <ShieldCheck aria-hidden="true" className="mt-0.5 size-5 text-action" />
          <div>
            <h2 id="totp-provider-heading" className="text-sm font-semibold text-text">인증 앱(TOTP)</h2>
            <p className="mt-1 max-w-2xl text-sm leading-6 text-muted">
              Google Authenticator, Microsoft Authenticator, 1Password 등 표준 6자리 인증 앱을 사용합니다.
            </p>
          </div>
        </div>
        <StatusMark label={ready ? "등록됨" : "등록 안 됨"} tone={ready ? "success" : "neutral"} />
      </div>

      <div className="mt-5 rounded-panel border border-border bg-subtle px-4 py-4">
        <p className="text-sm text-text">
          등록과 초기화는 <strong>SSH 복구 주소의 관리자 세션</strong>에서만 가능합니다.
          공개 웹에서 계정이 탈취되어도 인증 수단을 교체할 수 없습니다.
        </p>
        <div className="mt-4 flex flex-wrap gap-2">
          {!ready ? (
            <Button disabled={!recoveryAdmin} onClick={() => { clearEnrollment(); setOpen(true); }}>
              <KeyRound aria-hidden="true" className="size-4" />인증 앱 등록
            </Button>
          ) : (
            <Button variant="secondary" disabled={!recoveryAdmin} onClick={() => { setMessage(null); setResetOpen(true); }}>
              <RotateCcw aria-hidden="true" className="size-4" />복구 코드로 초기화
            </Button>
          )}
        </div>
        {!recoveryAdmin ? (
          <p className="mt-3 text-xs leading-5 text-muted">현재 접속에서는 변경할 수 없습니다. SSH 터널의 복구 화면으로 접속해 주세요.</p>
        ) : null}
      </div>

      <Sheet
        open={open}
        onOpenChange={(next) => { setOpen(next); if (!next) clearEnrollment(); }}
        side="right"
        title="인증 앱 등록"
        description="비밀번호 확인 후 키를 한 번만 표시하고 연속된 두 코드를 검증합니다."
      >
        {step === "password" ? (
          <>
            <label htmlFor="totp-password" className="block text-sm font-semibold text-text">Linux 비밀번호</label>
            <Input id="totp-password" className="mt-2" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.currentTarget.value)} />
            <Button className="mt-5 w-full" disabled={password.length === 0 || busy} onClick={() => void start()}>
              {busy ? "확인 중" : "재인증 후 등록 시작"}
            </Button>
          </>
        ) : material !== null ? (
          <>
            <div className="grid justify-items-center rounded-panel border border-border bg-white p-4">
              {qrDataUrl === null ? <div className="size-[232px] animate-pulse bg-slate-100" /> : <img src={qrDataUrl} width={232} height={232} alt="TOTP 등록 QR 코드" />}
            </div>
            <p className="mt-4 text-xs font-medium text-muted">수동 등록 키</p>
            <button type="button" className="mt-2 flex w-full items-center justify-between gap-3 rounded-control border border-border bg-surface px-3 py-3 text-left font-mono text-sm text-text" onClick={() => void navigator.clipboard.writeText(material.manualKey)}>
              <span className="break-all">{material.manualKey}</span><Copy aria-hidden="true" className="size-4 shrink-0" />
            </button>
            <div className="mt-5 border-t border-border pt-5">
              <p className="text-sm font-semibold text-text">일회용 복구 코드</p>
              <p className="mt-1 text-xs leading-5 text-muted">이 화면을 닫으면 다시 볼 수 없습니다. 서버에는 원문을 저장하지 않습니다.</p>
              <div className="mt-3 grid grid-cols-2 gap-2 font-mono text-xs text-text">
                {material.recoveryCodes.map((recovery) => <code key={recovery} className="rounded-control bg-subtle px-2 py-2">{recovery}</code>)}
              </div>
              <label className="mt-4 flex cursor-pointer items-start gap-3 text-sm leading-6 text-text">
                <input type="checkbox" className="mt-1 size-4 accent-action" checked={codesSaved} onChange={(event) => setCodesSaved(event.currentTarget.checked)} />
                복구 코드를 서버 밖의 안전한 곳에 저장했습니다.
              </label>
            </div>
            <label htmlFor="totp-code" className="mt-5 block text-sm font-semibold text-text">
              {step === "next_code" ? "다음 30초 코드" : "현재 6자리 코드"}
            </label>
            <Input id="totp-code" className="mt-2 font-mono tracking-[0.3em]" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={(event) => setCode(event.currentTarget.value.replace(/\D/g, "").slice(0, 6))} />
            <Button className="mt-5 w-full" disabled={!codesSaved || code.length !== 6 || busy} onClick={() => void confirm()}>
              <Check aria-hidden="true" className="size-4" />{step === "next_code" ? "두 번째 코드 확인" : "첫 번째 코드 확인"}
            </Button>
          </>
        ) : null}
        {message !== null ? <p role="status" className="mt-4 text-sm leading-6 text-warning">{message}</p> : null}
      </Sheet>

      <Sheet open={resetOpen} onOpenChange={setResetOpen} side="right" title="TOTP 초기화" description="정책을 끄고 현재 계정의 모든 웹 세션을 종료합니다.">
        <label htmlFor="totp-reset-password" className="block text-sm font-semibold text-text">Linux 비밀번호</label>
        <Input id="totp-reset-password" className="mt-2" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.currentTarget.value)} />
        <label htmlFor="totp-recovery-code" className="mt-5 block text-sm font-semibold text-text">일회용 복구 코드</label>
        <Input id="totp-recovery-code" className="mt-2 font-mono" autoComplete="off" value={recoveryCode} onChange={(event) => setRecoveryCode(event.currentTarget.value)} />
        <Button className="mt-6 w-full" variant="danger" disabled={password.length === 0 || recoveryCode.length === 0 || busy} onClick={() => void removeProvider()}>
          {busy ? "초기화 중" : "인증 수단 초기화 및 로그아웃"}
        </Button>
        {message !== null ? <p role="alert" className="mt-4 text-sm text-danger">{message}</p> : null}
      </Sheet>
    </section>
  );
}

function totpErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return "Linux 비밀번호를 확인해 주세요.";
    if (error.status === 429) return "시도가 너무 많습니다. 잠시 후 다시 시도해 주세요.";
    if (error.code === "additional_authentication_rejected") return "코드가 일치하지 않거나 이미 사용되었습니다.";
    if (error.code === "additional_authentication_unavailable") return "암호화 키를 사용할 수 없어 안전하게 중단했습니다.";
  }
  return "인증 설정을 완료하지 못했습니다. 변경된 상태를 다시 확인해 주세요.";
}
