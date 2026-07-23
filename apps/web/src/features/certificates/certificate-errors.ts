import { ApiError } from "../../shared/api/client";

const OPERATION_MESSAGES: Record<string, string> = {
  stale_inventory: "인증서 상태가 바뀌었습니다. 다시 조회한 뒤 새 계획을 만드세요.",
  stale_site: "Nginx 관리 site가 바뀌었습니다. 현재 설정을 다시 조회하세요.",
  invalid_domain: "공개 관리 도메인과 발급 도메인이 일치하지 않습니다.",
  dns_resolution_failed: "공개 DNS를 조회하지 못했습니다. A/AAAA 레코드를 확인하세요.",
  dns_mismatch: "공개 DNS 주소와 설정된 서버 주소가 일치하지 않습니다.",
  challenge_unreachable: "로컬 80 포트 또는 ACME challenge 경로를 확인할 수 없습니다.",
  wrong_webroot: "제품 관리 Nginx site에 고정 ACME webroot include가 없습니다.",
  staging_required: "같은 도메인·DNS·Nginx 설정의 최근 staging 성공이 먼저 필요합니다.",
  preflight_stale: "DNS·포트 사전검증이 만료되었습니다. 새 계획을 만드세요.",
  issuance_failed: "Certbot 발급이 실패했습니다. 원문 대신 감사 digest만 기록됐습니다.",
  certificate_invalid: "발급 결과의 SAN·lineage·timer 검증을 통과하지 못했습니다.",
  attach_unsupported: "보호된 관리 vhost의 TLS 지시문 구조를 안전하게 한정할 수 없습니다.",
  attach_unavailable: "Nginx TLS 연결 사전조건 또는 fault gate가 준비되지 않았습니다.",
  protected_config_invalid: "보호된 관리 vhost의 구조가 변경되어 작업을 차단했습니다.",
  tls_read_back_failed: "SNI 인증서 지문 또는 Nginx·timer read-back이 실패해 자동 원복했습니다.",
  config_replace_confirmation: "Nginx 인증서 지시문 교체 확인이 필요합니다.",
  service_reload_confirmation: "Nginx reload 영향 확인이 필요합니다.",
  issuance_unavailable: "신규 발급 사전조건 또는 fault gate가 준비되지 않았습니다.",
  resource_busy: "다른 Certbot 작업이 실행 중입니다. 완료 후 다시 시도하세요.",
  plan_expired: "계획이 만료되었습니다. 현재 상태로 새 계획을 만드세요.",
  renewal_test_failed: "Certbot 갱신 사전 검증이 실패했습니다. 원문 대신 감사 digest가 기록됐습니다.",
  forensic_lockdown: "감사 원장 무결성 잠금 상태여서 작업이 차단되었습니다.",
};

export function operationErrorCopy(error: unknown, fallback: string): string {
  return error instanceof ApiError ? (OPERATION_MESSAGES[error.code] ?? fallback) : fallback;
}

export function problemLabel(problem: string): string {
  if (problem === "certbot_not_installed") return "Ubuntu Certbot이 설치되지 않았습니다.";
  if (problem === "certbot_timer_disabled") return "certbot.timer가 활성화되지 않았습니다.";
  if (problem === "certbot_timer_inactive") return "certbot.timer가 현재 대기 상태가 아닙니다.";
  if (problem.startsWith("certificate_invalid:")) return `${problem.slice(20)} lineage를 안전하게 읽지 못했습니다.`;
  return "표준 Certbot lineage가 아닌 항목을 발견했습니다.";
}
