interface StageResult {
  resultCode: string;
}

const NGINX_LINE_PREFIX = "nginx_config_test_failed:line=";
const PHP_FPM_LINE_PREFIX = "php_fpm_config_syntax_line_";

export function nginxSyntaxDiagnosticLine(stages: readonly StageResult[]): number | null {
  for (const stage of stages) {
    if (!stage.resultCode.startsWith(NGINX_LINE_PREFIX)) continue;
    const encoded = stage.resultCode.slice(NGINX_LINE_PREFIX.length);
    if (!/^[1-9][0-9]{0,9}$/.test(encoded)) return null;
    const line = Number.parseInt(encoded, 10);
    if (Number.isSafeInteger(line)) return line;
  }
  return null;
}

export function managedConfigSyntaxDiagnosticLine(stages: readonly StageResult[]): number | null {
  for (const stage of stages) {
    if (!stage.resultCode.startsWith(PHP_FPM_LINE_PREFIX)) continue;
    const encoded = stage.resultCode.slice(PHP_FPM_LINE_PREFIX.length);
    if (!/^[1-9][0-9]{0,9}$/.test(encoded)) return null;
    const line = Number.parseInt(encoded, 10);
    if (Number.isSafeInteger(line)) return line;
  }
  return nginxSyntaxDiagnosticLine(stages);
}

export function operationResultLabel(resultCode: string): string {
  if (resultCode.startsWith(PHP_FPM_LINE_PREFIX)) {
    const line = managedConfigSyntaxDiagnosticLine([{ resultCode }]);
    return line === null
      ? "PHP-FPM 설정 문법검사 실패"
      : `PHP-FPM 문법 오류 · php.ini ${String(line)}번째 줄`;
  }
  if (resultCode.startsWith(NGINX_LINE_PREFIX)) {
    const line = nginxSyntaxDiagnosticLine([{ resultCode }]);
    return line === null
      ? "Nginx 문법검사 실패"
      : `Nginx 문법 오류 · 선택한 설정 ${String(line)}번째 줄`;
  }
  const labels: Record<string, string> = {
    planned: "변경 계획 생성",
    approved: "실행 승인",
    snapshot_durable: "이전 설정 snapshot 저장",
    config_apply_started: "설정 적용 시작",
    config_replaced: "설정 파일 원자 교체",
    nginx_config_valid: "Nginx 문법검사 통과",
    nginx_reloaded: "Nginx reload 완료",
    php_fpm_config_valid: "PHP-FPM 설정 문법검사 통과",
    php_fpm_reloaded: "PHP-FPM reload 완료",
    php_fpm_config_invalid: "PHP-FPM 설정 문법검사 실패",
    managed_config_verified: "설정·서비스 상태 검증 완료",
    nginx_config_test_failed: "Nginx 문법검사 실패",
    rollback_verified: "이전 설정 복원·재검증 완료",
  };
  return labels[resultCode] ?? resultCode;
}
