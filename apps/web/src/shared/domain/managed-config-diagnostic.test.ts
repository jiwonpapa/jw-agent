import { describe, expect, it } from "vitest";

import {
  managedConfigDiagnostics,
  managedConfigSyntaxDiagnosticLine,
  nginxSyntaxDiagnosticLine,
  operationResultLabel,
} from "./managed-config-diagnostic";

describe("managed config diagnostics", () => {
  it("accepts only the bounded selected-resource line code", () => {
    expect(nginxSyntaxDiagnosticLine([{ resultCode: "nginx_config_test_failed:line=17" }])).toBe(17);
    expect(nginxSyntaxDiagnosticLine([{ resultCode: "nginx_config_test_failed:line=0" }])).toBeNull();
    expect(nginxSyntaxDiagnosticLine([{ resultCode: "nginx_config_test_failed:line=17:secret" }])).toBeNull();
    expect(nginxSyntaxDiagnosticLine([{ resultCode: "nginx_config_test_failed:line=4294967295" }])).toBe(4294967295);
  });

  it("turns known ledger codes into operator copy", () => {
    expect(operationResultLabel("nginx_config_valid")).toBe("Nginx 문법검사 통과");
    expect(operationResultLabel("nginx_config_test_failed:line=9")).toBe(
      "Nginx 문법 오류 · 선택한 설정 9번째 줄",
    );
    expect(operationResultLabel("nginx_config_test_failed:line=9:secret")).toBe(
      "Nginx 문법검사 실패",
    );
    expect(managedConfigSyntaxDiagnosticLine([{ resultCode: "php_fpm_config_syntax_line_42" }])).toBe(42);
    expect(managedConfigSyntaxDiagnosticLine([{ resultCode: "php_fpm_config_syntax_line_0" }])).toBeNull();
    expect(operationResultLabel("php_fpm_config_syntax_line_42")).toBe(
      "PHP-FPM 문법 오류 · php.ini 42번째 줄",
    );
  });

  it("prefers structured diagnostics and only marks the open resource", () => {
    const stages = [{
      resultCode: "nginx_config_test_failed",
      diagnostics: [{
        resourceId: "ngf_include",
        maskedPath: "/etc/nginx/conf.d/include.conf",
        line: 13,
        column: null,
        severity: "error" as const,
        code: "unknown_directive",
        message: "Nginx가 알 수 없는 지시어를 발견했습니다.",
        relatedChangedLines: [],
        causeCandidateLines: [9],
      }],
    }];
    expect(managedConfigDiagnostics(stages)).toHaveLength(1);
    expect(managedConfigDiagnostics(stages)[0]?.causeCandidateLines).toEqual([9]);
    expect(managedConfigSyntaxDiagnosticLine(stages, "ngf_include")).toBe(13);
    expect(managedConfigSyntaxDiagnosticLine(stages, "ngf_open")).toBeNull();
  });
});
