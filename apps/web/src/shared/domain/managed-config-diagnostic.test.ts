import { describe, expect, it } from "vitest";

import { nginxSyntaxDiagnosticLine, operationResultLabel } from "./managed-config-diagnostic";

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
  });
});
