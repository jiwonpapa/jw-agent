# OPS-MANAGED-CONFIG-DIAGNOSTIC-V1

Status: Accepted  
Authority: Operation Specification  
Owner: Managed Configuration Maintainer  
Last reviewed: 2026-08-03

## 목적

서비스 공식 validator 결과를 비밀·원문 출력 없이 구조화하여 정확한 service,
managed resource, file, line, column과 수정 가능한 원인을 UI와 immutable receipt에
제공합니다.

## Contract

각 diagnostic은 다음 필드를 가집니다.

- `service`: `nginx | apache | php_fpm`
- `validator`: fixed command registry의 validator ID
- `resourceId`: managed root 안에서 식별된 opaque resource ID 또는 `null`
- `maskedPath`: managed root 기준 표시 경로 또는 `null`
- `line`, `column`: validator가 양의 위치를 제공할 때만 설정
- `severity`: `error | warning`
- `code`: allowlisted stable diagnostic code
- `message`: code에 대응하는 bounded 비밀 비포함 설명
- `relatedChangedLines`: candidate diff와 겹치는 줄만 bounded 정수 목록으로 제공
- `causeCandidateLines`: 공식 오류 줄보다 앞선 selected diff 중 parser 중단 원인일
  가능성이 있는 줄. 원인 확정이 아닌 참고 후보

목록은 최대 32개, message는 최대 240 bytes, related line은 diagnostic당 최대 16개로
제한합니다.

## Source and mapping

- Nginx는 `nginx -t`, Apache는 `apache2ctl configtest`, PHP-FPM은
  `php-fpm8.3 -t`가 권위 validator입니다.
- parser는 stdout·stderr 전체를 성공 근거로 저장하지 않고 bounded capture에서
  allowlisted pattern만 추출합니다.
- absolute path가 adapter의 service-owned root 안에 있고 discovery 정책을 충족할 때만
  opaque resource ID와 masked path로 변환합니다.
- root 밖 path, private-key·credential 후보, invalid UTF-8, control character와
  validator가 보고하지 않은 위치는 노출하거나 추측하지 않습니다.
- selected file과 다른 include file의 오류도 같은 managed root 안이면 해당 resource로
  연결합니다.
- Nginx·Apache validator가 활성 symlink 경로를 보고하면 exact allowlisted
  available/enabled 쌍만 현재 selected source로 역매핑합니다.
- `relatedChangedLines`는 진단 resource가 selected resource와 같을 때만 계산합니다.
  다른 include resource의 같은 줄 번호는 변경 원인으로 연결하지 않습니다.
- native output이 위치를 제공하지 않으면 file·line·column은 `null`이며 UI는 일반
  validator 실패로 표시합니다.
- validator가 보고한 줄은 parser가 오류를 처음 감지한 위치이며 실제 오타의 시작
  위치라고 단정하지 않습니다. Nginx `unknown_directive`·`unexpected_token`은 앞
  8줄 안의 selected diff 중 세미콜론과 블록 구분자로 끝나지 않는 가장 가까운 줄
  하나만 `causeCandidateLines`로 표시합니다. 공식 validator 줄 번호를 임의로
  앞당기거나 후보를 오류 확정으로 표현하지 않습니다.

## Evidence integrity

- safe diagnostic JSON과 validator evidence digest를 결합해 ledger event
  `evidenceDigest`를 생성합니다.
- command class·exit·timeout·stdout/stderr digest·truncation은 raw output 없이 같은
  event sequence에 결합하며 command row와 event digest 불일치는 fail closed입니다.
- safe diagnostic payload는 ledger event sequence에 결합된 별도 SQLite row에 저장하고
  receipt 조회 시 digest를 다시 검증합니다.
- row 누락, JSON 변조, digest 불일치는 `FORENSIC_LOCKDOWN`입니다.
- raw command output, canonical path와 config body는 SQLite, receipt, REST, browser
  storage와 audit log에 저장하지 않습니다.

## UX

- Monaco marker와 Problems panel은 structured diagnostic만 사용합니다.
- 첫 오류만 강조하되 모든 bounded diagnostic을 볼 수 있어야 합니다.
- error는 apply 실패를 의미하며 warning은 adapter 정책이 명시적으로 허용한 경우에만
  저장을 계속할 수 있습니다.
- changed hunk와 겹침은 원인 확정이 아니므로 `변경한 줄과 겹침`으로만 표시합니다.
- `line`은 빨간 오류 marker, `causeCandidateLines`는 노란 원인 후보 marker로
  구분하며 두 위치를 바꾸거나 합치지 않습니다.

## Acceptance

- Nginx selected file와 다른 include file의 file·line 추출
- Nginx 누락 종결자 시 공식 validator 줄은 보존하고 같은 selected resource의 가까운
  이전 changed line만 별도 원인 후보로 표시
- Apache path·line 추출과 위치 없는 `Syntax error` fallback
- PHP-FPM stdout·stderr의 warning/error와 line 추출
- root 밖 path·secret-like output·malformed line·32개 초과 진단 차단
- diagnostic payload·validator digest 변조 시 ledger read fail closed
- REST/OpenAPI generated type과 Monaco marker가 같은 contract 사용

## Evidence

- `jw-agent_0.2.0~p2.24_amd64.deb`
- SHA-256 `9c3779180facc4cd4d4e83a17b773bb77488b401d8d138aa131bfb4cfd3d2ffc`
- Ubuntu 24.04 `VM-P2-MANAGED-CONFIG`: Nginx·Apache·PHP-FPM structured
  diagnostic, exact official error line, separate cause candidate, selected diff relation,
  rejected source 비노출과 exact rollback PASS. Nginx 실검증은 official line 851,
  cause candidate line 845를 확인했고 validator timeout·stderr cap도 구조화된 command
  evidence로 확인했습니다.
- `p2-vm` 28/28, `p2-browser` 8/8 및 Playwright 45/45 PASS
- [실제 p2.23 Monaco workspace와 인라인 복원 표면](../../../output/vm/jw-agent-p2.23-editor-history.png)
