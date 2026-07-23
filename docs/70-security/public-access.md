# Public Access Security

Status: Accepted  
Authority: Security  
Owner: Security Maintainer  
Last reviewed: 2026-07-23

## Exposure rule

Internet에 노출되는 기본 관리 ingress는 valid TLS의 비권한 `jw-edge` 9443입니다. Nginx 443은 선택적 호환 경로입니다. 127.0.0.1-only agentd recovery endpoint, agentd proxy UDS, authd socket, opsd socket은 public network에서 도달할 수 없어야 합니다.

## Activation preconditions

- exact FQDN and Host allowlist
- valid certificate and tested renewal path
- jw-edge TLS·UDS health probe와 선택적 Nginx config test
- at least one non-root allowed admin account
- login budget and bounded authd workers
- SSH recovery path confirmed
- P1에서는 수동 template 제거와 session revoke recovery 절차 확인; P2 typed operation에서는 자동 public disable과 session revoke 검증
- UFW/cloud firewall impact displayed

설치 직후에는 loopback만 활성화합니다. package script가 DNS, certificate, UFW, cloud security group을 자동 변경하지 않습니다.

## Edge controls

- HTTP login 금지; port 80은 credential을 받지 않고 HTTPS redirect/ACME 용도로만 제한
- jw-edge가 TLS handshake·connection·header bound와 trusted peer address를 소유하고 agentd가 endpoint별 body·auth budget을 소유
- forwarded headers are accepted only from dedicated proxy UDS
- Host confusion, absolute-form target, oversized JSON, slow request fail closed
- external script/font/CDN/advertisement/telemetry 없음
- auth/API/no-store, CSP, clickjacking defense, HSTS after certificate validation
- SSE와 log query도 per-session/global concurrency budget 적용

## Firewall

- active UFW에서는 제품이 소유한 9443 또는 선택적 443 rule만 plan 후 추가
- inactive UFW를 임의 활성화하지 않음
- SSH rule과 기존 user rule을 절대 변경하지 않음
- cloud firewall은 제품 밖의 필요한 작업으로 표시
- 공개 mode 실패/disable 때 제품이 만든 rule만 제거

## Self-lockout defense

- jw-edge unit·certificate mapping과 public management vhost는 `system-owned/protected`
- `opsd`가 고정 Unix health socket의 실시간 응답을 받지 못하면 Nginx stop을 side effect 전에 거부
- Nginx site toggle·bulk operation·일반 config editor에서 제외
- Nginx/TLS failure banner와 SSH recovery runbook 제공
- public disable은 공개 session 전부 revoke
- SSH fallback이 확인되지 않으면 public activation 완료 불가
- public·recovery session cookie는 서로의 ingress에서 수락하지 않음

## Mobile and shared-device risks

- persistent login과 browser storage token 없음
- password manager와 paste 허용; 직접 만든 keypad 금지
- background 복귀 후 session·SSE·canonical operation state 재확인
- sensitive page service-worker/offline cache 금지
- logout에서 `Clear-Site-Data` 적용 가능성을 구현 단계에서 검증

## Additional authentication policy

추가 인증은 `disabled | risky_operations | all_mutations` 설정으로 제공합니다. 기본은 `disabled`이고 `risky_operations`를 권장합니다. PAM 재인증은 정책과 무관하게 write 승인과 정책 변경에 항상 필요합니다. 공개 root-equivalent 관리에서 password-only 선택은 잔여 위험 경고와 감사 event를 남기며, 정책 완화는 추가 경고를 요구합니다. 첫 provider `totp/v1`은 recovery ingress의 admin PAM 뒤에서만 등록·초기화할 수 있고, non-disabled 정책의 typed-operation 승인은 exact-plan PAM claim과 single-use TOTP claim을 원자적으로 소비합니다. Linux PAM·SSH MFA는 변경하지 않으며 console recovery bypass는 제공하지 않습니다. 등록·복구·replay 계약과 VM 증거는 [AUTH-TOTP-STEP-UP-V1](../90-specs/auth/totp-step-up-v1.md)을 따릅니다.
