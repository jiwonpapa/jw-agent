# Core User Workflows

Status: Accepted  
Authority: Product  
Owner: Product Maintainer  
Last reviewed: 2026-07-21

## 1. 서버 상태 확인

1. 사용자는 서버의 공개 HTTPS URL을 직접 엽니다. SSH tunnel은 공개 경로 장애 때만 복구 절차로 사용합니다.
2. 허용된 Linux PAM ID·비밀번호로 로그인합니다.
3. 서버 identity·관찰 시각·role·write 가능 여부를 확인합니다.
4. Attention Queue에서 실패 unit, disk 부족, SSL 만료, 지원 불가를 우선순위대로 봅니다.
5. desktop·tablet·mobile에서 같은 근거와 제한된 로그를 확인합니다.

## 2. Nginx 사이트 상태 변경

1. 발견된 site 목록에서 `제한된 설정 자동 원복 지원`과 지원 근거를 확인합니다.
2. site를 선택합니다.
3. 서버가 생성한 plan에서 현재→목표, 대상 경로, 영향, snapshot, 원복 범위·제외 효과, apply/rollback 검증을 확인합니다.
4. plan이 만료되거나 상태가 drift하면 재계획합니다.
5. 쓰기 권한과 최근 PAM 재인증을 확인합니다.
6. 승인 후 단계 timeline을 SSE로 확인합니다.
7. 결과를 `완료`, `실패·원복 완료`, `실패·수동 복구 필요`로 명확히 구분합니다.

## 3. 공개 모드 활성화·복구

1. 관리자는 먼저 SSH tunnel로 로그인합니다.
2. domain·certificate·protected Nginx resource·firewall 영향을 포함한 plan을 검토합니다.
3. HTTPS 검증이 끝난 뒤 마지막 단계에서 443 공개를 활성화합니다.
4. 실패하면 vhost와 제품이 추가한 firewall rule만 원복합니다.
5. Nginx·TLS 장애 시 SSH tunnel에서 공개 모드를 해제하고 session을 전부 폐기합니다.

## 4. 장애·강제 종료 복구

1. 재시작한 `opsd`가 durable stage와 OS 상태를 read-back합니다.
2. 안전하게 확정할 수 없으면 resource를 `RECOVERY_REQUIRED`로 잠급니다.
3. 사용자는 읽기 진단·evidence export·recovery runbook을 사용할 수 있습니다.

## 5. 감사 연속성 손상

1. ledger 연속성 검사가 실패하면 `FORENSIC_LOCKDOWN`으로 전환합니다.
2. 신규 write는 차단합니다.
3. UI는 손상 범위와 마지막 검증 지점을 보여주고 evidence export를 유지합니다.
