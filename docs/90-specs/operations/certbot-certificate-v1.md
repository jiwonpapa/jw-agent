# OPS-CERTBOT-CERTIFICATE-V1

Status: Accepted  
Authority: Operation Specification  
Owner: Certificate Lifecycle Maintainer  
Last reviewed: 2026-07-21

## 목적

Ubuntu apt Certbot과 Nginx webroot를 이용해 certificate를 안전하게 발급·연결하고, systemd timer와 dry-run으로 갱신 가능성을 확인합니다.

## 비목표

- ACME client·CA·DNS provider 구현
- wildcard·DNS-01·외부 provider credential 보관
- arbitrary Certbot plugin/argv, certificate private key 다운로드
- DNS record·cloud firewall·user-owned vhost 자동 변경
- CA가 이미 기록한 issuance·rate-limit effect의 rollback 보장

## Operations and assurance

- `certbot.certificate.issue/v1`: CA external effect `G1`, product-owned local attach `G2`
- `certbot.certificate.renew_test/v1`: read-mostly external validation `G1`
- `certbot.certificate.attach/v1`: managed Nginx fragment `G2`
- schema version `1`, Ubuntu apt Certbot + `webroot` + standard Nginx만 지원

## Typed input

- canonical lower-case FQDN list, primary FQDN, account email, ToS consent
- discovered managed Nginx site/resource ID and fixed webroot capability
- environment `staging | production`
- expected DNS/address, Nginx/config and certificate inventory digests
- idempotency key, exact plan hash, recent PAM reauth, policy-required additional auth

path, plugin name, command, environment variable와 key material은 입력받지 않습니다. 국제화 domain은 IDNA canonicalization 결과와 display value를 함께 확인합니다.

## Plan and preflight

- public DNS A/AAAA와 host address 비교; mismatch·unknown은 production 차단
- 80/443 listener, external challenge reachability, Nginx config, webroot ownership 확인
- existing certificate·SAN·expiry·renewal config와 conflicting managed site 발견
- staging success evidence 없으면 production approval 차단
- CA rate-limit·issuance 비가역성, expected downtime, local rollback 범위를 표시
- certificate/Nginx resource와 global Certbot lock 획득

## Execution

1. ledger·snapshot continuity와 local managed Nginx fragment snapshot
2. fixed `certbot certonly --webroot` command class를 bounded process runner로 실행
3. certificate path·owner·mode·SAN·chain·expiry를 read-back; private key content는 읽거나 기록하지 않음
4. managed Nginx TLS fragment plan 생성·별도 승인 확인
5. atomic attach, `nginx -t`, reload, HTTPS/SNI health probe
6. `certbot.timer` enabled/active와 renewal config를 read-back
7. local attach까지 검증되면 terminal receipt

production issuance가 성공한 뒤 local attach가 실패하면 certificate issuance 자체는 되돌릴 수 없습니다. local Nginx config만 이전 상태로 G2 원복하고 receipt는 CA effect와 local rollback을 분리해 기록합니다.

## Renewal

- 임의 cron을 만들지 않고 distribution `certbot.timer`를 사용
- `certbot renew --dry-run`은 manual high-cost operation으로 timeout·output cap 적용
- renewal hook은 제품이 소유한 fixed deploy hook만 허용하고 Nginx syntax·reload·health 검증
- expiry thresholds는 typed config로 관리하고 관찰 timestamp와 함께 경고

## Secret and evidence

account email은 표시·export 시 mask할 수 있으며 private key, ACME account secret, challenge token, full command output은 로그하지 않습니다. receipt는 domain, environment, command class, bounded/redacted result, certificate fingerprint/SAN/expiry, Nginx digest, timer/dry-run 상태와 rollback 결과만 기록합니다.

## Typed errors

`unsupported_environment`, `invalid_domain`, `dns_mismatch`, `challenge_unreachable`, `staging_required`, `rate_limit_risk`, `certbot_busy`, `issuance_failed`, `certificate_invalid`, `attach_failed`, `renewal_test_failed`, `rollback_failed`, `recovery_required`.

## Acceptance scenarios

- staging issue, production issue after staging, existing valid certificate no-op
- DNS mismatch, closed port, wrong webroot, failed challenge and timeout
- SAN/chain/expiry read-back mismatch
- attach syntax/reload/HTTPS failure with local rollback
- production issuance succeeds but attach fails: G1/G2 split receipt
- concurrent Certbot request and duplicate idempotency behavior
- timer disabled/missing and renewal dry-run failure
- no secret in argv evidence, DB, logs, browser storage or diagnostic export

실제 public CA production test는 전용 disposable domain·VM·rate budget이 준비된 release lane에서만 수행합니다. 일반 VM lane은 staging ACME와 deterministic failure fixtures를 사용합니다.
