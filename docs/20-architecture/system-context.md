# System Context and Trust Boundaries

Status: Accepted  
Authority: Architecture  
Owner: Architecture Maintainer  
Last reviewed: 2026-07-23

```text
Public Browser ─HTTPS─> jw-edge :9443 ─────UDS─> agentd (non-root)
                    └─> optional Nginx :443 ─UDS─┘
Recovery Browser ─SSH tunnel─> loopback ────────> agentd
                                                    │
                         password, one request UDS ├──> authd (root, one-shot)
                                                    │       └──> Linux PAM/NSS
                                   typed operation └──> opsd (root, networkless)
                                                            └──> Ubuntu services
                     manual access └──> loopback OpenSSH (non-root account)
```

## 신뢰 경계

1. Internet Browser ↔ jw-edge 또는 Nginx: TLS, Host, request/body/rate limit, forwarded header 재작성
2. public edge ↔ agentd: 전용 UDS, trusted proxy metadata, REST/SSE schema
3. Recovery Browser ↔ agentd: loopback·SSH, forwarded header 불신
4. agentd ↔ authd: password-bearing one-request UDS, peer UID, size, timeout, zeroize
5. authd ↔ PAM/NSS: dedicated PAM service, account·group policy, raw error 비노출
6. agentd ↔ opsd: socket permission, peer UID, version, size, typed operation
7. opsd ↔ OS: canonical path, symlink defense, fixed argv, timeout, resource lock
8. 저장 상태 ↔ runtime: digest, transaction, ledger chain, crash recovery
9. package ↔ host: signature, checksum, SBOM, maintainer scripts
10. agentd ↔ OpenSSH: short-lived server ticket, strict host key, Linux user authorization, bounded terminal/SFTP session
11. jw-edge ↔ TLS key/runtime: root provisioned read-only key, 비권한 listener, readiness와 systemd sandbox

## 중앙 seam

향후 중앙관제는 `agentd`의 outbound-only client로 연결합니다. `authd`와 `opsd`는 중앙 주소·TLS·tenant를 알지 못합니다. 중앙과 공개 ingress가 사라져도 loopback 복구가 유지됩니다.

## 보안 불변식

- 외부 네트워크에서 agentd 내부 endpoint·authd·opsd 도달 불가
- Browser가 root credential을 획득하지 않음
- root 계정은 웹에 로그인할 수 없음
- Nginx 관리 vhost는 일반 Nginx operation 대상이 아님
- 독립 edge가 준비되지 않으면 Nginx stop을 노출하거나 실행하지 않음
- agentd compromise가 arbitrary root primitive로 확대되지 않음
- unsupported service는 write로 승격되지 않음
- evidence 손상이 신규 write를 허용하지 않음
- terminal/SFTP가 opsd root mutation 경계를 우회하지 않음
