# Linux PAM Authentication

Status: Accepted  
Authority: Security  
Owner: Security Maintainer  
Last reviewed: 2026-07-21

## Support boundary

MVP 검증 대상은 Ubuntu 24.04 기본 local Linux account와 `pam_unix` username/password입니다. SSSD·LDAP·Kerberos·smartcard·다중 prompt PAM은 system administrator가 구성할 수 있어도 JW Agent가 `SUPPORTED`로 주장하지 않습니다.

## Why authd exists

Ubuntu의 `unix_chkpwd`는 현재 호출 사용자의 password를 확인하는 pam_unix 내부 helper이며 application이 직접 호출하도록 설계되지 않았습니다. 비-root agentd가 임의 Linux account를 안전하게 인증할 수 없으므로 root one-shot `authd`가 필요합니다.

- systemd Unix socket activation
- one connection, one PAM transaction, one response, process exit
- peer credential must be agentd service UID
- no TCP, HTTP, TLS, DB, opsd call, shell, sudo, Linux session
- `ffi-pam` 외 workspace unsafe 금지
- direct `/etc/shadow` read와 custom setuid helper 금지

## PAM transaction

1. `pam_start("jw-agent", supplied_user, bounded_conversation)`
2. trusted proxy channel의 remote address를 `PAM_RHOST`로 설정
3. `pam_authenticate(PAM_DISALLOW_NULL_AUTHTOK)`
4. `pam_acct_mgmt`로 locked·expired·access restriction 확인
5. PAM이 canonicalize한 `PAM_USER`를 다시 읽음
6. NSS에서 UID와 allowed role group 확인
7. UID 0 또는 비허용 group 거부
8. generic result와 canonical subject만 agentd에 반환
9. password buffer zeroize 후 `pam_end`, process exit

`pam_open_session`, `pam_setcred`, `pam_chauthtok`은 호출하지 않습니다. 비밀번호 만료·변경 필요는 generic login 실패와 SSH/console 안내로 처리합니다.

## Conversation boundary

- MVP는 preset username과 password용 masked prompt 하나만 지원
- username/password/request frame에 strict byte limit
- info/error text를 browser에 전달하지 않음
- 추가 OTP·binary·interactive prompt는 `UNSUPPORTED_CONVERSATION`
- password는 argv, environment, URL, log, DB, evidence, core dump에 남기지 않음
- agentd/authd 양쪽에 secret type과 zeroization 적용

## Abuse resistance

- Nginx connection/body/burst limit
- agentd의 source·username·global budget와 progressive delay
- bounded authd concurrency와 queue
- agentd memory의 service-local global·source·subject request budget; 공개 공격이 SSH account를 영구 잠그지 못해야 함
- unknown user, wrong password, locked, denied group의 public status/body 동일
- auth failure reason은 비밀이 제거된 internal code로만 감사
- raw username은 필요 최소 기간만 보존하고 full User-Agent는 저장하지 않음

Accepted package fixture의 control order는 `pam_faildelay.so → pam_unix.so auth → pam_unix.so account`입니다. `pam_faillock`과 persistent failure directory는 사용하지 않습니다. limiter exhaustion 전후 Linux password state와 OpenSSH key login이 변하지 않는지 Ubuntu VM에서 검증합니다.

## FFI ownership review

- `unsafe`는 `ffi-pam`만 허용하고 workspace gate가 다른 crate의 unsafe를 거부합니다.
- application source password buffer와 callback error-path response copy는 explicit zeroize 후 해제합니다.
- 성공 callback response는 Linux-PAM contract에 따라 PAM으로 ownership이 이전됩니다. JW Agent는 외부 PAM module/libpam 내부의 copy가 언제 어떻게 지워지는지 보장한다고 주장하지 않습니다.
- callback은 최대 32 message, masked prompt 하나, info/error text만 허용하고 null pointer·추가 prompt·echo-on을 fail closed 합니다.
- `pam_end`는 성공한 `pam_start` handle에 정확히 한 번 호출하며 session·credential·password change API는 호출하지 않습니다.

## Native dependency gate

`libpam` link와 header/toolchain은 native dependency입니다. build package는 `libpam0g-dev`, runtime link owner는 `libpam0g`이며 `.deb`는 `libpam.so.0` link를 VM에서 확인합니다. `ffi-pam` normal dependency는 `zeroize`와 Linux의 `libc`뿐입니다.

## Sources

- [Ubuntu 24.04 unix_chkpwd](https://manpages.ubuntu.com/manpages/noble/man8/unix_chkpwd.8.html)
- [Linux-PAM pam_start](https://www.man7.org/linux/man-pages/man3/pam_start.3.html)
- [Linux-PAM pam_authenticate](https://man7.org/linux/man-pages/man3/pam_authenticate.3.html)
- [Linux-PAM pam_acct_mgmt](https://www.man7.org/linux/man-pages/man3/pam_acct_mgmt.3.html)
- [Linux-PAM pam_faillock](https://man7.org/linux/man-pages/man8/pam_faillock.8.html)
