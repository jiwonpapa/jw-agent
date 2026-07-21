# Clean-room Reference Policy

Status: Accepted  
Authority: Governance  
Owner: Maintainers  
Last reviewed: 2026-07-21

## 독립성

JW Agent는 신규 저장소·crate·DB·protocol·installer·release 체계를 사용합니다.

다음 기존 제품과 코드를 공유하지 않습니다.

- gnuboard7
- g7-installer
- VPSGuard
- 기타 기존 서버 관리 앱

## 허용

- 공개 문서와 동작에서 설계 교훈·실패 사례 기록
- 일반적인 패턴 비교
- 라이선스·보안 경계 평가

## 금지

- source, schema, fixture, protocol frame, UI asset, installer script 복사
- git/path dependency 연결
- 기존 저장소를 vendor 또는 subtree로 포함
- 참조 제품과 호환된다고 오해시키는 명칭 사용

참조 조사는 출처 URL, 관찰 날짜, 채택/거부 이유만 ADR에 남깁니다.

