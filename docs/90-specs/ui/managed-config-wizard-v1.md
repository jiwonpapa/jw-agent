# UI-MANAGED-CONFIG-WIZARD-V1

Status: Accepted  
Authority: UI Specification  
Owner: Product Designer  
Last reviewed: 2026-07-23

## 작업 흐름

설정 변경은 하나의 전체화면 workspace에서 `편집 → 검증 → 변경 확인·적용 → 결과`로 진행합니다.

- sticky header: resource title·masked path, 취소, 현재 단계의 primary action
- 편집 action은 `검증하기`; 서버에 반영하지 않음
- 검증 실패는 editor line·간결한 원인·수정 action만 표시
- 확인 화면은 changed lines, service action, downtime 가능성만 기본 표시
- assurance·digest·수동 복구 경로·전체 stage는 `기술 세부정보`에 접음
- 관리 모드가 유효하면 G2 설정마다 비밀번호를 반복 요구하지 않음
- 관리 모드가 없거나 만료되면 inline step-up 뒤 같은 단계로 복귀
- 결과는 성공·자동 원복·수동 복구 필요를 구분하고 stage timeline은 접음
- desktop sticky top action, mobile sticky bottom action을 제공
- dirty close는 한 번만 확인하며 draft는 브라우저 영구 저장소에 보존하지 않음

## Acceptance

- 1440px와 390px에서 primary action이 scroll 없이 보임
- 단계 이동·뒤로가기·새로고침·실패 후 해당 줄 복귀
- 관리자 모드 중 비밀번호 재입력 없음; 만료 시 재인증 후 계획 유지
- 빈 파일·무시 행·알 수 없는 directive는 적용 전에 차단
- receipt에서 `이 버전으로 복원`이 새 계획을 생성

