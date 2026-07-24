# UI-MANAGED-CONFIG-WIZARD-V1

Status: Accepted  
Authority: UI Specification  
Owner: Product Designer  
Last reviewed: 2026-07-24

## 작업 흐름

서비스 화면은 고정 root 아래 발견된 설정을 directory/file tree로 보여주고, 설정 변경은
하나의 전체화면 편집 workspace에서 끝냅니다. backend의
`plan → snapshot → apply → validate → reload → verify → rollback` 상태 기계는
사용자에게 마법사 단계로 전가하지 않습니다.

- desktop: 좌측 bounded file tree, 우측 전체 폭 editor
- mobile/tablet: file list에서 editor로 전환하고 명시적인 뒤로가기를 제공
- sticky header: 뒤로가기, resource title·masked path, `저장`과 `취소`
- 편집기 위 기본 설명은 `문법 검사`, `service reload`, `실패 시 이전 설정 자동 복구` 세 가지만 표시
- `저장`은 immutable plan 생성과 승인을 한 흐름으로 수행
- 관리 모드가 유효하면 G2 설정마다 비밀번호를 반복 요구하지 않음
- 관리 모드가 없거나 만료되면 한 번 승격한 뒤 같은 draft에서 저장을 계속함
- 검증 실패는 editor line·간결한 원인·수정 action만 표시
- 성공·자동 원복·수동 복구 필요는 편집기 위 결과 banner로 구분
- diff·assurance·digest·수동 복구 경로·전체 stage는 `기술 세부정보`에 접음
- primary UI에 `계획 만들기`, `G2 제한 작업`, `제한된 설정` 문구를 표시하지 않음
- Nginx site 활성화·비활성화는 file tree와 분리된 보조 action으로만 제공
- right sheet/drawer 안에 editor·plan·approval을 배치하지 않음
- desktop sticky top action, mobile sticky bottom action을 제공
- dirty close는 한 번만 확인하며 draft는 브라우저 영구 저장소에 보존하지 않음

## Acceptance

- 1440px와 390px에서 primary action이 scroll 없이 보임
- service root의 nested directory와 active·inactive existing file을 한 tree에서 탐색
- 차단 파일은 열기/저장 버튼 대신 차단 사유를 짧게 표시
- 별도 wizard route나 다음 단계 이동 없이 편집·저장·결과를 한 화면에서 처리
- 뒤로가기·새로고침·실패 후 해당 줄 복귀
- 관리자 모드 중 비밀번호 재입력 없음; 만료 시 재인증 후 계획 유지
- 빈 파일·무시 행·알 수 없는 directive는 적용 전에 차단
- 저장 double click은 하나의 plan과 operation만 생성
- receipt에서 `이 버전으로 복원`이 새 계획을 생성
