export const PRODUCT = {
  name: "JW Agent",
  edition: "Single Server",
} as const;

export const NAV_GROUPS = [
  {
    label: "서버",
    items: [
      { href: "/overview", label: "개요", key: "overview" },
      { href: "/services", label: "서비스", key: "services" },
    ],
  },
  {
    label: "운영 도구",
    items: [
      { href: "/terminal", label: "터미널", key: "terminal" },
      { href: "/files", label: "SFTP", key: "files" },
    ],
  },
  {
    label: "보안",
    items: [
      { href: "/firewall", label: "방화벽", key: "firewall" },
      { href: "/settings/access", label: "접속 및 보안", key: "access" },
    ],
  },
] as const;

export const CATALOG_NAV_ITEM = {
  href: "/integrations",
  label: "통합 카탈로그",
  key: "integrations",
} as const;

export const AUTH_COPY = {
  title: "서버에 로그인",
  description: "Ubuntu의 허용된 Linux 계정으로 인증합니다.",
  username: "Linux 아이디",
  password: "비밀번호",
  submit: "로그인",
  submitting: "인증 중",
  showPassword: "비밀번호 표시",
  hidePassword: "비밀번호 숨기기",
  genericError: "아이디 또는 비밀번호를 확인해 주세요.",
  unavailable: "현재 PAM 인증을 사용할 수 없습니다. 잠시 후 다시 시도해 주세요.",
  httpsRequired: "공개 접속에서는 유효한 HTTPS 연결이 필요합니다.",
  recovery: "SSH 터널을 통한 복구 접속입니다.",
  public: "공개 HTTPS 접속입니다.",
} as const;

export const ROLE_LABELS = {
  admin: "관리자",
  operator: "작업자",
  viewer: "읽기 전용",
} as const;

export const OBSERVATION_LABELS = {
  observed: "정상 관찰",
  partial: "부분 관찰",
  not_installed: "설치되지 않음",
  unsupported_platform: "지원하지 않음",
} as const;

export const SERVICE_STATE_LABELS = {
  running: "실행 중",
  active: "활성",
  failed: "실패",
  stopped: "중지",
  transitioning: "전환 중",
  unknown: "알 수 없음",
} as const;

export const SERVICE_SUPPORT_LABELS = {
  supported_observe: "관리 지원 · 현재 읽기 전용",
  known_read_only: "알려진 서비스 · 읽기 전용",
  discovered_read_only: "발견된 서비스 · 읽기 전용",
  system_internal: "시스템 내부",
} as const;

export const SERVICE_CATEGORY_LABELS = {
  web: "웹",
  runtime: "애플리케이션 실행",
  database: "데이터베이스",
  cache: "캐시",
  access: "원격 접속",
  security: "보안",
  certificate: "인증서",
  container: "컨테이너",
  monitoring: "모니터링",
  custom: "사용자 정의",
  system: "시스템",
  other: "기타",
} as const;

export const POLICY_LABELS = {
  disabled: {
    label: "꺼짐",
    description: "추가 인증을 요청하지 않습니다. PAM 로그인은 계속 필요합니다.",
  },
  risky_operations: {
    label: "위험 작업만",
    description: "서버가 위험 작업으로 판정한 변경에 추가 인증을 요구합니다.",
  },
  all_mutations: {
    label: "모든 변경",
    description: "설정 변경을 포함한 모든 쓰기 요청에 추가 인증을 요구합니다.",
  },
} as const;

export const POLICY_PROVIDER_LABELS = {
  not_implemented: "추가 인증 제공자가 아직 구현되지 않았습니다.",
  not_configured: "추가 인증 제공자가 설정되지 않았습니다.",
  ready: "추가 인증 제공자를 사용할 수 있습니다.",
  unavailable: "등록된 추가 인증 제공자를 현재 사용할 수 없습니다.",
} as const;
