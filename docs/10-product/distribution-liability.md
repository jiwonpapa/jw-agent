# Distribution and Responsibility Notice

Status: Draft  
Authority: Product Policy  
Owner: Product Maintainer  
Last reviewed: 2026-07-21

## 계획

- 단일 서버 Agent와 로컬 콘솔은 무료 오픈소스를 기본으로 검토합니다.
- 중앙관제 호스팅·다중 고객·직원 권한·원격 백업·리포트·SSO는 별도 후속 사업입니다.
- 무료 제품에서 광고나 유료 addon이 안전 경고·복구 경로를 가리면 안 됩니다.

## 책임 고지 원칙

- 제품은 서버 손실이 절대 없다고 보증하지 않습니다.
- operation마다 지원 환경, 영향, 원복 범위, 잔여 위험을 승인 전에 표시합니다.
- 사용자는 독립 backup과 recovery access를 유지해야 합니다.
- unsupported/custom environment, 외부 root 변경, 제3자 패키지 장애를 제품 책임으로 단정하지 않습니다.
- 반대로 제품이 실행한 단계와 실패는 ledger에 숨기지 않습니다.

## 동의 시점

- 설치 시 license·privacy·support boundary 확인
- 최초 write 기능 활성화 시 위험·backup 책임 확인
- 공개 access 활성화 시 domain·TLS·credential attack·SSH recovery·firewall 책임 확인
- 각 operation은 구체적인 plan을 별도 승인
- 면책 문구만으로 안전 설계를 대체하지 않음

## 출시 전 필수 문서

- `LICENSE`
- Community Terms / hosted service Terms
- Privacy Notice
- Supported Matrix and Known Limitations
- Security Policy and vulnerability reporting
- Data export/removal policy

라이선스와 법적 면책 문구는 관할권을 반영한 법률 검토 전 확정하지 않습니다. 이 문서는 법률 자문이 아니라 제품 요구사항입니다.
