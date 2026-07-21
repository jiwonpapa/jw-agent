# Documentation Map

Status: Accepted  
Authority: Index  
Owner: Maintainers  
Last reviewed: 2026-07-21

문서는 책임별로 나눕니다. 같은 규칙을 여러 문서에 복사하지 않고 링크합니다.

## 00 Governance

- [문서 권위와 소유권](00-governance/document-authority.md)
- [Spec lifecycle](00-governance/specification-lifecycle.md)
- [빌드·의존성 정책](00-governance/build-and-dependency-policy.md)
- [단일 검증 하네스](00-governance/verification-harness.md)
- [증거 수준](00-governance/evidence-levels.md)
- [Clean-room 참조 정책](00-governance/clean-room-policy.md)

## 10 Product

- [제품 경계](10-product/product-boundary.md)
- [MVP 범위](10-product/mvp-scope.md)
- [지원표](10-product/support-matrix.md)
- [비목표](10-product/non-goals.md)
- [핵심 사용자 흐름](10-product/user-workflows.md)
- [배포 모델과 책임 고지](10-product/distribution-liability.md)

## 20 Architecture

- [시스템과 신뢰 경계](20-architecture/system-context.md)
- [Workspace와 의존 방향](20-architecture/workspace-layout.md)
- [상태 소유권](20-architecture/state-ownership.md)
- [배포 모델](20-architecture/deployment-model.md)
- [공개 HTTPS ingress](20-architecture/public-ingress.md)
- [중앙관제 후속 경계](20-architecture/central-future.md)
- [Local maintenance surfaces ADR](90-specs/adr/0010-local-maintenance-surfaces.md)
- [Certbot one-shot network runner ADR](90-specs/adr/0011-certbot-network-runner.md)

## 30 Domain

- [도메인 지도](30-domain/domain-map.md)
- [Service Adapter 계약](30-domain/service-adapter-contract.md)
- [Safe Operation](30-domain/safe-operation.md)
- [Evidence와 포렌식](30-domain/evidence-forensics.md)

## 40 Contracts and 50 Data

- [Operation lifecycle](40-contracts/operation-lifecycle.md)
- [로컬 인터페이스](40-contracts/local-interfaces.md)
- [보장 등급](40-contracts/assurance-levels.md)
- [로컬 상태](50-data/local-state.md)
- [Ledger·snapshot·보존](50-data/ledger-snapshot-retention.md)

## 60 UI/UX

- [웹 기술과 빌드](60-ui-ux/web-stack.md)
- [정보 구조](60-ui-ux/information-architecture.md)
- [디자인 시스템과 대시보드](60-ui-ux/design-system-dashboard.md)
- [상호작용·접근성](60-ui-ux/interaction-accessibility.md)

## 70 Security

- [권한·Identity·Session](70-security/privilege-and-auth.md)
- [Linux PAM 인증](70-security/pam-authentication.md)
- [공개 접속 보안](70-security/public-access.md)
- [로깅과 포렌식](70-security/logging-and-forensics.md)
- [업데이트와 공급망](70-security/update-supply-chain.md)
- [위협모델](70-security/JW-agent-threat-model.md)

## 80 Delivery and 90 Specs

- [개발 로드맵](80-delivery/roadmap.md)
- [Definition of Done](80-delivery/definition-of-done.md)
- [시험 전략](80-delivery/test-strategy.md)
- [패키징과 릴리스](80-delivery/packaging-release.md)
- [고정·미결정 항목](80-delivery/decision-register.md)
- [Spec index](90-specs/README.md)
