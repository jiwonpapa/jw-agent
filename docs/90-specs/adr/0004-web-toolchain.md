# ADR-0004 — Web Toolchain

Status: Accepted  
Authority: Architecture Decision  
Owner: Web Maintainer  
Last reviewed: 2026-07-21

## Decision

React, TypeScript, Vite, Bun, Tailwind CSS v4 CLI, shadcn/ui, TanStack Router/Query, Playwright를 사용합니다.

## 빌드 결정

Tailwind CLI가 CSS를 단독 생성하고 Vite는 생성된 CSS와 app을 bundle합니다. Tailwind Vite plugin을 함께 사용하지 않습니다. shadcn은 source generation 도구이며 runtime dependency registry가 아닙니다.

## 결과

- package manager와 lockfile은 Bun 하나
- exact dependency pin은 P1 compatibility spike에서 확정
- generated route tree/API client 직접 편집 금지
- raw token과 dynamic Tailwind class 금지
- Storybook과 monorepo orchestrator는 MVP 제외
- public management UI에 PWA/service worker/offline mutation 제외
- mobile·tablet은 별도 app이 아니라 같은 responsive web package로 지원

## 공식 기준

- [Tailwind CSS CLI](https://tailwindcss.com/docs/installation/tailwind-cli)
- [shadcn/ui Tailwind v4](https://ui.shadcn.com/docs/tailwind-v4)
- [shadcn/ui CLI](https://ui.shadcn.com/docs/cli)
- [TanStack Router file-based routing](https://tanstack.com/router/latest/docs/routing/file-based-routing)
- [WCAG 2.2](https://www.w3.org/TR/WCAG22/)
- [Playwright accessibility testing](https://playwright.dev/docs/accessibility-testing)
