# Web Stack and Build Pipeline

Status: Accepted  
Authority: UI Architecture  
Owner: Web Maintainer  
Last reviewed: 2026-07-21

## Stack

- React + TypeScript
- Vite SPA bundler
- Bun runtime, package manager, scripts, lockfile
- Tailwind CSS v4 and `@tailwindcss/cli`
- shadcn/ui source-owned primitives
- TanStack Router file-based routes
- TanStack Query server-state cache
- generated OpenAPI TypeScript client
- Playwright browser evidence
- CodeMirror 6 shared managed-text editor and unified diff

도입 시점에 호환되는 최신 stable 조합을 확인한 뒤 exact pin합니다. manifest와 release 명령에 `latest`를 남기지 않습니다.

## 단일 CSS pipeline

Tailwind CLI만 CSS를 생성하고 Vite는 생성 결과를 bundle합니다. `@tailwindcss/vite` plugin을 동시에 사용하지 않습니다. shadcn CLI는 component 생성 시에만 쓰며 runtime registry 호출은 없습니다.

## Package boundary

```text
apps/web/src/
  app/              # router, query client, theme, error boundary
  routes/           # composition and typed route inputs
  features/         # auth, overview, nginx, operations, access settings
  shared/api/       # generated client, SSE, Problem Details
  shared/domain/    # status meaning, formatter, capability view
  shared/ui/        # tokenized shadcn primitives
```

- `shared/ui`는 API를 모릅니다.
- route는 직접 fetch하지 않습니다.
- feature는 다른 feature의 내부 component를 import하지 않습니다.
- API response type을 화면에서 재정의하지 않습니다.

## 빌드지옥 금지

MVP에는 Storybook, CSS-in-JS runtime, second package manager, Nx/Turborepo, microfrontend, Tailwind plugin 이중화를 넣지 않습니다.

공개 관리 UI에는 PWA manifest, service worker, offline mutation/cache를 넣지 않습니다. 인증·operation 화면은 항상 canonical server state를 다시 확인합니다.
