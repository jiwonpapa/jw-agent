import type { ErrorComponentProps } from "@tanstack/react-router";

import { SurfaceState } from "../shared/ui/surface-state";

export function RouteError({ error, reset }: ErrorComponentProps) {
  return (
    <main className="mx-auto max-w-3xl px-4 py-16">
      <SurfaceState
        kind="error"
        title="화면을 표시하지 못했습니다"
        description="현재 경로의 화면 상태를 복구할 수 없습니다. 다시 불러와 주세요."
        detail={import.meta.env.DEV ? error.message : undefined}
        action={{ label: "다시 불러오기", onClick: reset }}
      />
    </main>
  );
}
