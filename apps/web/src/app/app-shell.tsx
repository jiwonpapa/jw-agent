import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useRouter } from "@tanstack/react-router";
import {
  Activity,
  BadgeCheck,
  GlobeLock,
  FolderOpen,
  LogOut,
  Menu,
  PackageSearch,
  Server,
  Settings2,
  ShieldCheck,
  SquareTerminal,
} from "lucide-react";
import { useState, type ReactNode } from "react";

import { logout } from "../shared/api/client";
import { hostQueryOptions, sessionQueryOptions } from "../shared/api/queries";
import { NAV_ITEMS, PRODUCT, ROLE_LABELS } from "../shared/content/copy";
import { formatDateTime } from "../shared/domain/format";
import { Button } from "../shared/ui/button";
import { cn } from "../shared/ui/cn";
import { Sheet } from "../shared/ui/sheet";
import { StatusMark } from "../shared/ui/status-mark";

const navigationIcons = {
  overview: Activity,
  nginx: Server,
  certificates: BadgeCheck,
  integrations: PackageSearch,
  terminal: SquareTerminal,
  files: FolderOpen,
  access: ShieldCheck,
} as const;

function Navigation({ compact = false, onNavigate }: { compact?: boolean; onNavigate?: () => void }) {
  return (
    <nav aria-label="주요 메뉴" className="space-y-1">
      {NAV_ITEMS.map((item) => {
        const Icon = navigationIcons[item.key];
        return (
          <Link
            key={item.href}
            to={item.href}
            onClick={onNavigate}
            className={cn(
              "flex min-h-11 items-center gap-3 rounded-control px-3 text-sm font-medium text-muted transition-colors hover:bg-subtle hover:text-text",
              compact && "justify-center px-0 xl:justify-start xl:px-3",
            )}
            activeProps={{ className: "bg-subtle text-text" }}
          >
            <Icon aria-hidden="true" className="size-4 shrink-0" />
            <span className={cn(compact && "sr-only xl:not-sr-only")}>{item.label}</span>
          </Link>
        );
      })}
    </nav>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const [navigationOpen, setNavigationOpen] = useState(false);
  const [logoutPending, setLogoutPending] = useState(false);
  const session = useQuery(sessionQueryOptions).data;
  const host = useQuery(hostQueryOptions);
  const queryClient = useQueryClient();
  const router = useRouter();

  if (session === undefined) return null;

  async function handleLogout(): Promise<void> {
    setLogoutPending(true);
    try {
      await logout();
    } finally {
      queryClient.clear();
      setLogoutPending(false);
      await router.navigate({
        to: "/login",
        search: { returnTo: "/overview" },
        replace: true,
      });
    }
  }

  const hostname = host.data?.hostname ?? "서버 이름 확인 중";
  const observedAt = host.data?.observedAt;

  return (
    <div className="app-shell">
      <a
        href="#main-content"
        className="fixed left-3 top-3 z-50 -translate-y-20 rounded-control bg-action px-3 py-2 text-sm font-semibold text-action-foreground focus:translate-y-0"
      >
        본문으로 건너뛰기
      </a>

      <header className="sticky top-0 z-30 flex h-14 items-center border-b border-border bg-surface/95 px-3 backdrop-blur md:px-5">
        <Button
          aria-label="메뉴 열기"
          className="mr-2 lg:hidden"
          size="icon"
          variant="ghost"
          onClick={() => setNavigationOpen(true)}
        >
          <Menu aria-hidden="true" className="size-5" />
        </Button>

        <div className="flex min-w-0 flex-1 items-center gap-3">
          <div className="flex size-8 shrink-0 items-center justify-center rounded-control bg-text text-surface">
            <Server aria-hidden="true" className="size-4" />
          </div>
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-text">{hostname}</p>
            <p className="truncate text-xs text-muted">
              {PRODUCT.name} · {session.ingress === "public" ? "공개 HTTPS" : "SSH 복구"}
            </p>
          </div>
        </div>

        <div className="ml-3 hidden items-center gap-3 sm:flex">
          <StatusMark
            label={ROLE_LABELS[session.subject.role]}
            tone={session.subject.role === "admin" ? "info" : "neutral"}
          />
          <span className="h-5 w-px bg-border" aria-hidden="true" />
          <span className="text-sm text-muted">{session.subject.username}</span>
        </div>
      </header>

      <div className="app-body">
        <aside className="app-nav-desktop border-r border-border bg-surface px-2 py-4 xl:px-3">
          <Navigation compact />
        </aside>

        <main id="main-content" className="app-workspace">
          {children}
        </main>

        <aside className="app-inspector-desktop border-l border-border bg-surface px-5 py-6">
          <p className="text-xs font-semibold uppercase tracking-wider text-muted">현재 세션</p>
          <dl className="mt-5 space-y-5 text-sm">
            <div>
              <dt className="text-muted">Linux 계정</dt>
              <dd className="mt-1 font-medium text-text">{session.subject.username}</dd>
            </div>
            <div>
              <dt className="text-muted">권한</dt>
              <dd className="mt-1 font-medium text-text">{ROLE_LABELS[session.subject.role]}</dd>
            </div>
            <div>
              <dt className="text-muted">접속 경로</dt>
              <dd className="mt-1 font-medium text-text">
                {session.ingress === "public" ? "공개 HTTPS" : "Loopback · SSH 터널"}
              </dd>
            </div>
            <div>
              <dt className="text-muted">세션 만료</dt>
              <dd className="mt-1 font-medium text-text">{formatDateTime(session.idleExpiresAt)}</dd>
            </div>
            <div>
              <dt className="text-muted">관찰 시각</dt>
              <dd className="mt-1 font-medium text-text">
                {observedAt === undefined ? "확인 중" : formatDateTime(observedAt)}
              </dd>
            </div>
          </dl>
          <Button
            className="mt-8 w-full"
            variant="secondary"
            disabled={logoutPending}
            onClick={() => void handleLogout()}
          >
            <LogOut aria-hidden="true" className="size-4" />
            {logoutPending ? "로그아웃 중" : "로그아웃"}
          </Button>
        </aside>
      </div>

      <Sheet
        open={navigationOpen}
        onOpenChange={setNavigationOpen}
        title={PRODUCT.name}
        description={`${hostname} · ${ROLE_LABELS[session.subject.role]}`}
      >
        <Navigation onNavigate={() => setNavigationOpen(false)} />
        <div className="mt-8 border-t border-border pt-5">
          <div className="flex items-center gap-3 text-sm text-muted">
            {session.ingress === "public" ? (
              <GlobeLock aria-hidden="true" className="size-4" />
            ) : (
              <Settings2 aria-hidden="true" className="size-4" />
            )}
            {session.ingress === "public" ? "공개 HTTPS" : "SSH 복구 접속"}
          </div>
          <Button
            className="mt-4 w-full"
            variant="secondary"
            disabled={logoutPending}
            onClick={() => void handleLogout()}
          >
            <LogOut aria-hidden="true" className="size-4" />
            로그아웃
          </Button>
        </div>
      </Sheet>
    </div>
  );
}
