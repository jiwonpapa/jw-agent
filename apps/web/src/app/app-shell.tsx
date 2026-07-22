import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useRouter } from "@tanstack/react-router";
import {
  Activity,
  ChevronDown,
  GlobeLock,
  ListTree,
  FolderOpen,
  LogOut,
  Menu,
  PackageSearch,
  Server,
  Settings2,
  ShieldCheck,
  SquareTerminal,
  UserRound,
} from "lucide-react";
import { useState, type ReactNode } from "react";

import { logout } from "../shared/api/client";
import { hostQueryOptions, sessionQueryOptions } from "../shared/api/queries";
import { CATALOG_NAV_ITEM, NAV_GROUPS, PRODUCT, ROLE_LABELS } from "../shared/content/copy";
import { formatDateTime } from "../shared/domain/format";
import { Button } from "../shared/ui/button";
import { cn } from "../shared/ui/cn";
import { Sheet } from "../shared/ui/sheet";
import { StatusMark } from "../shared/ui/status-mark";

const navigationIcons = {
  overview: Activity,
  services: ListTree,
  integrations: PackageSearch,
  terminal: SquareTerminal,
  files: FolderOpen,
  access: ShieldCheck,
} as const;

function Navigation({ compact = false, onNavigate }: { compact?: boolean; onNavigate?: () => void }) {
  return (
    <nav aria-label="주요 메뉴" className="flex min-h-full flex-col">
      <div className="space-y-6">
        {NAV_GROUPS.map((group) => (
          <div key={group.label}>
            <p className={cn("mb-2 px-3 text-[0.6875rem] font-semibold uppercase tracking-wider text-muted", compact && "sr-only xl:not-sr-only")}>
              {group.label}
            </p>
            <div className="space-y-1">
              {group.items.map((item) => (
                <NavigationLink key={item.href} item={item} compact={compact} onNavigate={onNavigate} />
              ))}
            </div>
          </div>
        ))}
      </div>
      <div className="mt-auto border-t border-border pt-3">
        <NavigationLink item={CATALOG_NAV_ITEM} compact={compact} onNavigate={onNavigate} />
      </div>
    </nav>
  );
}

function NavigationLink({
  item,
  compact,
  onNavigate,
}: {
  item: { href: string; label: string; key: keyof typeof navigationIcons };
  compact: boolean;
  onNavigate: (() => void) | undefined;
}) {
  const Icon = navigationIcons[item.key];
  return (
    <Link
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
}

export function AppShell({ children }: { children: ReactNode }) {
  const [navigationOpen, setNavigationOpen] = useState(false);
  const [accountOpen, setAccountOpen] = useState(false);
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

        <Button
          className="ml-3 max-w-[13rem] gap-2"
          variant="ghost"
          onClick={() => setAccountOpen(true)}
          aria-label="현재 계정과 권한 보기"
        >
          <UserRound aria-hidden="true" className="size-4 shrink-0" />
          <span className="hidden min-w-0 text-left sm:block">
            <span className="block truncate text-sm font-semibold text-text">{session.subject.username}</span>
            <span className="block truncate text-[0.6875rem] text-muted">JW Agent {ROLE_LABELS[session.subject.role]}</span>
          </span>
          <ChevronDown aria-hidden="true" className="hidden size-4 shrink-0 text-muted sm:block" />
        </Button>
      </header>

      <div className="app-body">
        <aside className="app-nav-desktop border-r border-border bg-surface px-2 py-4 xl:px-3">
          <Navigation compact />
        </aside>

        <main id="main-content" className="app-workspace">
          {children}
        </main>

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

      <Sheet
        side="right"
        open={accountOpen}
        onOpenChange={setAccountOpen}
        title={session.subject.username}
        description={`JW Agent ${ROLE_LABELS[session.subject.role]} · Linux UID ${String(session.subject.uid)}`}
      >
        <StatusMark
          label={session.subject.uid === 0 ? "root 로그인 차단 대상" : "비-root Linux 계정"}
          tone={session.subject.uid === 0 ? "danger" : "success"}
        />
        <dl className="mt-6 divide-y divide-border border-y border-border text-sm">
          <SessionDetail label="JW Agent 권한" value={ROLE_LABELS[session.subject.role]} />
          <SessionDetail label="Linux 계정" value={`${session.subject.username} · UID ${String(session.subject.uid)}`} />
          <SessionDetail label="root 권한" value="웹 root 로그인 없음 · typed opsd 작업만 별도 승인" />
          <SessionDetail label="접속 경로" value={session.ingress === "public" ? "공개 HTTPS" : "Loopback · SSH 터널"} />
          <SessionDetail label="세션 만료" value={formatDateTime(session.idleExpiresAt)} />
          <SessionDetail label="관찰 시각" value={observedAt === undefined ? "확인 중" : formatDateTime(observedAt)} />
        </dl>
        <Button
          className="mt-6 w-full"
          variant="secondary"
          disabled={logoutPending}
          onClick={() => void handleLogout()}
        >
          <LogOut aria-hidden="true" className="size-4" />
          {logoutPending ? "로그아웃 중" : "로그아웃"}
        </Button>
      </Sheet>
    </div>
  );
}

function SessionDetail({ label, value }: { label: string; value: string }) {
  return (
    <div className="py-4">
      <dt className="text-xs text-muted">{label}</dt>
      <dd className="mt-1 leading-6 text-text">{value}</dd>
    </div>
  );
}
