"use client";

import { LayoutDashboard, Bell, Ticket, Settings, FileText, LogOut, Users } from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth, Role } from "@/lib/use-auth";
import { usePathname } from "next/navigation";
import Link from "next/link";
import { BrandMark, Wordmark } from "@/components/brand";

type NavItem = { label: string; icon: typeof Bell; href: string };
type NavGroup = { title: string; items: NavItem[] };

const DASHBOARD: NavItem = { label: "Overview", icon: LayoutDashboard, href: "/" };
const ALERTS: NavItem = { label: "Alert queue", icon: Bell, href: "/alerts" };
const INCIDENTS: NavItem = { label: "Incidents", icon: Ticket, href: "/tickets" };
const REPORTS: NavItem = { label: "Reports", icon: FileText, href: "/reports" };
const SETTINGS: NavItem = { label: "Settings", icon: Settings, href: "/settings" };
const USERS: NavItem = { label: "Users & access", icon: Users, href: "/admin" };

function getNavGroups(role?: Role): NavGroup[] {
  const operations: Record<string, NavItem[]> = {
    SOC_L1: [DASHBOARD, ALERTS],
    SOC_L2: [DASHBOARD, INCIDENTS, REPORTS],
    MANAGER: [DASHBOARD, REPORTS],
    ADMIN: [DASHBOARD, ALERTS, INCIDENTS, REPORTS],
  };
  if (!role) return [{ title: "Operations", items: [DASHBOARD] }];
  return [
    { title: "Operations", items: operations[role] ?? [DASHBOARD] },
    { title: "System", items: role === "ADMIN" ? [USERS, SETTINGS] : [SETTINGS] },
  ];
}

export const ROLE_LABELS: Record<string, string> = {
  SOC_L1: "SOC L1 · Triage analyst",
  SOC_L2: "SOC L2 · Investigator",
  MANAGER: "SOC manager",
  ADMIN: "Administrator",
};

function initials(name?: string) {
  if (!name) return "?";
  return name
    .split(" ")
    .map((w) => w[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);
}

export function Sidebar() {
  const { user, logout } = useAuth();
  const pathname = usePathname();
  const groups = getNavGroups(user?.role);

  return (
    <aside className="w-56 flex flex-col shrink-0 bg-sidebar border-r border-sidebar-border">
      <div className="h-12 px-4 flex items-center gap-2.5 border-b border-sidebar-border">
        <BrandMark />
        <Wordmark className="text-[15px]" />
      </div>

      <nav className="flex-1 px-2 py-3 space-y-5 overflow-y-auto" aria-label="Main">
        {groups.map((group) => (
          <div key={group.title}>
            <p className="px-2.5 mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              {group.title}
            </p>
            <ul className="space-y-px">
              {group.items.map((item) => {
                const active = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      aria-current={active ? "page" : undefined}
                      className={cn(
                        "relative flex items-center gap-2.5 h-8 px-2.5 rounded-sm text-sm transition-colors",
                        active
                          ? "bg-sidebar-accent text-sidebar-accent-foreground font-medium"
                          : "text-sidebar-foreground/75 hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground"
                      )}
                    >
                      {active && <span aria-hidden className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-full bg-primary" />}
                      <item.icon className="h-4 w-4 shrink-0" strokeWidth={1.75} />
                      {item.label}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      {user && (
        <div className="border-t border-sidebar-border p-2">
          <div className="flex items-center gap-1 px-1 py-1">
            <Link
              href="/account"
              title="My account"
              aria-label={`My account: ${user.full_name}`}
              aria-current={pathname === "/account" ? "page" : undefined}
              className={cn(
                "flex items-center gap-2.5 min-w-0 flex-1 px-1 py-0.5 rounded-sm hover:bg-sidebar-accent/60",
                pathname === "/account" && "bg-sidebar-accent"
              )}
            >
              <span className="h-7 w-7 rounded-sm bg-sidebar-accent text-[11px] font-semibold flex items-center justify-center shrink-0">
                {initials(user.full_name)}
              </span>
              <span className="min-w-0 flex-1">
                <span className="block text-[13px] font-medium truncate">{user.full_name}</span>
                <span className="block text-[11px] text-muted-foreground truncate">{ROLE_LABELS[user.role] ?? user.role}</span>
              </span>
            </Link>
            <button
              onClick={logout}
              aria-label="Sign out"
              title="Sign out"
              className="h-7 w-7 rounded-sm flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-sidebar-accent"
            >
              <LogOut className="h-4 w-4" strokeWidth={1.75} />
            </button>
          </div>
        </div>
      )}
    </aside>
  );
}
