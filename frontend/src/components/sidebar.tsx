"use client";

import {
  Shield, LayoutDashboard, Bell, Ticket,
  Settings, ShieldCheck, FileText, Activity,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth, Role } from "@/lib/use-auth";
import { usePathname } from "next/navigation";
import Link from "next/link";

type NavItem = { label: string; icon: typeof Shield; href: string; badge?: string };

function getNavItems(role?: Role): NavItem[] {
  switch (role) {
    case "SOC_L1":
      return [
        { label: "Dashboard", icon: LayoutDashboard, href: "/" },
        { label: "Alerts", icon: Bell, href: "/alerts" },
        { label: "Settings", icon: Settings, href: "/settings" },
      ];
    case "SOC_L2":
      return [
        { label: "Dashboard", icon: LayoutDashboard, href: "/" },
        { label: "Incidents", icon: Ticket, href: "/tickets" },
        { label: "Reports", icon: FileText, href: "/reports" },
        { label: "Settings", icon: Settings, href: "/settings" },
      ];
    case "SOC_MANAGER":
    case "MANAGER":
      return [
        { label: "Dashboard", icon: LayoutDashboard, href: "/" },
        { label: "Reports", icon: FileText, href: "/reports" },
        { label: "Settings", icon: Settings, href: "/settings" },
      ];
    case "ADMIN":
      return [
        { label: "Dashboard", icon: LayoutDashboard, href: "/" },
        { label: "Alerts", icon: Bell, href: "/alerts" },
        { label: "Incidents", icon: Ticket, href: "/tickets" },
        { label: "Reports", icon: FileText, href: "/reports" },
        { label: "Administration", icon: ShieldCheck, href: "/admin" },
        { label: "Settings", icon: Settings, href: "/settings" },
      ];
    default:
      return [{ label: "Dashboard", icon: LayoutDashboard, href: "/" }];
  }
}

const ROLE_CONFIG: Record<string, { label: string; color: string; bg: string; border: string; dot: string }> = {
  SOC_L1: {
    label: "SOC L1 — Analyst",
    color: "text-sky-300",
    bg: "bg-sky-500/10",
    border: "border-sky-500/25",
    dot: "bg-sky-400",
  },
  SOC_L2: {
    label: "SOC L2 — Investigator",
    color: "text-violet-300",
    bg: "bg-violet-500/10",
    border: "border-violet-500/25",
    dot: "bg-violet-400",
  },
  SOC_MANAGER: {
    label: "SOC Manager",
    color: "text-emerald-300",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/25",
    dot: "bg-emerald-400",
  },
  MANAGER: {
    label: "SOC Manager",
    color: "text-emerald-300",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/25",
    dot: "bg-emerald-400",
  },
  ADMIN: {
    label: "Administrator",
    color: "text-rose-300",
    bg: "bg-rose-500/10",
    border: "border-rose-500/25",
    dot: "bg-rose-400",
  },
};

function getInitials(name?: string) {
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
  const navItems = getNavItems(user?.role);
  const roleConf = user?.role ? ROLE_CONFIG[user.role] : undefined;

  return (
    <aside className="w-64 flex flex-col shrink-0 bg-sidebar border-r border-sidebar-border">
      {/* ── Logo / Brand ── */}
      <div className="px-5 py-5 border-b border-sidebar-border">
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-xl bg-primary/15 border border-primary/25 flex items-center justify-center shrink-0">
            <Shield className="h-5 w-5 text-primary" />
          </div>
          <div>
            <p className="font-bold text-sm tracking-tight text-foreground">SOCVision</p>
            <div className="flex items-center gap-1.5 mt-0.5">
              <span className="relative flex h-1.5 w-1.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500" />
              </span>
              <span className="text-[10px] text-emerald-400 font-medium">System Online</span>
            </div>
          </div>
        </div>
      </div>

      {/* ── Navigation ── */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        <p className="px-3 mb-2 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60">
          Navigation
        </p>
        {navItems.map((item) => {
          const isActive =
            pathname === item.href ||
            (item.href !== "/" && pathname.startsWith(item.href));
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "group flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150",
                isActive
                  ? "bg-primary/12 text-primary border border-primary/20 shadow-sm shadow-primary/5"
                  : "text-muted-foreground hover:bg-accent/60 hover:text-foreground border border-transparent"
              )}
            >
              {/* Active indicator bar */}
              <span
                className={cn(
                  "absolute left-0 h-6 w-0.5 rounded-r-full transition-all duration-150",
                  isActive ? "bg-primary" : "bg-transparent"
                )}
              />
              <item.icon
                className={cn(
                  "h-4 w-4 shrink-0 transition-colors",
                  isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
                )}
              />
              <span>{item.label}</span>
              {isActive && (
                <span className="ml-auto h-1.5 w-1.5 rounded-full bg-primary" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* ── Live Activity indicator ── */}
      <div className="mx-3 mb-3 px-3 py-2.5 rounded-lg bg-muted/40 border border-border/50 flex items-center gap-2.5">
        <Activity className="h-3.5 w-3.5 text-primary shrink-0" />
        <span className="text-[11px] text-muted-foreground">Real-time monitoring active</span>
      </div>

      {/* ── User card ── */}
      {user && (
        <div className="px-3 pb-4 border-t border-sidebar-border pt-3 space-y-2.5">
          <div className={cn("flex items-center gap-3 px-3 py-2.5 rounded-lg border", roleConf?.bg, roleConf?.border)}>
            {/* Avatar */}
            <div className="h-8 w-8 rounded-full bg-gradient-to-br from-primary/40 to-primary/10 border border-primary/25 flex items-center justify-center shrink-0">
              <span className={cn("text-[11px] font-bold", roleConf?.color ?? "text-primary")}>
                {getInitials(user.full_name)}
              </span>
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-xs font-semibold text-foreground truncate">{user.full_name}</p>
              <p className={cn("text-[10px] font-medium truncate", roleConf?.color ?? "text-muted-foreground")}>
                {roleConf?.label ?? user.role}
              </p>
            </div>
            {/* Online dot */}
            <span className={cn("h-2 w-2 rounded-full shrink-0", roleConf?.dot ?? "bg-primary")} />
          </div>

          <button
            onClick={logout}
            className="w-full text-[11px] font-medium text-muted-foreground hover:text-foreground py-2 rounded-lg border border-border/50 hover:border-border hover:bg-accent/40 transition-all duration-150"
          >
            Sign out
          </button>
        </div>
      )}
    </aside>
  );
}