"use client";

import { useAuth } from "@/lib/use-auth";
import { Clock, Wifi } from "lucide-react";
import { useEffect, useState } from "react";

type HeaderProps = {
  title?: string;
};

function LiveClock() {
  const [now, setNow] = useState<Date | null>(null);

  useEffect(() => {
    setNow(new Date());
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  if (!now) return null;

  const date = now.toLocaleDateString("en-GB", {
    weekday: "short",
    day: "2-digit",
    month: "short",
    year: "numeric",
  });
  const time = now.toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  return (
    <div className="flex items-center gap-2 text-xs text-muted-foreground">
      <Clock className="h-3.5 w-3.5 shrink-0" />
      <span className="font-mono">
        <span className="text-foreground/70">{date}</span>
        {" — "}
        <span className="text-primary font-semibold tabular-nums">{time}</span>
      </span>
    </div>
  );
}

const ROLE_PILL: Record<string, { label: string; className: string }> = {
  SOC_L1: {
    label: "SOC L1",
    className: "bg-sky-500/10 text-sky-300 border-sky-500/25 ring-sky-500/10",
  },
  SOC_L2: {
    label: "SOC L2",
    className: "bg-violet-500/10 text-violet-300 border-violet-500/25 ring-violet-500/10",
  },
  SOC_MANAGER: {
    label: "SOC Manager",
    className: "bg-emerald-500/10 text-emerald-300 border-emerald-500/25 ring-emerald-500/10",
  },
  MANAGER: {
    label: "SOC Manager",
    className: "bg-emerald-500/10 text-emerald-300 border-emerald-500/25 ring-emerald-500/10",
  },
  ADMIN: {
    label: "Admin",
    className: "bg-rose-500/10 text-rose-300 border-rose-500/25 ring-rose-500/10",
  },
};

export function Header({ title = "Dashboard" }: HeaderProps) {
  const { user } = useAuth();
  const rolePill = user?.role ? ROLE_PILL[user.role] : undefined;

  return (
    <header className="h-14 border-b border-border flex items-center justify-between px-6 shrink-0 bg-card/50 backdrop-blur-sm">
      {/* Left: page title */}
      <div className="flex items-center gap-3">
        <h1 className="text-base font-semibold text-foreground tracking-tight">{title}</h1>
        {rolePill && (
          <span
            className={`hidden sm:inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border ring-1 ${rolePill.className}`}
          >
            {rolePill.label}
          </span>
        )}
      </div>

      {/* Right: clock + connection indicator */}
      <div className="flex items-center gap-5">
        <LiveClock />

        <div className="flex items-center gap-2 text-xs">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-60" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
          </span>
          <span className="hidden sm:inline text-muted-foreground font-medium">
            API Live
          </span>
          <Wifi className="h-3.5 w-3.5 text-emerald-400" />
        </div>
      </div>
    </header>
  );
}