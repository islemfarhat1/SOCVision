"use client";

import { useEffect, useState } from "react";
import { fetchHealth } from "@/lib/api";
import { cn } from "@/lib/utils";

type HeaderProps = {
  title?: string;
};

type Health = "checking" | "ok" | "degraded" | "down";

const HEALTH_LABEL: Record<Health, string> = {
  checking: "Checking API…",
  ok: "API connected",
  degraded: "Database unreachable",
  down: "API unreachable",
};

const HEALTH_DOT: Record<Health, string> = {
  checking: "bg-muted-foreground",
  ok: "bg-emerald-500",
  degraded: "bg-amber-400",
  down: "bg-red-500",
};

/** Real API/database status from GET /api/health, refreshed every 30 s. */
function ApiStatus() {
  const [health, setHealth] = useState<Health>("checking");
  const [checkedAt, setCheckedAt] = useState<Date | null>(null);

  useEffect(() => {
    let cancelled = false;
    const check = () =>
      fetchHealth()
        .then((h) => !cancelled && setHealth(h.status === "healthy" ? "ok" : "degraded"))
        .catch(() => !cancelled && setHealth("down"))
        .finally(() => !cancelled && setCheckedAt(new Date()));
    check();
    const t = setInterval(check, 30000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  return (
    <span
      role="status"
      className={cn("flex items-center gap-2 text-xs", health === "ok" ? "text-muted-foreground" : "text-foreground")}
      title={checkedAt ? `Last checked ${checkedAt.toLocaleTimeString()}` : undefined}
    >
      <span aria-hidden className={cn("h-2 w-2 rounded-full", HEALTH_DOT[health])} />
      {HEALTH_LABEL[health]}
    </span>
  );
}

/** UTC clock: the time reference analysts use to correlate logs across sources. */
function UtcClock() {
  const [now, setNow] = useState<Date | null>(null);

  useEffect(() => {
    const tick = () => setNow(new Date());
    tick();
    const t = setInterval(tick, 15000);
    return () => clearInterval(t);
  }, []);

  if (!now) return null;
  const date = now.toISOString().slice(0, 10);
  const time = now.toISOString().slice(11, 16);
  return (
    <span className="font-mono text-xs text-muted-foreground tabular-nums" title="Coordinated Universal Time">
      {date} <span className="text-foreground">{time}</span> UTC
    </span>
  );
}

export function Header({ title = "Overview" }: HeaderProps) {
  return (
    <header className="h-12 shrink-0 border-b border-border bg-background flex items-center justify-between gap-4 px-6">
      <h1 className="text-sm font-semibold truncate">{title}</h1>
      <div className="flex items-center gap-5 shrink-0">
        <ApiStatus />
        <span aria-hidden className="h-4 w-px bg-border hidden sm:block" />
        <span className="hidden sm:inline">
          <UtcClock />
        </span>
      </div>
    </header>
  );
}
