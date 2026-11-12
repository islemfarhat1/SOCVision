"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Sidebar } from "@/components/sidebar";
import { Header } from "@/components/header";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { fetchAlertPage, fetchAlertStatusCounts, type AlertStatusCounts } from "@/lib/api";
import { AuthGuard } from "@/components/auth-guard";
import { ArrowDown, ArrowUp, Loader2, Search } from "lucide-react";
import { cn } from "@/lib/utils";
import { timeAgo } from "@/lib/time";

type Alert = {
  id: number;
  alert_id: string;
  incident_title: string;
  created_at: string;
  severity: string;
  attack_type: string;
  score: number;
  source_ip: string;
  destination_ip: string;
  destination_port: number | null;
  status: string;
};

// Colour is reserved for severity; statuses stay neutral (same rule as the alert page).
const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-400 border-red-500/30",
  HIGH: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  MEDIUM: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  LOW: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
};

const STATUS_LABELS: Record<string, string> = {
  NEW: "New",
  UNDER_REVIEW: "Under review",
  ESCALATED: "Escalated",
  DISMISSED: "Dismissed",
};

const TABS = {
  triage: { label: "To triage", statuses: ["NEW", "UNDER_REVIEW"] },
  handled: { label: "Handled", statuses: ["ESCALATED", "DISMISSED"] },
  all: { label: "All", statuses: ["NEW", "UNDER_REVIEW", "ESCALATED", "DISMISSED"] },
} as const;
type TabKey = keyof typeof TABS;

const SEVERITY_OPTIONS: Record<string, string> = {
  all: "All",
  "CRITICAL,HIGH": "Critical & high",
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
};
const SOURCE_OPTIONS = { all: "All", wazuh: "Wazuh lab", cicids: "CICIDS2017" };

type SortField = "score" | "created_at";
const PAGE_SIZE = 20;

// Filters can be preset from the URL, e.g. /alerts?tab=triage&severity=CRITICAL,HIGH
// (used by the dashboard KPIs). useSearchParams needs a Suspense boundary.
export default function AlertsPage() {
  return (
    <Suspense fallback={null}>
      <AlertQueue />
    </Suspense>
  );
}

function initialFrom<T extends string>(value: string | null, allowed: readonly T[], fallback: T): T {
  return value && (allowed as readonly string[]).includes(value) ? (value as T) : fallback;
}

function AlertQueue() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [tab, setTabState] = useState<TabKey>(() =>
    initialFrom(searchParams.get("tab"), Object.keys(TABS) as TabKey[], "triage")
  );
  const [severity, setSeverityState] = useState(() =>
    initialFrom(searchParams.get("severity"), Object.keys(SEVERITY_OPTIONS), "all")
  );
  const [source, setSourceState] = useState(() =>
    initialFrom(searchParams.get("source"), Object.keys(SOURCE_OPTIONS), "all")
  );
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<{ field: SortField; order: "asc" | "desc" }>({ field: "score", order: "desc" });
  const [page, setPage] = useState(1);

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [counts, setCounts] = useState<AlertStatusCounts | null>(null);
  const [loadedKey, setLoadedKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Any filter change goes back to the first page.
  const setTab = (v: TabKey) => { setTabState(v); setPage(1); };
  const setSeverity = (v: string) => { setSeverityState(v); setPage(1); };
  const setSource = (v: string) => { setSourceState(v); setPage(1); };

  // Wait until the analyst stops typing before querying the API.
  useEffect(() => {
    const t = setTimeout(() => {
      setSearch(searchInput.trim());
      setPage(1);
    }, 300);
    return () => clearTimeout(t);
  }, [searchInput]);

  const filters: Record<string, string> = {};
  if (severity !== "all") filters.severity = severity;
  if (source !== "all") filters.source = source;
  if (search) filters.search = search;
  const listParams: Record<string, string> = {
    ...filters,
    status: TABS[tab].statuses.join(","),
    sort: sort.field,
    order: sort.order,
    page: String(page),
    size: String(PAGE_SIZE),
  };
  // The rows on screen belong to an older query while this differs from the current one.
  const requestKey = JSON.stringify(listParams);
  const loading = loadedKey !== requestKey;

  useEffect(() => {
    const params: Record<string, string> = JSON.parse(requestKey);
    const countFilters = Object.fromEntries(
      Object.entries(params).filter(([k]) => ["severity", "source", "search"].includes(k))
    );

    let cancelled = false;
    const load = () => {
      Promise.all([fetchAlertPage<Alert>(params), fetchAlertStatusCounts(countFilters)])
        .then(([pageData, statusCounts]) => {
          if (cancelled) return;
          setAlerts(pageData.alerts);
          setTotal(pageData.total);
          setCounts(statusCounts);
          setError(null);
        })
        .catch(() => !cancelled && setError("Could not load alerts. Check that the API is running."))
        .finally(() => !cancelled && setLoadedKey(requestKey));
    };

    load();
    const interval = setInterval(load, 15000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [requestKey]);

  const tabCount = (key: TabKey) =>
    counts ? TABS[key].statuses.reduce((sum, s) => sum + (counts[s] ?? 0), 0) : null;

  const toggleSort = (field: SortField) => {
    setSort((s) => (s.field === field ? { field, order: s.order === "desc" ? "asc" : "desc" } : { field, order: "desc" }));
    setPage(1);
  };

  const first = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
  const last = Math.min(page * PAGE_SIZE, total);

  return (
    <AuthGuard allowedRoles={["SOC_L1", "ADMIN"]}>
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header title="Alert queue" />
        <main className="flex-1 overflow-y-auto">
          <div className="max-w-7xl mx-auto p-6 space-y-4">
            {/* ── Tabs ── */}
            <div role="tablist" aria-label="Alert status" className="flex gap-1 border-b border-border">
              {(Object.keys(TABS) as TabKey[]).map((key) => {
                const count = tabCount(key);
                const active = tab === key;
                return (
                  <button
                    key={key}
                    role="tab"
                    aria-selected={active}
                    onClick={() => setTab(key)}
                    className={cn(
                      "px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors",
                      active
                        ? "border-primary text-foreground"
                        : "border-transparent text-muted-foreground hover:text-foreground"
                    )}
                  >
                    {TABS[key].label}
                    {count !== null && (
                      <span
                        className={cn(
                          "ml-2 rounded-full px-2 py-0.5 text-xs",
                          active ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground"
                        )}
                      >
                        {count}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* ── Filters ── */}
            <div className="flex flex-wrap items-center gap-3">
              <div className="relative w-full sm:w-80">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
                <Input
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  placeholder="Search IP, title or alert ID"
                  aria-label="Search alerts"
                  className="pl-8"
                />
              </div>
              <FilterSelect label="Severity" value={severity} onChange={setSeverity} options={SEVERITY_OPTIONS} />
              <FilterSelect label="Source" value={source} onChange={setSource} options={SOURCE_OPTIONS} />
              {(severity !== "all" || source !== "all" || searchInput) && (
                <button
                  onClick={() => {
                    setSeverity("all");
                    setSource("all");
                    setSearchInput("");
                    setSearch("");
                  }}
                  className="text-sm text-muted-foreground hover:text-foreground underline-offset-4 hover:underline"
                >
                  Clear filters
                </button>
              )}
            </div>

            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}

            {/* ── Table ── */}
            <div
              aria-busy={loading}
              className={cn("rounded-lg border border-border bg-card overflow-x-auto transition-opacity", loading && alerts.length > 0 && "opacity-60")}
            >
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                    <th className="px-4 py-3 font-medium w-40">
                      <SortButton label="Severity" active={sort.field === "score"} order={sort.order} onClick={() => toggleSort("score")} />
                    </th>
                    <th className="px-4 py-3 font-medium">Alert</th>
                    <th className="px-4 py-3 font-medium">Source → target</th>
                    <th className="px-4 py-3 font-medium w-36">Status</th>
                    <th className="px-4 py-3 font-medium w-28">
                      <SortButton label="Age" active={sort.field === "created_at"} order={sort.order} onClick={() => toggleSort("created_at")} />
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {loading && alerts.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="p-10 text-center text-muted-foreground">
                        <Loader2 className="h-5 w-5 animate-spin mx-auto" aria-label="Loading" />
                      </td>
                    </tr>
                  ) : alerts.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="p-10 text-center text-muted-foreground">
                        {tab === "triage" && !search && severity === "all" && source === "all"
                          ? "Nothing left to triage."
                          : "No alerts match these filters."}
                      </td>
                    </tr>
                  ) : (
                    alerts.map((a) => (
                      <tr
                        key={a.alert_id}
                        onClick={() => router.push(`/alerts/${a.alert_id}`)}
                        className="border-b border-border last:border-0 cursor-pointer hover:bg-muted/40 transition-colors"
                      >
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className={cn("text-xs font-semibold", SEVERITY_STYLES[a.severity])}>
                              {a.severity}
                            </Badge>
                            <span className="font-semibold tabular-nums">{a.score}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <Link
                            href={`/alerts/${a.alert_id}`}
                            onClick={(e) => e.stopPropagation()}
                            className="font-medium hover:text-primary focus-visible:text-primary outline-none"
                          >
                            {a.incident_title}
                          </Link>
                          <p className="text-xs text-muted-foreground mt-0.5">
                            {detectionLabel(a.attack_type)} · <span className="font-mono">{a.alert_id}</span>
                          </p>
                        </td>
                        <td className="px-4 py-3 font-mono text-[13px] whitespace-nowrap">
                          {a.source_ip}
                          <span className="text-muted-foreground"> → </span>
                          {a.destination_ip}
                          {a.destination_port ? <span className="text-muted-foreground">:{a.destination_port}</span> : null}
                        </td>
                        <td className="px-4 py-3">
                          <Badge variant="outline" className="text-xs bg-muted text-foreground border-border">
                            {STATUS_LABELS[a.status] ?? a.status}
                          </Badge>
                        </td>
                        <td className="px-4 py-3 text-muted-foreground whitespace-nowrap" title={new Date(a.created_at).toLocaleString()}>
                          {timeAgo(a.created_at)}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* ── Pagination ── */}
            <div className="flex items-center justify-between text-sm text-muted-foreground">
              <span>{total === 0 ? "0 alerts" : `${first}–${last} of ${total}`}</span>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="px-3 py-1.5 rounded-md border border-border hover:bg-muted disabled:opacity-40 disabled:hover:bg-transparent"
                >
                  Previous
                </button>
                <button
                  onClick={() => setPage((p) => p + 1)}
                  disabled={last >= total}
                  className="px-3 py-1.5 rounded-md border border-border hover:bg-muted disabled:opacity-40 disabled:hover:bg-transparent"
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        </main>
      </div>
    </AuthGuard>
  );
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function FilterSelect({
  label, value, onChange, options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: Record<string, string>;
}) {
  // `items` lets the trigger show the option label instead of the raw value.
  const items = Object.fromEntries(Object.entries(options).map(([v, l]) => [v, `${label}: ${l}`]));
  return (
    <Select items={items} value={value} onValueChange={(v) => onChange((v as string | null) ?? "all")}>
      <SelectTrigger className="min-w-44" aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {Object.entries(options).map(([v, l]) => (
          <SelectItem key={v} value={v}>
            {l}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function SortButton({
  label, active, order, onClick,
}: {
  label: string;
  active: boolean;
  order: "asc" | "desc";
  onClick: () => void;
}) {
  const Icon = order === "desc" ? ArrowDown : ArrowUp;
  return (
    <button
      onClick={onClick}
      className={cn("inline-flex items-center gap-1 uppercase tracking-wide hover:text-foreground", active && "text-foreground")}
      aria-label={`Sort by ${label.toLowerCase()}`}
    >
      {label}
      {active && <Icon className="h-3.5 w-3.5" />}
    </button>
  );
}

/** "SSH Bruteforce (Hydra)" -> "Hydra"; otherwise the attack type itself. */
function detectionLabel(attackType: string): string {
  const match = attackType.match(/\(([^)]+)\)\s*$/);
  return match ? match[1] : attackType;
}
