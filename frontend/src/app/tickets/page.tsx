"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Search } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Header } from "@/components/header";
import { Input } from "@/components/ui/input";
import { AuthGuard } from "@/components/auth-guard";
import { SeverityBadge } from "@/components/severity";
import { TicketStatus } from "@/components/status";
import { fetchTickets, fetchAnalysts, formatTicketId } from "@/lib/api";
import { useAuth } from "@/lib/use-auth";
import { timeAgo, parseDate } from "@/lib/time";
import { cn } from "@/lib/utils";

type Ticket = {
  ticket_id: string;
  alert_id: string;
  incident_title: string;
  severity: string;
  attack_type: string;
  score: number;
  source_ip: string;
  assigned_to: string | null;
  status: string;
  comments: string | null;
  ticket_created_at: string;
};

type Analyst = { username: string; full_name: string };

type TabKey = "mine" | "active" | "closed" | "all";
const TAB_LABELS: Record<TabKey, string> = { mine: "Assigned to me", active: "Active", closed: "Closed", all: "All" };

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

function matchesTab(t: Ticket, tab: TabKey, username?: string) {
  if (tab === "mine") return t.assigned_to === username && t.status !== "CLOSED";
  if (tab === "active") return t.status !== "CLOSED";
  if (tab === "closed") return t.status === "CLOSED";
  return true;
}

export default function IncidentsPage() {
  const router = useRouter();
  const { user } = useAuth();
  const isL2 = user?.role === "SOC_L2";

  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [analysts, setAnalysts] = useState<Analyst[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState(false);
  const [tabChoice, setTabChoice] = useState<TabKey | null>(null);
  const [search, setSearch] = useState("");

  // L2 analysts land on their own incidents; supervisors on all active ones.
  const tab: TabKey = tabChoice ?? (isL2 ? "mine" : "active");
  const tabs: TabKey[] = isL2 ? ["mine", "active", "closed", "all"] : ["active", "closed", "all"];

  useEffect(() => {
    let cancelled = false;
    const load = () =>
      fetchTickets()
        .then((data: Ticket[]) => {
          if (cancelled) return;
          setTickets(data);
          setError(false);
        })
        .catch(() => !cancelled && setError(true))
        .finally(() => !cancelled && setLoaded(true));
    load();
    fetchAnalysts("SOC_L2").then(setAnalysts).catch(() => {});
    const interval = setInterval(load, 15000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const nameOf = (username: string | null) =>
    analysts.find((a) => a.username === username)?.full_name ?? username ?? "Unassigned";

  const term = search.trim().toLowerCase();
  const rows = tickets
    .filter((t) => matchesTab(t, tab, user?.username))
    .filter(
      (t) =>
        !term ||
        [t.incident_title, t.ticket_id, formatTicketId(t.ticket_id), t.alert_id, t.source_ip, t.attack_type]
          .some((v) => v?.toLowerCase().includes(term))
    )
    .sort(
      (a, b) =>
        (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) ||
        (parseDate(b.ticket_created_at)?.getTime() ?? 0) - (parseDate(a.ticket_created_at)?.getTime() ?? 0)
    );

  const countFor = (key: TabKey) => tickets.filter((t) => matchesTab(t, key, user?.username)).length;

  return (
    <AuthGuard allowedRoles={["SOC_L2", "MANAGER", "ADMIN"]}>
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header title="Incidents" />
        <main className="flex-1 overflow-y-auto">
          <div className="max-w-7xl mx-auto p-6 space-y-4">
            <div role="tablist" aria-label="Incident filter" className="flex gap-1 border-b border-border">
              {tabs.map((key) => (
                <button
                  key={key}
                  role="tab"
                  aria-selected={tab === key}
                  onClick={() => setTabChoice(key)}
                  className={cn(
                    "px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors",
                    tab === key ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"
                  )}
                >
                  {TAB_LABELS[key]}
                  {loaded && (
                    <span className={cn("ml-2 rounded-sm px-1.5 py-0.5 text-xs", tab === key ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground")}>
                      {countFor(key)}
                    </span>
                  )}
                </button>
              ))}
            </div>

            <div className="relative w-full sm:w-80">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
              <Input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search title, incident, alert or IP"
                aria-label="Search incidents"
                className="pl-8"
              />
            </div>

            {error && (
              <p role="alert" className="text-sm text-destructive">Could not load incidents. Check that the API is running.</p>
            )}

            <div className="rounded-lg border border-border bg-card overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                    <th className="px-4 py-3 font-medium w-40">Severity</th>
                    <th className="px-4 py-3 font-medium">Incident</th>
                    <th className="px-4 py-3 font-medium w-36">Status</th>
                    <th className="px-4 py-3 font-medium w-44">Investigator</th>
                    <th className="px-4 py-3 font-medium w-28">Opened</th>
                  </tr>
                </thead>
                <tbody>
                  {!loaded ? (
                    <tr><td colSpan={5} className="p-10 text-center text-muted-foreground">Loading incidents…</td></tr>
                  ) : rows.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="p-10 text-center text-muted-foreground">
                        {term ? "No incidents match this search." : tab === "mine" ? "No active incident assigned to you." : "No incidents here."}
                      </td>
                    </tr>
                  ) : (
                    rows.map((t) => {
                      const href = `/tickets/${formatTicketId(t.ticket_id)}`;
                      return (
                        <tr
                          key={t.ticket_id}
                          onClick={() => router.push(href)}
                          className="border-b border-border last:border-0 cursor-pointer hover:bg-muted/40 transition-colors"
                        >
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <SeverityBadge severity={t.severity} />
                              <span className="font-semibold tabular-nums">{t.score}</span>
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <Link href={href} onClick={(e) => e.stopPropagation()} className="font-medium hover:text-primary">
                              {t.incident_title}
                            </Link>
                            <p className="text-xs text-muted-foreground mt-0.5">
                              <span className="font-mono">{formatTicketId(t.ticket_id)}</span>
                              {" · from "}
                              <span className="font-mono">{t.alert_id}</span>
                              {" · "}
                              <span className="font-mono">{t.source_ip}</span>
                            </p>
                          </td>
                          <td className="px-4 py-3"><TicketStatus status={t.status} /></td>
                          <td className="px-4 py-3 text-muted-foreground truncate">
                            {t.assigned_to === user?.username ? <span className="text-foreground">You</span> : nameOf(t.assigned_to)}
                          </td>
                          <td className="px-4 py-3 text-muted-foreground whitespace-nowrap" title={parseDate(t.ticket_created_at)?.toLocaleString()}>
                            {timeAgo(t.ticket_created_at)}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
            {loaded && rows.length > 0 && (
              <p className="text-sm text-muted-foreground">{rows.length} incident{rows.length > 1 ? "s" : ""}</p>
            )}
          </div>
        </main>
      </div>
    </AuthGuard>
  );
}
