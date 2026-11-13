"use client";

import { useEffect, useState } from "react";
import { Sidebar } from "@/components/sidebar";
import { Header } from "@/components/header";
import { AuthGuard } from "@/components/auth-guard";
import { useAuth } from "@/lib/use-auth";
import {
  fetchAlertPage, fetchAlertStatusCounts, fetchAnalysts, fetchTickets, fetchIncidentReports, formatTicketId,
} from "@/lib/api";
import { isToday, parseDate, timeAgo } from "@/lib/time";
import Link from "next/link";
import { SeverityBadge, SEVERITY_FILL } from "@/components/severity";
import { TicketStatus } from "@/components/status";

// ─────────────────────────────────────────────────────────────────────────────
// SOC L1 Dashboard
// ─────────────────────────────────────────────────────────────────────────────

type AlertRow = {
  alert_id: string;
  incident_title: string;
  severity: string;
  score: number;
  status: string;
  created_at: string;
  attack_type: string;
  source_ip: string;
  destination_ip: string;
  destination_port?: number | null;
  reviewed_by?: string | null;
  reviewed_at?: string | null;
};

const TRIAGE = "NEW,UNDER_REVIEW";
const HANDLED = "ESCALATED,DISMISSED";

type L1Data = {
  toTriage: number;
  urgent: number;
  oldest: AlertRow | null;
  handledToday: number;
  nextUp: AlertRow[];
  waitingByType: [string, number][];
  waitingSample: number;
};

function DashboardL1() {
  const { user } = useAuth();
  const [data, setData] = useState<L1Data | null>(null);
  const [error, setError] = useState(false);
  const username = user?.username;

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        // Each figure comes from the API with server-side filters, so the numbers
        // stay correct whatever the number of alerts (no client-side sample).
        const [counts, urgentCounts, nextUp, oldest, waiting, handled] = await Promise.all([
          fetchAlertStatusCounts({}),
          fetchAlertStatusCounts({ severity: "CRITICAL,HIGH" }),
          fetchAlertPage<AlertRow>({ status: TRIAGE, sort: "score", order: "desc", size: "5" }),
          fetchAlertPage<AlertRow>({ status: TRIAGE, sort: "created_at", order: "asc", size: "1" }),
          fetchAlertPage<AlertRow>({ status: TRIAGE, size: "200" }),
          fetchAlertPage<AlertRow>({ status: HANDLED, sort: "id", order: "desc", size: "200" }),
        ]);

        const byType: Record<string, number> = {};
        for (const a of waiting.alerts) byType[a.attack_type] = (byType[a.attack_type] ?? 0) + 1;

        if (cancelled) return;
        setData({
          toTriage: counts.NEW + counts.UNDER_REVIEW,
          urgent: urgentCounts.NEW + urgentCounts.UNDER_REVIEW,
          oldest: oldest.alerts[0] ?? null,
          handledToday: handled.alerts.filter((a) => a.reviewed_by === username && isToday(a.reviewed_at)).length,
          nextUp: nextUp.alerts,
          waitingByType: Object.entries(byType).sort((a, b) => b[1] - a[1]).slice(0, 5),
          waitingSample: waiting.alerts.length,
        });
        setError(false);
      } catch {
        if (!cancelled) setError(true);
      }
    };
    load();
    const interval = setInterval(load, 30000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [username]);

  if (error && !data) {
    return <p role="alert" className="p-6 text-sm text-destructive">Could not load the dashboard. Check that the API is running.</p>;
  }
  if (!data) return <p className="p-6 text-sm text-muted-foreground">Loading dashboard…</p>;

  const maxType = Math.max(...data.waitingByType.map(([, n]) => n), 1);

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      {/* ── KPIs: each one opens the matching filtered view ── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatTile href="/alerts?tab=triage" label="To triage" value={data.toTriage} hint="New + under review" />
        <StatTile
          href="/alerts?tab=triage&severity=CRITICAL,HIGH"
          label="Critical & high waiting"
          value={data.urgent}
          hint={data.urgent ? "Start with these" : "None waiting"}
          tone={data.urgent ? "danger" : undefined}
        />
        <StatTile
          href={data.oldest ? `/alerts/${data.oldest.alert_id}` : "/alerts"}
          label="Oldest waiting"
          value={data.oldest ? timeAgo(data.oldest.created_at) : "—"}
          hint={data.oldest ? data.oldest.alert_id : "Queue is empty"}
        />
        <StatTile href="/alerts?tab=handled" label="Handled by you today" value={data.handledToday} hint="Escalated or dismissed" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* ── Next up ── */}
        <section className="lg:col-span-2 rounded-lg border border-border bg-card">
          <header className="flex items-center justify-between px-5 py-3 border-b border-border">
            <h2 className="text-sm font-semibold">Next up</h2>
            <Link href="/alerts?tab=triage" className="text-sm text-primary hover:underline underline-offset-4">
              Open queue →
            </Link>
          </header>
          {data.nextUp.length === 0 ? (
            <p className="p-8 text-center text-sm text-muted-foreground">Nothing left to triage.</p>
          ) : (
            <ul className="divide-y divide-border">
              {data.nextUp.map((a) => (
                <li key={a.alert_id}>
                  <Link
                    href={`/alerts/${a.alert_id}`}
                    className="flex items-center gap-4 px-5 py-3 hover:bg-muted/40 transition-colors"
                  >
                    <div className="flex items-center gap-2 w-32 shrink-0">
                      <SeverityBadge severity={a.severity} />
                      <span className="font-semibold tabular-nums">{a.score}</span>
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="font-medium truncate">{a.incident_title}</p>
                      <p className="text-xs text-muted-foreground font-mono truncate">
                        {a.source_ip} → {a.destination_ip}{a.destination_port ? `:${a.destination_port}` : ""}
                      </p>
                    </div>
                    <span className="text-sm text-muted-foreground whitespace-nowrap">{timeAgo(a.created_at)}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* ── What is waiting ── */}
        <section className="rounded-lg border border-border bg-card">
          <header className="px-5 py-3 border-b border-border">
            <h2 className="text-sm font-semibold">What&apos;s waiting</h2>
            <p className="text-xs text-muted-foreground">Attack types in the triage queue</p>
          </header>
          {data.waitingByType.length === 0 ? (
            <p className="p-8 text-center text-sm text-muted-foreground">Nothing waiting.</p>
          ) : (
            <ul className="p-5 space-y-4">
              {data.waitingByType.map(([type, count]) => (
                <li key={type} className="space-y-1.5">
                  <div className="flex justify-between gap-3 text-sm">
                    <span className="truncate" title={type}>{type}</span>
                    <span className="tabular-nums text-muted-foreground">{count}</span>
                  </div>
                  <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                    <div className="h-full rounded-full bg-primary/70" style={{ width: `${(count / maxType) * 100}%` }} />
                  </div>
                </li>
              ))}
              {data.waitingSample < data.toTriage && (
                <li className="text-xs text-muted-foreground">Based on the {data.waitingSample} most recent alerts waiting.</li>
              )}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}

function StatTile({
  href, label, value, hint, tone,
}: {
  href?: string;
  label: string;
  value: string | number;
  hint?: string;
  tone?: "danger";
}) {
  const className = `group block rounded-lg border bg-card p-4 transition-colors ${
    tone === "danger" ? "border-red-500/40" : "border-border"
  } ${href ? "hover:border-primary/60" : ""}`;
  const body = (
    <>
      <p className="text-sm text-muted-foreground">{label}</p>
      <p className={`mt-1 text-3xl font-semibold tabular-nums ${tone === "danger" ? "text-red-400" : ""}`}>{value}</p>
      {hint && (
        <p className={`mt-1 text-xs text-muted-foreground truncate ${href ? "group-hover:text-foreground" : ""}`}>
          {hint} {href && <span aria-hidden>→</span>}
        </p>
      )}
    </>
  );
  // Tiles without a destination (e.g. a manager cannot open the L1 queue) are plain figures.
  return href ? <Link href={href} className={className}>{body}</Link> : <div className={className}>{body}</div>;
}

type TicketRow = {
  ticket_id: string;
  alert_id: string;
  incident_title: string;
  severity: string;
  status: string;
  assigned_to: string | null;
  ticket_created_at: string;
  attack_type: string;
  score: number;
  comments: string | null;
};

type Analyst = { username: string; full_name: string };

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const isActive = (t: TicketRow) => t.status !== "CLOSED";
const isUrgent = (t: { severity: string }) => t.severity === "CRITICAL" || t.severity === "HIGH";
const byUrgency = (a: TicketRow, b: TicketRow) =>
  (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) ||
  (parseDate(a.ticket_created_at)?.getTime() ?? 0) - (parseDate(b.ticket_created_at)?.getTime() ?? 0);

function oldest(rows: TicketRow[]): TicketRow | null {
  return [...rows].sort(
    (a, b) => (parseDate(a.ticket_created_at)?.getTime() ?? 0) - (parseDate(b.ticket_created_at)?.getTime() ?? 0)
  )[0] ?? null;
}

function Panel({ title, subtitle, action, children }: {
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-border bg-card">
      <header className="flex items-center justify-between gap-3 px-5 py-3 border-b border-border">
        <div>
          <h2 className="text-sm font-semibold">{title}</h2>
          {subtitle && <p className="text-xs text-muted-foreground">{subtitle}</p>}
        </div>
        {action}
      </header>
      {children}
    </section>
  );
}

function IncidentRow({ t }: { t: TicketRow }) {
  return (
    <li>
      <Link
        href={`/tickets/${formatTicketId(t.ticket_id)}`}
        className="flex items-center gap-4 px-5 py-3 hover:bg-muted/40 transition-colors"
      >
        <div className="flex items-center gap-2 w-32 shrink-0">
          <SeverityBadge severity={t.severity} />
          <span className="font-semibold tabular-nums">{t.score}</span>
        </div>
        <div className="min-w-0 flex-1">
          <p className="font-medium truncate">{t.incident_title}</p>
          <p className="text-xs text-muted-foreground font-mono truncate">
            {formatTicketId(t.ticket_id)} · {t.alert_id}
          </p>
        </div>
        <TicketStatus status={t.status} className="w-28 shrink-0" />
        <span className="text-sm text-muted-foreground whitespace-nowrap w-24 text-right">{timeAgo(t.ticket_created_at)}</span>
      </Link>
    </li>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// SOC L2 Dashboard
// ─────────────────────────────────────────────────────────────────────────────

function DashboardL2() {
  const { user } = useAuth();
  const [tickets, setTickets] = useState<TicketRow[] | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const load = () =>
      fetchTickets()
        .then((data: TicketRow[]) => {
          if (cancelled) return;
          setTickets(data);
          setError(false);
        })
        .catch(() => !cancelled && setError(true));
    load();
    const interval = setInterval(load, 30000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  if (error && !tickets) {
    return <p role="alert" className="p-6 text-sm text-destructive">Could not load incidents. Check that the API is running.</p>;
  }
  if (!tickets) return <p className="p-6 text-sm text-muted-foreground">Loading…</p>;

  const mine = tickets.filter((t) => t.assigned_to === user?.username && isActive(t)).sort(byUrgency);
  const urgent = mine.filter(isUrgent);
  const oldestMine = oldest(mine);
  const withoutNotes = mine.filter((t) => !t.comments?.trim());

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatTile href="/tickets" label="Assigned to me" value={mine.length} hint="Open + in progress" />
        <StatTile
          href="/tickets"
          label="Critical & high on my desk"
          value={urgent.length}
          hint={urgent.length ? "Investigate these first" : "None"}
          tone={urgent.length ? "danger" : undefined}
        />
        <StatTile
          href={oldestMine ? `/tickets/${formatTicketId(oldestMine.ticket_id)}` : "/tickets"}
          label="Oldest open incident"
          value={oldestMine ? timeAgo(oldestMine.ticket_created_at) : "—"}
          hint={oldestMine ? formatTicketId(oldestMine.ticket_id) : "Nothing open"}
        />
        <StatTile
          href="/tickets"
          label="Missing investigation notes"
          value={withoutNotes.length}
          hint={withoutNotes.length ? "Needed before a report" : "All documented"}
        />
      </div>

      <Panel
        title="My active incidents"
        subtitle="Most severe first, then oldest"
        action={<Link href="/tickets" className="text-sm text-primary hover:underline underline-offset-4">All incidents →</Link>}
      >
        {mine.length === 0 ? (
          <p className="p-8 text-center text-sm text-muted-foreground">No active incident assigned to you.</p>
        ) : (
          <ul className="divide-y divide-border">
            {mine.slice(0, 8).map((t) => <IncidentRow key={t.ticket_id} t={t} />)}
          </ul>
        )}
      </Panel>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// SOC Manager Dashboard
// ─────────────────────────────────────────────────────────────────────────────

type ReportRow = { id: number; ticket_id: string; generated_by: string; generated_at: string; version: number };

type ManagerData = {
  triage: number;
  triageBySeverity: Record<string, number>;
  tickets: TicketRow[];
  analysts: Analyst[];
  reports: (ReportRow & { incident_title: string })[];
};

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

function DashboardManager() {
  const [data, setData] = useState<ManagerData | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const [triageCounts, bySeverity, tickets, analysts] = await Promise.all([
          fetchAlertStatusCounts({}),
          Promise.all(SEVERITIES.map((s) => fetchAlertStatusCounts({ severity: s }))),
          fetchTickets() as Promise<TicketRow[]>,
          fetchAnalysts("SOC_L2") as Promise<Analyst[]>,
        ]);
        // Latest report of each incident (one request per incident: fine at lab scale).
        const reports = (
          await Promise.all(
            tickets.map((t) =>
              fetchIncidentReports(t.ticket_id)
                .then((r: ReportRow[]) => (r[0] ? { ...r[0], incident_title: t.incident_title } : null))
                .catch(() => null)
            )
          )
        )
          .filter((r): r is ReportRow & { incident_title: string } => r !== null)
          .sort((a, b) => (parseDate(b.generated_at)?.getTime() ?? 0) - (parseDate(a.generated_at)?.getTime() ?? 0));

        if (cancelled) return;
        setData({
          triage: triageCounts.NEW + triageCounts.UNDER_REVIEW,
          triageBySeverity: Object.fromEntries(SEVERITIES.map((s, i) => [s, bySeverity[i].NEW + bySeverity[i].UNDER_REVIEW])),
          tickets,
          analysts,
          reports: reports.slice(0, 5),
        });
        setError(false);
      } catch {
        if (!cancelled) setError(true);
      }
    };
    load();
    const interval = setInterval(load, 60000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  if (error && !data) {
    return <p role="alert" className="p-6 text-sm text-destructive">Could not load the dashboard. Check that the API is running.</p>;
  }
  if (!data) return <p className="p-6 text-sm text-muted-foreground">Loading…</p>;

  const active = data.tickets.filter(isActive);
  const closed = data.tickets.length - active.length;
  const urgentTriage = data.triageBySeverity.CRITICAL + data.triageBySeverity.HIGH;
  const workload = data.analysts
    .map((a) => {
      const own = active.filter((t) => t.assigned_to === a.username);
      return { ...a, active: own.length, urgent: own.filter(isUrgent).length, oldest: oldest(own) };
    })
    .sort((a, b) => b.active - a.active);
  const maxLoad = Math.max(...workload.map((w) => w.active), 1);

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatTile label="Alerts awaiting triage" value={data.triage} hint="New + under review (L1)" />
        <StatTile
          label="Critical & high awaiting triage"
          value={urgentTriage}
          hint={urgentTriage ? "Backlog risk" : "None"}
          tone={urgentTriage ? "danger" : undefined}
        />
        <StatTile href="/tickets" label="Active incidents" value={active.length} hint="Open + in progress (L2)" />
        <StatTile href="/tickets" label="Closed incidents" value={closed} hint="All time" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-5">
        <div className="lg:col-span-3">
          <Panel title="Analyst workload" subtitle="Active incidents per SOC L2 analyst">
            {workload.length === 0 ? (
              <p className="p-8 text-center text-sm text-muted-foreground">No SOC L2 analyst found.</p>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                    <th className="px-5 py-2.5 font-medium">Analyst</th>
                    <th className="px-5 py-2.5 font-medium w-48">Active</th>
                    <th className="px-5 py-2.5 font-medium text-right">Critical / high</th>
                    <th className="px-5 py-2.5 font-medium text-right">Oldest</th>
                  </tr>
                </thead>
                <tbody>
                  {workload.map((w) => (
                    <tr key={w.username} className="border-b border-border last:border-0">
                      <td className="px-5 py-3">
                        <p className="font-medium">{w.full_name}</p>
                        <p className="text-xs text-muted-foreground font-mono">{w.username}</p>
                      </td>
                      <td className="px-5 py-3">
                        <div className="flex items-center gap-3">
                          <span className="tabular-nums w-6 text-right font-semibold">{w.active}</span>
                          <div className="h-1.5 flex-1 bg-muted rounded-full overflow-hidden">
                            <div className="h-full bg-primary/80" style={{ width: `${(w.active / maxLoad) * 100}%` }} />
                          </div>
                        </div>
                      </td>
                      <td className={`px-5 py-3 text-right tabular-nums ${w.urgent ? "text-red-300 font-semibold" : "text-muted-foreground"}`}>
                        {w.urgent}
                      </td>
                      <td className="px-5 py-3 text-right text-muted-foreground whitespace-nowrap">
                        {w.oldest ? timeAgo(w.oldest.ticket_created_at) : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
        </div>

        <div className="lg:col-span-2">
          <Panel title="Triage backlog by severity" subtitle={`${data.triage} alerts not yet qualified by L1`}>
            <div className="p-5 space-y-4">
              <div className="flex h-2.5 rounded-sm overflow-hidden bg-muted" role="img" aria-label="Backlog by severity">
                {SEVERITIES.map((s) =>
                  data.triageBySeverity[s] ? (
                    <div key={s} className={SEVERITY_FILL[s]} style={{ width: `${(data.triageBySeverity[s] / Math.max(data.triage, 1)) * 100}%` }} />
                  ) : null
                )}
              </div>
              <dl className="space-y-2">
                {SEVERITIES.map((s) => (
                  <div key={s} className="flex items-center justify-between text-sm">
                    <dt className="flex items-center gap-2">
                      <span aria-hidden className={`h-2.5 w-2.5 rounded-sm ${SEVERITY_FILL[s]}`} />
                      {s.charAt(0) + s.slice(1).toLowerCase()}
                    </dt>
                    <dd className="tabular-nums text-muted-foreground">{data.triageBySeverity[s]}</dd>
                  </div>
                ))}
              </dl>
            </div>
          </Panel>
        </div>
      </div>

      <Panel
        title="Latest incident reports"
        action={<Link href="/reports" className="text-sm text-primary hover:underline underline-offset-4">All reports →</Link>}
      >
        {data.reports.length === 0 ? (
          <p className="p-8 text-center text-sm text-muted-foreground">No report generated yet.</p>
        ) : (
          <ul className="divide-y divide-border">
            {data.reports.map((r) => (
              <li key={r.id}>
                <Link
                  href={`/reports?ticket_id=${r.ticket_id}`}
                  className="flex items-center gap-4 px-5 py-3 hover:bg-muted/40 transition-colors"
                >
                  <span className="font-mono text-sm w-28 shrink-0">{formatTicketId(r.ticket_id)}</span>
                  <span className="flex-1 min-w-0 truncate">{r.incident_title}</span>
                  <span className="text-sm text-muted-foreground whitespace-nowrap">
                    v{r.version} · {r.generated_by} · {timeAgo(r.generated_at)}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Root
// ─────────────────────────────────────────────────────────────────────────────

export default function HomePage() {
  const { user } = useAuth();

  const isManager = user?.role === "MANAGER";

  const title =
    user?.role === "SOC_L1" ? "Overview · Triage"
    : user?.role === "SOC_L2" ? "Overview · Investigation"
    : isManager ? "Overview · Supervision"
    : "Overview";

  return (
    <AuthGuard>
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header title={title} />
        <main className="flex-1 overflow-y-auto">
          {user?.role === "SOC_L1" && <DashboardL1 />}
          {user?.role === "SOC_L2" && <DashboardL2 />}
          {isManager && <DashboardManager />}
          {user?.role === "ADMIN" && <DashboardL1 />}
        </main>
      </div>
    </AuthGuard>
  );
}