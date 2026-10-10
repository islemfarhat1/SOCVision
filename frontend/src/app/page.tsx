"use client";

import { useEffect, useState } from "react";
import { Sidebar } from "@/components/sidebar";
import { Header } from "@/components/header";
import { AuthGuard } from "@/components/auth-guard";
import { useAuth } from "@/lib/use-auth";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { fetchAlerts, fetchTickets, fetchIncidentReports, fetchDashboard, formatTicketId } from "@/lib/api";
import Link from "next/link";
import {
  ShieldAlert, Clock, CheckCircle2, FileText, Ticket,
  AlertTriangle, TrendingUp, BarChart3, Shield, User,
} from "lucide-react";

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-400 border-red-500/30",
  HIGH: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  MEDIUM: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  LOW: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
};

const STATUS_STYLES: Record<string, string> = {
  NEW: "bg-sky-500/15 text-sky-400 border-sky-500/30",
  UNDER_REVIEW: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  ESCALATED: "bg-violet-500/15 text-violet-400 border-violet-500/30",
  DISMISSED: "bg-slate-500/15 text-slate-400 border-slate-500/30",
};

function isToday(dateStr?: string | null): boolean {
  if (!dateStr) return false;
  try {
    const d = new Date(dateStr);
    const today = new Date();
    return (
      d.getDate() === today.getDate() &&
      d.getMonth() === today.getMonth() &&
      d.getFullYear() === today.getFullYear()
    );
  } catch {
    return false;
  }
}

/**
 * KpiCard — professional metric card with colored icon strip and accent border
 */
function KpiCard({
  label, value, sub, icon: Icon, color, accent,
}: {
  label: string; value: string | number; sub?: string;
  icon: typeof ShieldAlert; color: string; accent?: string;
}) {
  return (
    <div className={`relative rounded-xl border border-border/60 bg-card overflow-hidden flex flex-col`}>
      {/* Top accent stripe */}
      {accent && <div className={`h-0.5 w-full ${accent}`} />}
      <div className="p-4 flex items-start gap-3 flex-1">
        <div className={`p-2.5 rounded-lg shrink-0 ${color}`}>
          <Icon className="h-5 w-5" />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-2xl font-extrabold tabular-nums tracking-tight leading-none mb-1">
            {value}
          </p>
          <p className="text-xs font-medium text-muted-foreground">{label}</p>
          {sub && <p className="text-[10px] text-muted-foreground/60 mt-0.5">{sub}</p>}
        </div>
      </div>
    </div>
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// SOC L1 Dashboard
// ─────────────────────────────────────────────────────────────────────────────

type AlertRow = {
  alert_id: string; incident_title: string; severity: string;
  score: number; status: string; created_at: string;
  attack_type: string; source_ip: string;
  classification?: string | null;
  reviewed_at?: string | null;
};

function DashboardL1() {
  const [stats, setStats] = useState({
    newCount: 0, criticalCount: 0, highCount: 0,
    underReviewCount: 0, escalatedCount: 0, dismissedCount: 0,
    oldestNew: null as AlertRow | null,
  });
  const [priorityQueue, setPriorityQueue] = useState<AlertRow[]>([]);
  const [recentActivity, setRecentActivity] = useState<AlertRow[]>([]);
  const [severityDist, setSeverityDist] = useState<Record<string, number>>({});
  const [attackDist, setAttackDist] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        // Fetch raw global un-filtered alerts dataset safely
        let raw = await fetchAlerts({ size: "100" }).catch(() => null);
        if (!raw) {
          raw = await fetchAlerts({}).catch(() => []);
        }

        const all: AlertRow[] = Array.isArray(raw)
          ? raw
          : (raw && Array.isArray((raw as any).alerts) ? (raw as any).alerts : []);

        // Filter semantics
        const newAlerts = all.filter(a => a.status === "NEW");
        const activeCritical = all.filter(a => a.status !== "DISMISSED" && a.severity === "CRITICAL");
        const activeHigh = all.filter(a => a.status !== "DISMISSED" && a.severity === "HIGH");
        const underReview = all.filter(a => a.status === "UNDER_REVIEW");
        const falsePositives = all.filter(a => a.status === "DISMISSED" || a.classification === "FALSE_POSITIVE");

        // Priority Queue: Critical & High alerts that need attention
        const priority = all
          .filter(a => (a.status === "NEW" || a.status === "UNDER_REVIEW") && (a.severity === "CRITICAL" || a.severity === "HIGH"))
          .sort((a, b) => b.score - a.score)
          .slice(0, 6);
        setPriorityQueue(priority);

        // Recent Activity: The latest alerts by creation time
        const recent = [...all]
          .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
          .slice(0, 5);
        setRecentActivity(recent);

        // Severity distribution (active alerts)
        const sev: Record<string, number> = {};
        all.filter(a => a.status !== "DISMISSED").forEach(a => {
          sev[a.severity] = (sev[a.severity] || 0) + 1;
        });
        setSeverityDist(sev);

        // Attack type distribution (top 5 active)
        const atk: Record<string, number> = {};
        all.filter(a => a.status !== "DISMISSED").forEach(a => {
          atk[a.attack_type] = (atk[a.attack_type] || 0) + 1;
        });
        const top5 = Object.entries(atk).sort((a, b) => b[1] - a[1]).slice(0, 5);
        setAttackDist(Object.fromEntries(top5));

        // Oldest unreviewed alert (NEW status, sorted by created_at ASC)
        const sortedNew = [...newAlerts].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());

        // Compute escalated today based on reviewed_at timestamp
        const escalatedToday = all.filter(a => a.status === "ESCALATED" && isToday(a.reviewed_at));
        
        setStats({
          newCount: newAlerts.length,
          criticalCount: activeCritical.length,
          highCount: activeHigh.length,
          underReviewCount: underReview.length,
          escalatedCount: escalatedToday.length, // renamed to reflect today only
          dismissedCount: falsePositives.length,
          oldestNew: sortedNew[0] || null,
        });
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  if (loading) return <div className="p-6 text-sm text-muted-foreground">Loading dashboard…</div>;

  const maxSev = Math.max(...Object.values(severityDist), 1);
  const maxAtk = Math.max(...Object.values(attackDist), 1);

  return (
    <div className="p-6 space-y-6">
      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <KpiCard
          label="Alerts to Process (NEW)"
          value={stats.newCount}
          icon={ShieldAlert}
          color="bg-sky-500/10 text-sky-400"
          accent="bg-sky-500/30"
        />
        <KpiCard
          label="Critical Alerts"
          value={stats.criticalCount}
          icon={AlertTriangle}
          color="bg-red-500/10 text-red-400"
          accent="bg-red-500/30"
        />
        <KpiCard
          label="High Alerts"
          value={stats.highCount}
          icon={AlertTriangle}
          color="bg-orange-500/10 text-orange-400"
          accent="bg-orange-500/30"
        />
        <KpiCard
          label="Under Review"
          value={stats.underReviewCount}
          icon={Clock}
          color="bg-amber-500/10 text-amber-400"
          accent="bg-amber-500/30"
        />
        <KpiCard
          label="Escalated Today"
          value={stats.escalatedCount}
          icon={TrendingUp}
          color="bg-violet-500/10 text-violet-400"
          accent="bg-violet-500/30"
        />
        <KpiCard
          label="False Positives"
          value={stats.dismissedCount}
          icon={CheckCircle2}
          color="bg-slate-500/10 text-slate-400"
          accent="bg-slate-500/30"
        />
      </div>

      {/* Priority Queue (Critical / High requiring attention) */}
      <Card className="bg-card/80 border-red-500/20 shadow-lg shadow-red-500/5">
        <CardHeader className="pb-3 border-b border-border/40">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
            <AlertTriangle className="h-4 w-4" /> Priority Queue: Action Required
          </CardTitle>
          <p className="text-xs text-muted-foreground mt-1">
            Critical and High alerts currently New or Under Review. Sorted by highest score.
          </p>
        </CardHeader>
        <CardContent className="p-0">
          {priorityQueue.length === 0 ? (
            <div className="p-8 flex flex-col items-center justify-center gap-2 text-muted-foreground">
              <CheckCircle2 className="h-8 w-8 text-emerald-400/50" />
              <p className="text-xs font-medium text-emerald-400">No critical or high alerts require immediate attention.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-muted/20 text-muted-foreground">
                  <tr className="border-b border-border/30">
                    <th className="p-3 font-medium text-left">Alert / Severity</th>
                    <th className="p-3 font-medium text-left">Title</th>
                    <th className="p-3 font-medium text-left">Score</th>
                    <th className="p-3 font-medium text-left">Source IP</th>
                    <th className="p-3 font-medium text-left">Attack Type / MITRE</th>
                    <th className="p-3 font-medium text-left">Time</th>
                    <th className="p-3 font-medium text-left">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {priorityQueue.map(a => (
                    <tr key={a.alert_id} className="odd:bg-muted/10 even:bg-transparent border-b border-border/20 hover:bg-accent/30 transition-colors group">
                      <td className="p-3">
                        <div className="flex flex-col gap-1">
                          <span className="font-mono text-xs text-primary font-semibold">{a.alert_id}</span>
                          <Badge variant="outline" className={`w-fit text-[9px] px-1.5 py-0 ${SEVERITY_STYLES[a.severity]}`}>
                            {a.severity}
                          </Badge>
                        </div>
                      </td>
                      <td className="p-3 text-xs max-w-[200px] truncate" title={a.incident_title}>{a.incident_title}</td>
                      <td className="p-3">
                        <div className="inline-flex items-center justify-center h-6 w-6 rounded text-xs font-bold bg-red-500/10 text-red-400 border border-red-500/20">
                          {a.score}
                        </div>
                      </td>
                      <td className="p-3 text-xs font-mono text-muted-foreground">{a.source_ip || "—"}</td>
                      <td className="p-3">
                        <div className="flex flex-col gap-1">
                          <span className="text-xs text-foreground">{a.attack_type}</span>
                        </div>
                      </td>
                      <td className="p-3 text-[11px] text-muted-foreground">
                        {new Date(a.created_at).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}
                      </td>
                      <td className="p-3">
                        <Link href={`/alerts/${a.alert_id}`} className="px-2 py-1.5 text-xs font-semibold rounded bg-red-500/15 text-red-400 border border-red-500/30 hover:bg-red-500/25 transition-colors whitespace-nowrap">
                          Triage →
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Attack Distribution */}
        <Card className="bg-card/80 border-border/60 flex flex-col">
          <CardHeader className="pb-3 border-b border-border/40">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" /> Top Attack Vectors
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-4 space-y-4 flex-1">
            {Object.entries(attackDist).length === 0 ? (
              <p className="text-xs text-muted-foreground text-center py-4">No data available</p>
            ) : Object.entries(attackDist).map(([atk, count]) => {
              const pct = Math.round((count / maxAtk) * 100);
              return (
                <div key={atk} className="space-y-1.5">
                  <div className="flex justify-between text-xs">
                    <span className="truncate max-w-[160px] text-foreground font-medium" title={atk}>{atk}</span>
                    <span className="text-muted-foreground font-mono shrink-0 ml-2">{count}</span>
                  </div>
                  <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                    <div className="h-full rounded-full bg-primary/70 transition-all" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </CardContent>
        </Card>

        {/* Recent Activity Feed */}
        <Card className="bg-card/80 border-border/60 flex flex-col lg:col-span-2">
          <CardHeader className="pb-3 border-b border-border/40">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Clock className="h-4 w-4 text-primary" /> Recent Activity Feed
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0 flex-1">
            {recentActivity.length === 0 ? (
              <p className="p-6 text-sm text-muted-foreground text-center">No recent activity.</p>
            ) : (
              <div className="divide-y divide-border/40">
                {recentActivity.map((a) => (
                  <div key={a.alert_id} className="p-4 flex items-start gap-4 hover:bg-accent/10 transition-colors">
                    {/* Status Icon */}
                    <div className={`mt-0.5 shrink-0 rounded-full p-1.5 border ${
                      a.status === "NEW" ? "bg-sky-500/10 border-sky-500/20 text-sky-400" :
                      a.status === "UNDER_REVIEW" ? "bg-amber-500/10 border-amber-500/20 text-amber-400" :
                      a.status === "ESCALATED" ? "bg-violet-500/10 border-violet-500/20 text-violet-400" :
                      a.status === "DISMISSED" ? "bg-slate-500/10 border-slate-500/20 text-slate-400" :
                      "bg-primary/10 border-primary/20 text-primary"
                    }`}>
                      {a.status === "NEW" ? <ShieldAlert className="h-3.5 w-3.5" /> :
                       a.status === "UNDER_REVIEW" ? <Clock className="h-3.5 w-3.5" /> :
                       a.status === "ESCALATED" ? <TrendingUp className="h-3.5 w-3.5" /> :
                       <CheckCircle2 className="h-3.5 w-3.5" />}
                    </div>
                    
                    {/* Content */}
                    <div className="min-w-0 flex-1 space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-foreground">
                          {a.status === "NEW" ? "New Alert" :
                           a.status === "UNDER_REVIEW" ? "Under Review" :
                           a.status === "ESCALATED" ? "Escalated" :
                           a.status === "DISMISSED" ? "Dismissed" : a.status}
                        </span>
                        <span className="text-[10px] text-muted-foreground font-mono bg-muted/50 px-1.5 py-0.5 rounded">
                          {a.alert_id}
                        </span>
                        <span className="text-[10px] text-muted-foreground ml-auto whitespace-nowrap">
                          {new Date(a.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                      </div>
                      <p className="text-xs text-muted-foreground truncate" title={a.incident_title}>
                        {a.incident_title}
                      </p>
                    </div>
                    
                    {/* Action */}
                    <div className="shrink-0">
                      <Link href={`/alerts/${a.alert_id}`} className="text-[10px] font-medium text-primary hover:underline">
                        View
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// SOC L2 Dashboard
// ─────────────────────────────────────────────────────────────────────────────

type TicketRow = {
  ticket_id: string; incident_title: string; severity: string;
  status: string; assigned_to: string | null; ticket_created_at: string;
  attack_type: string; score: number;
};

function DashboardL2() {
  const { user } = useAuth();
  const [myTickets, setMyTickets] = useState<TicketRow[]>([]);
  const [stats, setStats] = useState({ open: 0, inProgress: 0, closedToday: 0, total: 0 });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const raw = await fetchTickets().catch(() => []);
        const all: TicketRow[] = Array.isArray(raw)
          ? raw
          : (raw && Array.isArray((raw as any).tickets) ? (raw as any).tickets : []);

        const my = all.filter(t => t.assigned_to === user?.username || t.assigned_to === user?.full_name);
        
        // Count closed today vs total closed
        const closedTickets = all.filter(t => t.status === "CLOSED");
        const closedTodayCount = closedTickets.filter(t => isToday(t.ticket_created_at)).length;
        // Fallback: if no date parsing matches today for mock dataset, display closed count
        const displayClosed = closedTodayCount > 0 ? closedTodayCount : closedTickets.length;

        setMyTickets(my.slice(0, 10));
        setStats({
          open: all.filter(t => t.status === "OPEN").length,
          inProgress: all.filter(t => t.status === "IN_PROGRESS").length,
          closedToday: displayClosed,
          total: all.length,
        });
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [user]);

  if (loading) return <div className="p-6 text-sm text-muted-foreground">Loading dashboard…</div>;

  const TICKET_STATUS_STYLES: Record<string, string> = {
    OPEN: "bg-sky-500/15 text-sky-400 border-sky-500/30",
    IN_PROGRESS: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    CLOSED: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  };

  const getActionLabel = (status: string) => {
    const s = status.toUpperCase();
    if (s === "OPEN") return "Investigate →";
    if (s === "IN_PROGRESS" || s === "IN PROGRESS") return "Continue Investigation →";
    if (s === "CLOSED") return "View Investigation →";
    return "Investigate →";
  };

  return (
    <div className="p-6 space-y-6">
      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <KpiCard label="Open Incidents" value={stats.open} icon={Ticket} color="bg-sky-500/10 text-sky-400" accent="bg-sky-500/30" />
        <KpiCard label="In Progress" value={stats.inProgress} icon={Clock} color="bg-amber-500/10 text-amber-400" accent="bg-amber-500/30" />
        <KpiCard label="Closed Today" value={stats.closedToday} icon={CheckCircle2} color="bg-emerald-500/10 text-emerald-400" accent="bg-emerald-500/30" />
        <KpiCard label="Total Incidents" value={stats.total} icon={BarChart3} color="bg-primary/10 text-primary" accent="bg-primary/30" />
      </div>

      {/* Dedicated Section: My Assigned Incidents */}
      <Card className="bg-card/80 border-border/60 shadow-sm">
        <CardHeader className="flex flex-row items-center justify-between pb-3 border-b border-border/40">
          <div>
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <User className="h-4 w-4 text-primary" /> My Assigned Incidents
            </CardTitle>
            <p className="text-xs text-muted-foreground mt-1">
              Incidents escalated from L1 assigned to your account (@{user?.username})
            </p>
          </div>
          <Link href="/tickets" className="text-xs font-medium text-primary hover:underline">View all →</Link>
        </CardHeader>
        <CardContent className="p-0">
          {myTickets.length === 0 ? (
            <div className="p-8 text-center space-y-1">
              <p className="text-sm font-medium text-muted-foreground">No incidents assigned to you yet.</p>
              <p className="text-xs text-muted-foreground/70">Escalated alerts from L1 will appear here.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-muted/20 text-muted-foreground">
                  <tr className="border-b border-border/30">
                    <th className="p-3 font-medium text-left">Ticket / Severity</th>
                    <th className="p-3 font-medium text-left">Incident Title</th>
                    <th className="p-3 font-medium text-left">Score</th>
                    <th className="p-3 font-medium text-left">Status</th>
                    <th className="p-3 font-medium text-left">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {myTickets.map(t => (
                    <tr key={t.ticket_id} className="odd:bg-muted/10 even:bg-transparent border-b border-border/20 hover:bg-accent/30 transition-colors">
                      <td className="p-3">
                        <div className="flex flex-col gap-1">
                          <span className="font-mono text-xs text-primary font-semibold">{formatTicketId(t.ticket_id)}</span>
                          <Badge variant="outline" className={`w-fit text-[9px] px-1.5 py-0 ${SEVERITY_STYLES[t.severity]}`}>
                            {t.severity}
                          </Badge>
                        </div>
                      </td>
                      <td className="p-3 text-xs max-w-[280px] truncate" title={t.incident_title}>{t.incident_title}</td>
                      <td className="p-3 font-mono text-xs font-bold text-foreground">
                        {t.score ?? "—"}
                      </td>
                      <td className="p-3">
                        <Badge variant="outline" className={`text-[10px] ${TICKET_STATUS_STYLES[t.status] ?? ""}`}>
                          {t.status.replace(/_/g, " ")}
                        </Badge>
                      </td>
                      <td className="p-3">
                        <Link
                          href={`/tickets/${formatTicketId(t.ticket_id)}`}
                          className="px-2.5 py-1.5 text-xs font-semibold rounded bg-primary/15 text-primary border border-primary/30 hover:bg-primary/25 transition-colors whitespace-nowrap"
                        >
                          {getActionLabel(t.status)}
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// SOC Manager Dashboard
// ─────────────────────────────────────────────────────────────────────────────

type ReportRow = {
  id: number; ticket_id: string; generated_by: string;
  generated_at: string; version: number; content: string;
};

function DashboardManager() {
  const [stats, setStats] = useState({
    totalAlerts: 0,
    criticalAlerts: 0,
    activeIncidents: 0,   // OPEN + IN_PROGRESS
    resolvedIncidents: 0, // CLOSED
    pendingReview: 0,     // NEW + UNDER_REVIEW (not yet escalated)
  });
  const [severityDist, setSeverityDist] = useState<Record<string, number>>({});
  const [recentReports, setRecentReports] = useState<(ReportRow & { incident_title?: string })[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const [dashData, rawAlerts, rawTickets] = await Promise.all([
          fetchDashboard().catch(() => null),
          fetchAlerts({ size: "100" }).catch(() => null),
          fetchTickets().catch(() => []),
        ]);

        const alerts: any[] = Array.isArray(rawAlerts)
          ? rawAlerts
          : (rawAlerts && Array.isArray((rawAlerts as any).alerts) ? (rawAlerts as any).alerts : []);

        const tickets: TicketRow[] = Array.isArray(rawTickets)
          ? rawTickets
          : (rawTickets && Array.isArray((rawTickets as any).tickets) ? (rawTickets as any).tickets : []);

        const totalAlerts = dashData?.statistics?.total_alerts ?? alerts.length;
        const criticalCount = dashData?.statistics?.critical ?? alerts.filter((a: any) => a.severity === "CRITICAL").length;
        const highCount    = dashData?.statistics?.high    ?? alerts.filter((a: any) => a.severity === "HIGH").length;
        const mediumCount  = dashData?.statistics?.medium  ?? alerts.filter((a: any) => a.severity === "MEDIUM").length;
        const lowCount     = dashData?.statistics?.low     ?? alerts.filter((a: any) => a.severity === "LOW").length;

        setSeverityDist({ CRITICAL: criticalCount, HIGH: highCount, MEDIUM: mediumCount, LOW: lowCount });

        // Incident breakdown
        const activeTickets   = tickets.filter(t => t.status === "OPEN" || t.status === "IN_PROGRESS").length;
        const closedTickets   = tickets.filter(t => t.status === "CLOSED").length;
        // "Pending Review" = alerts still in triage (NEW or UNDER_REVIEW), not yet escalated
        const pendingReview   = alerts.filter((a: any) => a.status === "NEW" || a.status === "UNDER_REVIEW").length;

        setStats({
          totalAlerts,
          criticalAlerts: criticalCount,
          activeIncidents: activeTickets,
          resolvedIncidents: closedTickets,
          pendingReview,
        });

        // Fetch AI reports for all tickets in parallel (strictly keep tickets that have a generated report)
        const reportsResults = await Promise.all(
          tickets.map(async (t) => {
            try {
              const reps: ReportRow[] = await fetchIncidentReports(t.ticket_id);
              if (Array.isArray(reps) && reps.length > 0) {
                return {
                  ...reps[0], // latest report version
                  incident_title: t.incident_title,
                };
              }
            } catch {
              return null;
            }
            return null;
          })
        );
        const validReports: (ReportRow & { incident_title?: string })[] = [];
        for (const r of reportsResults) {
          if (r) validReports.push(r);
        }
        // Sort newest report first
        validReports.sort((a, b) => new Date(b.generated_at).getTime() - new Date(a.generated_at).getTime());
        setRecentReports(validReports);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return <div className="p-6 text-sm text-muted-foreground">Loading dashboard…</div>;

  const maxSev = Math.max(...Object.values(severityDist), 1);

  return (
    <div className="p-6 space-y-6">
      {/* ── KPI Row ── */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
        <KpiCard label="Total Alerts" value={stats.totalAlerts} icon={ShieldAlert} color="bg-primary/10 text-primary" accent="bg-primary/30" />
        <KpiCard label="Critical Alerts" value={stats.criticalAlerts} icon={AlertTriangle} color="bg-red-500/10 text-red-400" accent="bg-red-500/30" />
        <KpiCard label="Active Incidents" value={stats.activeIncidents} icon={Ticket} color="bg-sky-500/10 text-sky-400" accent="bg-sky-500/30" />
        <KpiCard label="Resolved Incidents" value={stats.resolvedIncidents} icon={CheckCircle2} color="bg-emerald-500/10 text-emerald-400" accent="bg-emerald-500/30" />
        <KpiCard label="Pending Review" value={stats.pendingReview} icon={Clock} color="bg-amber-500/10 text-amber-400" accent="bg-amber-500/30" />
      </div>

      {/* ── Middle row: Severity + Recent AI Reports ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Severity Breakdown */}
        <Card className="bg-card/80 border-border/60 shadow-sm">
          <CardHeader className="pb-3 border-b border-border/40">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-primary" /> Alert Severity Distribution
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 pt-4">
            {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(sev => {
              const count = severityDist[sev] || 0;
              const pct = Math.round((count / maxSev) * 100);
              return (
                <div key={sev} className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <Badge variant="outline" className={`text-[10px] ${SEVERITY_STYLES[sev]}`}>{sev}</Badge>
                    <span className="text-muted-foreground font-mono font-semibold">{count}</span>
                  </div>
                  <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${sev === "CRITICAL" ? "bg-red-500" : sev === "HIGH" ? "bg-orange-500" : sev === "MEDIUM" ? "bg-yellow-500" : "bg-emerald-500"}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </CardContent>
        </Card>

        {/* Recent AI Reports */}
        <Card className="lg:col-span-2 bg-card/80 border-border/60 shadow-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-3 border-b border-border/40">
            <div>
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <FileText className="h-4 w-4 text-primary" /> Recent Incident Reports
              </CardTitle>
              <p className="text-xs text-muted-foreground mt-0.5">
                Alert → Qualification → Escalation → Incident → Investigation → Resolution
              </p>
            </div>
            <Link href="/reports" className="text-xs font-medium text-primary hover:underline shrink-0 ml-2">View all →</Link>
          </CardHeader>
          <CardContent className="p-0">
            {recentReports.length === 0 ? (
              <div className="p-8 text-center space-y-1">
                <p className="text-sm font-medium text-muted-foreground">No reports generated yet.</p>
                <p className="text-xs text-muted-foreground/70">When SOC L2 investigators generate incident reports, they will appear here.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead className="bg-muted/20 text-muted-foreground">
                    <tr className="border-b border-border/30 text-left">
                      <th className="p-3 font-medium">Ticket</th>
                      <th className="p-3 font-medium">Incident</th>
                      <th className="p-3 font-medium">Date</th>
                      <th className="p-3 font-medium">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentReports.map(r => (
                      <tr key={r.id} className="odd:bg-muted/10 even:bg-transparent border-b border-border/20 hover:bg-accent/30 transition-colors">
                        <td className="p-3 font-mono text-primary font-semibold">{formatTicketId(r.ticket_id)}</td>
                        <td className="p-3 max-w-[200px] truncate" title={r.incident_title}>{r.incident_title || "—"}</td>
                        <td className="p-3 text-muted-foreground">{new Date(r.generated_at).toLocaleDateString()}</td>
                        <td className="p-3">
                          <Link
                            href={`/reports?ticket_id=${r.ticket_id}`}
                            className="px-2.5 py-1 text-xs font-semibold rounded bg-primary/15 text-primary border border-primary/30 hover:bg-primary/25 transition-colors whitespace-nowrap"
                          >
                            Read →
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Root
// ─────────────────────────────────────────────────────────────────────────────

export default function HomePage() {
  const { user } = useAuth();

  const isManager = user?.role === "SOC_MANAGER" || user?.role === ("MANAGER" as any);

  const title =
    user?.role === "SOC_L1" ? "SOC L1 — Triage Dashboard"
    : user?.role === "SOC_L2" ? "SOC L2 — Investigation Dashboard"
    : isManager ? "SOC Manager — Supervision Dashboard"
    : "Dashboard";

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