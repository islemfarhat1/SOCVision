"use client";

import { useEffect, useState, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Header } from "@/components/header";
import { AuthGuard } from "@/components/auth-guard";
import { IncidentReportDocument } from "@/components/incident-report";
import { SeverityBadge } from "@/components/severity";
import { TicketStatus } from "@/components/status";
import { fetchTickets, fetchIncidentReports, formatTicketId, type IncidentReport } from "@/lib/api";
import { parseDate, timeAgo } from "@/lib/time";
import { cn } from "@/lib/utils";

type Ticket = {
  ticket_id: string;
  alert_id: string;
  incident_title: string;
  severity: string;
  status: string;
  assigned_to: string | null;
};

type Entry = { ticket: Ticket; reports: IncidentReport[] };

function ReportsContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const requested = searchParams.get("ticket_id") || searchParams.get("ticket");

  const [entries, setEntries] = useState<Entry[] | null>(null);
  const [error, setError] = useState(false);
  const [versionByTicket, setVersionByTicket] = useState<Record<string, number>>({});

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const tickets: Ticket[] = await fetchTickets();
        // One request per incident: fine at lab scale. The reports are kept for the viewer.
        const withReports = await Promise.all(
          tickets.map((ticket) =>
            fetchIncidentReports(ticket.ticket_id)
              .then((reports: IncidentReport[]) => ({ ticket, reports }))
              .catch(() => ({ ticket, reports: [] as IncidentReport[] }))
          )
        );
        if (cancelled) return;
        setEntries(
          withReports
            .filter((e) => e.reports.length > 0)
            .sort(
              (a, b) =>
                (parseDate(b.reports[0].generated_at)?.getTime() ?? 0) - (parseDate(a.reports[0].generated_at)?.getTime() ?? 0)
            )
        );
      } catch {
        if (!cancelled) setError(true);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, []);

  const selected = requested
    ? entries?.find((e) => e.ticket.ticket_id === requested || formatTicketId(e.ticket.ticket_id) === requested)
    : undefined;

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <Header title={selected ? `Reports · ${formatTicketId(selected.ticket.ticket_id)}` : "Reports"} />
      <main className="flex-1 overflow-y-auto">
        <div className="max-w-7xl mx-auto p-6 space-y-5">
          {error && <p role="alert" className="text-sm text-destructive">Could not load reports. Check that the API is running.</p>}
          {!entries && !error && <p className="text-sm text-muted-foreground">Loading reports…</p>}

          {/* ── Viewer ── */}
          {entries && requested && (
            <>
              <Link href="/reports" className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground">
                <ArrowLeft className="h-4 w-4" />
                All reports
              </Link>

              {!selected ? (
                <div className="p-10 text-center rounded-lg border border-dashed border-border text-muted-foreground">
                  No report has been generated for incident <span className="font-mono text-foreground">{requested}</span> yet.
                </div>
              ) : (
                <ReportViewer
                  entry={selected}
                  index={versionByTicket[selected.ticket.ticket_id] ?? 0}
                  onIndex={(i) => setVersionByTicket((v) => ({ ...v, [selected.ticket.ticket_id]: i }))}
                />
              )}
            </>
          )}

          {/* ── Registry ── */}
          {entries && !requested && (
            <>
              <p className="text-sm text-muted-foreground">
                AI-drafted incident reports, latest version of each incident. Open one to read, print or download it.
              </p>
              <div className="rounded-lg border border-border bg-card overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                      <th className="px-4 py-3 font-medium">Incident</th>
                      <th className="px-4 py-3 font-medium w-32">Severity</th>
                      <th className="px-4 py-3 font-medium w-36">Status</th>
                      <th className="px-4 py-3 font-medium w-28">Versions</th>
                      <th className="px-4 py-3 font-medium w-56">Latest</th>
                    </tr>
                  </thead>
                  <tbody>
                    {entries.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="p-10 text-center text-muted-foreground">
                          No report yet. Reports are generated by the assigned L2 analyst from the incident page.
                        </td>
                      </tr>
                    ) : (
                      entries.map(({ ticket, reports }) => {
                        const href = `/reports?ticket_id=${formatTicketId(ticket.ticket_id)}`;
                        return (
                          <tr
                            key={ticket.ticket_id}
                            onClick={() => router.push(href)}
                            className="border-b border-border last:border-0 cursor-pointer hover:bg-muted/40 transition-colors"
                          >
                            <td className="px-4 py-3">
                              <Link href={href} onClick={(e) => e.stopPropagation()} className="font-medium hover:text-primary">
                                {ticket.incident_title}
                              </Link>
                              <p className="text-xs text-muted-foreground font-mono mt-0.5">{formatTicketId(ticket.ticket_id)}</p>
                            </td>
                            <td className="px-4 py-3"><SeverityBadge severity={ticket.severity} /></td>
                            <td className="px-4 py-3"><TicketStatus status={ticket.status} /></td>
                            <td className="px-4 py-3 tabular-nums">{reports.length}</td>
                            <td className="px-4 py-3 text-muted-foreground">
                              v{reports[0].version} · {reports[0].generated_by} · {timeAgo(reports[0].generated_at)}
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      </main>
    </div>
  );
}

function ReportViewer({ entry, index, onIndex }: { entry: Entry; index: number; onIndex: (i: number) => void }) {
  const { ticket, reports } = entry;
  const report = reports[index] ?? reports[0];
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-muted-foreground">
          <Link href={`/tickets/${formatTicketId(ticket.ticket_id)}`} className="text-foreground hover:text-primary">
            Open the incident
          </Link>{" "}
          to add notes or generate a new version.
        </p>
        {reports.length > 1 && (
          <nav aria-label="Report versions" className="flex flex-wrap gap-2">
            {reports.map((r, i) => (
              <button
                key={r.id}
                onClick={() => onIndex(i)}
                aria-current={r.id === report.id}
                className={cn(
                  "px-3 py-1.5 rounded-md text-sm border",
                  r.id === report.id ? "border-primary bg-primary/5" : "border-border hover:bg-muted"
                )}
              >
                Version {r.version}
                {i === 0 && <span className="ml-1.5 text-xs text-primary">latest</span>}
              </button>
            ))}
          </nav>
        )}
      </div>
      <IncidentReportDocument
        report={report}
        incident={{
          ticketId: ticket.ticket_id,
          title: ticket.incident_title,
          severity: ticket.severity,
          status: ticket.status,
          assignee: ticket.assigned_to,
        }}
      />
    </div>
  );
}

export default function ReportsPage() {
  return (
    <AuthGuard allowedRoles={["SOC_L2", "MANAGER", "ADMIN"]}>
      <Sidebar />
      <Suspense fallback={<p className="flex-1 p-6 text-sm text-muted-foreground">Loading reports…</p>}>
        <ReportsContent />
      </Suspense>
    </AuthGuard>
  );
}
