"use client";

import { useEffect, useState, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import ReactMarkdown from "react-markdown";
import rehypeSanitize from "rehype-sanitize";
import { Sidebar } from "@/components/sidebar";
import { Header } from "@/components/header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { FileCheck, FileText, ArrowLeft, AlertTriangle, History, Shield, User, Clock, AlertCircle } from "lucide-react";
import { fetchTickets, fetchTicket, fetchIncidentReports, IncidentReport, formatTicketId } from "@/lib/api";
import { AuthGuard } from "@/components/auth-guard";

type Ticket = {
  ticket_id: string;
  alert_id: string;
  incident_title: string;
  severity: string;
  attack_type: string;
  score: number;
  assigned_to: string | null;
  status: string;
  ticket_created_at: string;
};

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-500 border-red-500/30",
  HIGH: "bg-orange-500/15 text-orange-500 border-orange-500/30",
  MEDIUM: "bg-yellow-500/15 text-yellow-500 border-yellow-500/30",
  LOW: "bg-green-500/15 text-green-500 border-green-500/30",
};

const STATUS_STYLES: Record<string, string> = {
  OPEN: "bg-sky-500/15 text-sky-400 border-sky-500/30",
  IN_PROGRESS: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  CLOSED: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
};

function ReportsContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const ticketIdParam = searchParams.get("ticket_id") || searchParams.get("ticket");

  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [loading, setLoading] = useState(true);

  // Active report viewer state
  const [selectedTicketId, setSelectedTicketId] = useState<string | null>(null);
  const [selectedTicket, setSelectedTicket] = useState<Ticket | null>(null);
  const [reports, setReports] = useState<IncidentReport[]>([]);
  const [selectedReportIndex, setSelectedReportIndex] = useState(0);
  const [loadingReports, setLoadingReports] = useState(false);

  // Load tickets with generated reports strictly
  useEffect(() => {
    const load = async () => {
      try {
        const rawTickets = await fetchTickets().catch(() => []);
        const all: Ticket[] = Array.isArray(rawTickets)
          ? rawTickets
          : (rawTickets && Array.isArray((rawTickets as any).tickets) ? (rawTickets as any).tickets : []);

        const ticketsWithReports = await Promise.all(
          all.map(async (t) => {
            try {
              const reps = await fetchIncidentReports(t.ticket_id);
              if (Array.isArray(reps) && reps.length > 0) {
                return t;
              }
            } catch {
              return null;
            }
            return null;
          })
        );
        const valid = ticketsWithReports.filter((t): t is Ticket => t !== null);
        setTickets(valid);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const loadTicketReport = async (ticketId: string, ticketMeta?: Ticket | null) => {
    setSelectedTicketId(ticketId);
    setLoadingReports(true);
    try {
      // Fetch ticket meta if not provided
      if (!ticketMeta) {
        const found = tickets.find((t) => t.ticket_id === ticketId || formatTicketId(t.ticket_id) === ticketId);
        if (found) {
          setSelectedTicket(found);
        } else {
          const fetched = await fetchTicket(ticketId).catch(() => null);
          if (fetched) setSelectedTicket(fetched);
        }
      } else {
        setSelectedTicket(ticketMeta);
      }

      const data = await fetchIncidentReports(ticketId);
      setReports(Array.isArray(data) ? data : []);
      setSelectedReportIndex(0);
    } catch (e) {
      console.error(e);
      setReports([]);
    } finally {
      setLoadingReports(false);
    }
  };

  // Synchronize when URL parameter changes or arrives
  useEffect(() => {
    if (ticketIdParam) {
      loadTicketReport(ticketIdParam);
    } else {
      setSelectedTicketId(null);
      setSelectedTicket(null);
      setReports([]);
    }
  }, [ticketIdParam, tickets.length]);

  const handleSelectTicket = (ticket: Ticket) => {
    router.push(`/reports?ticket_id=${formatTicketId(ticket.ticket_id)}`);
  };

  const handleBackToList = () => {
    setSelectedTicketId(null);
    setSelectedTicket(null);
    setReports([]);
    router.push("/reports");
  };

  const selectedReport = reports[selectedReportIndex] || null;

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <Header title="Incident Reports" />
      <main className="flex-1 overflow-y-auto p-6 space-y-4">
        {/* ── Report Viewer Mode ── */}
        {selectedTicketId ? (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <button
                onClick={handleBackToList}
                className="flex items-center gap-2 text-xs font-semibold text-muted-foreground hover:text-foreground transition-colors px-3 py-1.5 rounded-md hover:bg-accent border border-transparent hover:border-border"
              >
                <ArrowLeft className="h-4 w-4" />
                Back to all reports
              </button>
            </div>

            {loadingReports ? (
              <Card className="p-12 text-center text-muted-foreground">
                <div className="flex flex-col items-center gap-3">
                  <div className="h-6 w-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                  <span className="text-xs">Loading incident report...</span>
                </div>
              </Card>
            ) : reports.length === 0 ? (
              <Card className="p-10 text-center text-muted-foreground border-dashed">
                <div className="flex flex-col items-center gap-3 max-w-md mx-auto">
                  <AlertCircle className="h-10 w-10 text-amber-400/80" />
                  <div>
                    <h3 className="text-sm font-bold text-foreground">No Report Generated Yet</h3>
                    <p className="text-xs text-muted-foreground mt-1">
                      Incident <span className="font-mono font-bold text-primary">{selectedTicketId}</span> does not have a generated report yet. An SOC L2 analyst must investigate and generate the report first.
                    </p>
                  </div>
                  <button
                    onClick={handleBackToList}
                    className="mt-2 px-3 py-1.5 text-xs font-semibold rounded bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
                  >
                    Return to Reports Registry
                  </button>
                </div>
              </Card>
            ) : (
              <div className="space-y-4">
                {/* Incident Details & Version Bar */}
                <Card className="bg-card/80 border-border/60 shadow-sm">
                  <CardContent className="p-4">
                    <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                      <div className="space-y-1.5">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-sm font-bold text-primary">{formatTicketId(selectedTicketId)}</span>
                          {selectedTicket?.incident_title && (
                            <span className="text-sm font-semibold text-foreground">
                              — {selectedTicket.incident_title}
                            </span>
                          )}
                          {selectedTicket?.severity && (
                            <Badge variant="outline" className={`text-[10px] ${SEVERITY_STYLES[selectedTicket.severity] ?? ""}`}>
                              {selectedTicket.severity}
                            </Badge>
                          )}
                          {selectedTicket?.status && (
                            <Badge variant="outline" className={`text-[10px] ${STATUS_STYLES[selectedTicket.status] ?? ""}`}>
                              {selectedTicket.status.replace("_", " ")}
                            </Badge>
                          )}
                        </div>

                        <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
                          {selectedReport && (
                            <>
                              <span className="flex items-center gap-1">
                                <User className="h-3.5 w-3.5 text-primary" />
                                Author: <span className="text-foreground font-medium font-mono">{selectedReport.generated_by}</span>
                              </span>
                              <span className="flex items-center gap-1">
                                <Clock className="h-3.5 w-3.5 text-primary" />
                                Date: <span className="text-foreground font-medium">{selectedReport.generated_at}</span>
                              </span>
                            </>
                          )}
                          {selectedTicket?.attack_type && (
                            <span className="flex items-center gap-1">
                              <Shield className="h-3.5 w-3.5 text-primary" />
                              Attack: <span className="text-foreground font-medium">{selectedTicket.attack_type}</span>
                            </span>
                          )}
                        </div>
                      </div>

                      {reports.length > 1 && (
                        <div className="flex items-center gap-2 shrink-0">
                          <History className="h-4 w-4 text-primary" />
                          <Select
                            value={String(selectedReportIndex)}
                            onValueChange={(v) => setSelectedReportIndex(Number(v))}
                          >
                            <SelectTrigger className="w-56 h-8 text-xs font-mono">
                              <SelectValue placeholder="Select version" />
                            </SelectTrigger>
                            <SelectContent>
                              {reports.map((r, idx) => (
                                <SelectItem key={r.id} value={String(idx)}>
                                  Version {r.version} — {r.generated_at}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>

                {/* Report Content Card */}
                {selectedReport && (
                  <Card className="bg-card/90 border-border/80 shadow-xl">
                    <CardHeader className="border-b border-border/60 pb-3">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <CardTitle className="text-base flex items-center gap-2">
                          <FileCheck className="h-5 w-5 text-emerald-400" />
                          Incident Report (Version {selectedReport.version})
                        </CardTitle>
                        <span className="text-xs text-muted-foreground font-mono">
                          Generated by <span className="text-foreground font-semibold">{selectedReport.generated_by}</span> on {selectedReport.generated_at}
                        </span>
                      </div>
                      <div className="mt-3 p-3 rounded-md bg-amber-500/10 border border-amber-500/30 flex items-center gap-3 text-xs text-amber-300">
                        <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
                        <div>
                          <span className="font-bold">AI-Generated Investigation Report — Human-in-the-Loop</span>
                          <p className="text-[11px] text-amber-300/80">
                            This report was generated using verified SOC telemetry and LLM assistance, subject to human review by L2 analysts.
                          </p>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent className="p-6 prose prose-invert max-w-none text-sm leading-relaxed space-y-4">
                      <ReactMarkdown rehypePlugins={[rehypeSanitize]}>
                        {selectedReport.content}
                      </ReactMarkdown>
                    </CardContent>
                  </Card>
                )}
              </div>
            )}
          </div>
        ) : (
          /* ── Registry Table Mode (when no ticket selected) ── */
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-3">
              <div className="space-y-1">
                <CardTitle className="text-base font-semibold flex items-center gap-2">
                  <FileText className="h-5 w-5 text-primary" />
                  Incident Reports Registry
                </CardTitle>
                <p className="text-xs text-muted-foreground">
                  Select an incident to view its AI-generated investigation report and audit history
                </p>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-y border-border/60 bg-muted/30 text-left text-muted-foreground text-xs">
                    <th className="p-3 font-medium">Ticket ID</th>
                    <th className="p-3 font-medium">Title</th>
                    <th className="p-3 font-medium">Attack Type</th>
                    <th className="p-3 font-medium">Severity</th>
                    <th className="p-3 font-medium">Status</th>
                    <th className="p-3 font-medium">L2 Analyst</th>
                    <th className="p-3 font-medium">Date</th>
                    <th className="p-3 font-medium">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {loading ? (
                    <tr><td colSpan={8} className="p-6 text-center text-muted-foreground text-xs">Loading incidents...</td></tr>
                  ) : tickets.length === 0 ? (
                    <tr><td colSpan={8} className="p-6 text-center text-muted-foreground text-xs">No incidents found</td></tr>
                  ) : (
                    tickets.map((t) => (
                      <tr key={t.ticket_id} className="border-b border-border/40 hover:bg-accent/40 transition-colors">
                        <td className="p-3 font-mono text-xs font-semibold text-primary">{formatTicketId(t.ticket_id)}</td>
                        <td className="p-3 text-xs max-w-[180px] truncate" title={t.incident_title}>{t.incident_title}</td>
                        <td className="p-3 text-xs">{t.attack_type}</td>
                        <td className="p-3">
                          <Badge variant="outline" className={SEVERITY_STYLES[t.severity] ?? ""}>{t.severity}</Badge>
                        </td>
                        <td className="p-3">
                          <Badge variant="outline" className={`text-[10px] ${STATUS_STYLES[t.status] ?? ""}`}>{t.status.replace("_", " ")}</Badge>
                        </td>
                        <td className="p-3 text-xs text-muted-foreground">{t.assigned_to || "—"}</td>
                        <td className="p-3 text-xs text-muted-foreground">{t.ticket_created_at}</td>
                        <td className="p-3">
                          <button
                            onClick={() => handleSelectTicket(t)}
                            className="px-2.5 py-1 text-xs font-semibold rounded-md bg-primary/15 text-primary border border-primary/30 hover:bg-primary/25 transition-colors"
                          >
                            Read Report →
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </CardContent>
          </Card>
        )}
      </main>
    </div>
  );
}

export default function ReportsPage() {
  return (
    <AuthGuard allowedRoles={["SOC_L2", "SOC_MANAGER", "MANAGER", "ADMIN"]}>
      <Sidebar />
      <Suspense fallback={<div className="flex-1 flex items-center justify-center text-xs text-muted-foreground">Loading reports...</div>}>
        <ReportsContent />
      </Suspense>
    </AuthGuard>
  );
}
