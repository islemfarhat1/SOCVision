"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import ReactMarkdown from "react-markdown";
import rehypeSanitize from "rehype-sanitize";
import { Sidebar } from "@/components/sidebar";
import { Header } from "@/components/header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  ArrowLeft, Sparkles, FileCheck, History, AlertTriangle,
  ShieldCheck, Loader2, User, Clock, FileText, Shield, Network
} from "lucide-react";
import {
  fetchTicket, fetchIncidentReports,
  generateIncidentReport, updateTicket, fetchAnalysts, IncidentReport, formatTicketId
} from "@/lib/api";
import { AuthGuard } from "@/components/auth-guard";
import { useAuth } from "@/lib/use-auth";
import { IpReputationDisplay } from "@/components/ip-reputation";

type TicketDetail = {
  id: number;
  ticket_id: string;
  alert_id: string;
  assigned_to: string | null;
  status: string;
  comments: string | null;
  ticket_created_at: string;
  incident_title: string;
  severity: string;
  attack_type: string;
  score: number;
  source_ip: string;
  destination_ip?: string | null;
  source_port?: number | null;
  destination_port?: number | null;
  protocol?: number | null;
  frequency_count?: number | null;
  investigation_notes?: string | null;
  reviewed_by?: string | null;
  reviewed_at?: string | null;
  classification?: string | null;
  ip_reputation?: string | null;
  mitre_tactic?: string | null;
  mitre?: string | null;
  ioc_assessment?: string | null;
  mitre_context?: string | null;
  summary?: string | null;
  recommended_action?: string | null;
  source?: string | null;
};

type Analyst = { id: number; username: string; full_name: string; role: string };

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-500 border-red-500/30",
  HIGH: "bg-orange-500/15 text-orange-500 border-orange-500/30",
  MEDIUM: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  LOW: "bg-green-500/15 text-green-500 border-green-500/30",
};

const TICKET_STATUS_STYLES: Record<string, string> = {
  OPEN: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  IN_PROGRESS: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  CLOSED: "bg-slate-500/15 text-slate-400 border-slate-500/30",
};

export default function TicketDetailPage() {
  const params = useParams();
  const ticketId = params.ticket_id as string;
  const { user } = useAuth();

  const [ticket, setTicket] = useState<TicketDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "reports">("overview");

  // Edit ticket state
  const [analysts, setAnalysts] = useState<Analyst[]>([]);
  const [comments, setComments] = useState("");
  const [savingComments, setSavingComments] = useState(false);

  // Reports state
  const [reports, setReports] = useState<IncidentReport[]>([]);
  const [selectedReportIndex, setSelectedReportIndex] = useState<number>(0);
  const [loadingReports, setLoadingReports] = useState(false);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);

  const canEdit = user?.role === "SOC_L2" || user?.role === "ADMIN";
  const canGenerateReport = user?.role === "SOC_L2" || user?.role === "ADMIN";

  useEffect(() => {
    fetchTicket(ticketId)
      .then((data) => {
        setTicket(data);
        setComments(data.comments || "");
      })
      .catch(() => setError("Incident not found"));

    loadReports();
    if (canEdit) {
      fetchAnalysts("SOC_L2").then(setAnalysts).catch(console.error);
    }
  }, [ticketId, canEdit]);

  const loadReports = () => {
    setLoadingReports(true);
    fetchIncidentReports(ticketId)
      .then((data) => {
        setReports(data);
        setSelectedReportIndex(0);
      })
      .catch(() => {})
      .finally(() => setLoadingReports(false));
  };

  const handleStatusChange = async (status: string | null) => {
    if (!status || !ticket) return;
    try {
      await updateTicket(ticket.ticket_id, { status });
      setTicket({ ...ticket, status });
    } catch (err) {
      console.error(err);
    }
  };

  const handleAssignChange = async (assigned_to: string | null) => {
    if (!assigned_to || !ticket) return;
    try {
      await updateTicket(ticket.ticket_id, { assigned_to });
      setTicket({ ...ticket, assigned_to });
    } catch (err) {
      console.error(err);
    }
  };

  const handleSaveComments = async () => {
    if (!ticket) return;
    setSavingComments(true);
    try {
      await updateTicket(ticket.ticket_id, { comments });
      setTicket({ ...ticket, comments });
    } catch (err) {
      console.error(err);
    } finally {
      setSavingComments(false);
    }
  };

  const handleGenerateReport = async () => {
    setGeneratingReport(true);
    setReportError(null);
    try {
      const newReport = await generateIncidentReport(ticketId);
      setReports((prev) => [newReport, ...prev]);
      setSelectedReportIndex(0);
      setActiveTab("reports");
    } catch (err) {
      console.error(err);
      setReportError("Failed to generate report with LLM. Please try again.");
    } finally {
      setGeneratingReport(false);
    }
  };

  const selectedReport = reports[selectedReportIndex] || null;
  const matchedAnalyst = ticket ? analysts.find((a) => a.username === ticket.assigned_to || a.full_name === ticket.assigned_to) : null;

  return (
    <AuthGuard allowedRoles={["SOC_L2", "SOC_MANAGER", "MANAGER", "ADMIN"]}>
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header title={ticket ? `Ticket ${formatTicketId(ticket.ticket_id)} — ${ticket.incident_title}` : "Incident Dossier"} />
        <main className="flex-1 overflow-y-auto p-6 space-y-4">
          <div className="flex items-center justify-between">
            <Link
              href="/tickets"
              className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground w-fit"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to incidents queue
            </Link>

            {/* Top Generate Button Shortcut (SOC L2 / ADMIN ONLY) */}
            {canGenerateReport && (
              <button
                disabled={generatingReport}
                onClick={handleGenerateReport}
                className="px-3 py-1.5 text-xs font-semibold rounded-md bg-gradient-to-r from-primary to-blue-600 text-primary-foreground hover:opacity-90 transition-all disabled:opacity-50 flex items-center gap-1.5 shadow-md shadow-primary/20"
              >
                {generatingReport ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    Generating report with LLM...
                  </>
                ) : (
                  <>
                    <Sparkles className="h-3.5 w-3.5" />
                    Generate AI Report
                  </>
                )}
              </button>
            )}
          </div>

          {error && <p className="text-sm text-destructive">{error}</p>}
          {!ticket && !error && (
            <p className="text-sm text-muted-foreground">Loading...</p>
          )}

          {ticket && (
            <div className="space-y-4">
              {/* Tab selector */}
              <div className="border-b border-border/60 flex gap-2">
                <button
                  onClick={() => setActiveTab("overview")}
                  className={`px-4 py-2.5 text-xs font-semibold flex items-center gap-2 border-b-2 transition-all ${
                    activeTab === "overview"
                      ? "border-primary text-primary"
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  }`}
                >
                  <ShieldCheck className="h-4 w-4" />
                  Investigation Dossier & Management
                </button>

                <button
                  onClick={() => setActiveTab("reports")}
                  className={`px-4 py-2.5 text-xs font-semibold flex items-center gap-2 border-b-2 transition-all ${
                    activeTab === "reports"
                      ? "border-primary text-primary"
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  }`}
                >
                  <FileCheck className="h-4 w-4" />
                  Incident Reports & Audit Trail
                  {reports.length > 0 && (
                    <Badge variant="outline" className="bg-primary/10 text-primary border-primary/20 text-[10px]">
                      {reports.length}
                    </Badge>
                  )}
                </button>
              </div>

              {/* Tab 1: Overview & Incident Actions */}
              {activeTab === "overview" && (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                  {/* Left Column: Ticket Status & Controls */}
                  <div className="lg:col-span-1 self-start sticky top-0">
                    <Card className="h-fit shadow-sm border-border/60 bg-card/80">
                      <CardHeader className="border-b border-border/40 pb-3">
                        <CardTitle className="text-base flex items-center gap-2">
                          <ShieldCheck className="h-4 w-4 text-primary" /> Tracking Ticket Dossier
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-3 text-sm pt-4">
                        <InfoRow label="Ticket ID" value={formatTicketId(ticket.ticket_id)} mono />
                        <InfoRow label="Incident" value={ticket.incident_title} />
                        <div className="flex justify-between items-center gap-2">
                          <span className="text-muted-foreground">Original Alert</span>
                          <span className="font-mono text-xs text-muted-foreground bg-muted/40 px-2 py-0.5 rounded border border-border/40 font-semibold select-all">
                            {ticket.alert_id}
                          </span>
                        </div>
                        <InfoRow label="Created At" value={new Date(ticket.ticket_created_at).toLocaleString()} />

                        <div className="flex justify-between items-center">
                          <span className="text-muted-foreground">Severity</span>
                          <Badge variant="outline" className={SEVERITY_STYLES[ticket.severity]}>
                            {ticket.severity}
                          </Badge>
                        </div>

                        {/* Status select/display */}
                        <div className="flex justify-between items-center">
                          <span className="text-muted-foreground">Status</span>
                          {canEdit ? (
                          <Select value={ticket.status} onValueChange={handleStatusChange}>
                            <SelectTrigger className="w-36 h-8 text-xs">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="OPEN">Open</SelectItem>
                              <SelectItem value="IN_PROGRESS">In Progress</SelectItem>
                              <SelectItem value="CLOSED">Closed</SelectItem>
                            </SelectContent>
                          </Select>
                        ) : (
                          <Badge variant="outline" className={TICKET_STATUS_STYLES[ticket.status] ?? ""}>
                            {ticket.status.replace("_", " ")}
                          </Badge>
                        )}
                      </div>

                      <InfoRow label="Attack Type" value={ticket.attack_type} />
                      <InfoRow label="Threat Score" value={String(ticket.score)} />
                      <InfoRow label="Source IP" value={ticket.source_ip} mono />

                      <Separator />

                      {/* Assigned Analyst (Read-Only) */}
                      <div className="flex justify-between items-start gap-2">
                        <span className="text-muted-foreground">Assigned Analyst</span>
                        <div className="text-right">
                          <div className="font-semibold text-foreground">
                            {matchedAnalyst?.full_name || ticket.assigned_to || "Unassigned"}
                          </div>
                          {ticket.assigned_to && (
                            <p className="text-[11px] text-muted-foreground">
                              SOC L2 — Investigator {matchedAnalyst && matchedAnalyst.username !== matchedAnalyst.full_name ? `(@${matchedAnalyst.username})` : ""}
                            </p>
                          )}
                        </div>
                      </div>

                      {/* L2 Investigation Comments */}
                      <Separator />
                      <div className="space-y-2 pt-1">
                        <label className="text-xs font-semibold text-muted-foreground">L2 Investigation Comments</label>
                        {canEdit ? (
                          <>
                            <textarea
                              value={comments}
                              onChange={(e) => setComments(e.target.value)}
                              placeholder="Add L2 investigation comments, containment actions, or technical analysis..."
                              rows={4}
                              className="w-full text-xs p-3 rounded-md bg-background/60 border border-border/80 focus:border-primary focus:outline-none transition-all resize-y"
                            />
                            <div className="flex justify-end">
                              <button
                                onClick={handleSaveComments}
                                disabled={savingComments}
                                className="px-3 py-1.5 text-xs font-semibold rounded-md bg-primary text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-50"
                              >
                                {savingComments ? "Saving..." : "Save Comments"}
                              </button>
                            </div>
                          </>
                        ) : (
                          <div className="p-3 rounded-md bg-background/60 border border-border/60 text-xs text-foreground leading-relaxed">
                            {comments ? comments : (
                              <span className="italic text-muted-foreground">
                                No L2 investigation activity recorded yet.
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                  </div>

                  {/* Right Column: Inherited L1 Context & Telemetry */}
                  <div className="lg:col-span-2 space-y-4">
                    {/* Inherited L1 Triage Banner */}
                    <Card className="border-purple-500/30 bg-purple-500/5">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm font-semibold flex items-center justify-between text-purple-300">
                          <span className="flex items-center gap-2">
                            <FileText className="h-4 w-4 text-purple-400" />
                            Inherited L1 Triage & Analyst Context
                          </span>
                          {ticket.classification && (
                            <Badge variant="outline" className="bg-purple-500/20 text-purple-300 border-purple-500/40 text-[10px]">
                              {ticket.classification}
                            </Badge>
                          )}
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-3 text-xs">
                        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 p-2.5 rounded bg-background/50 border border-border/40">
                          <div>
                            <span className="text-muted-foreground block text-[11px]">Reviewed By (L1):</span>
                            <span className="font-semibold text-foreground">
                              {ticket.reviewed_by || "SOC L1 Analyst"}
                            </span>
                          </div>
                          <div>
                            <span className="text-muted-foreground block text-[11px]">Review Timestamp:</span>
                            <span className="font-mono text-foreground">
                              {ticket.reviewed_at
                                ? new Date(ticket.reviewed_at).toLocaleString()
                                : "—"}
                            </span>
                          </div>
                          <div>
                            <span className="text-muted-foreground block text-[11px]">Original Alert ID:</span>
                            <span className="font-mono text-foreground font-semibold">{ticket.alert_id}</span>
                          </div>
                        </div>

                        <div>
                          <span className="text-muted-foreground font-semibold block mb-1">L1 Investigation Notes:</span>
                          <div className="p-3 rounded-md bg-background/60 border border-border/60 text-sm leading-relaxed text-foreground whitespace-pre-wrap">
                            {ticket.investigation_notes || (
                              <span className="italic text-muted-foreground text-xs">
                                No investigation notes added by L1 analyst.
                              </span>
                            )}
                          </div>
                        </div>
                      </CardContent>
                    </Card>

                    {/* Threat Intelligence & Telemetry Context */}
                    {(ticket.ioc_assessment || ticket.mitre || ticket.summary || ticket.ip_reputation) && (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <Card className="bg-card/80 border-border/60">
                          <CardHeader className="pb-2">
                            <CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                              <Shield className="h-3.5 w-3.5 text-primary" /> Threat Intelligence & Reputation
                            </CardTitle>
                          </CardHeader>
                          <CardContent className="space-y-3 text-xs">
                            <p className="text-[11px] text-muted-foreground leading-relaxed">
                              {ticket.ioc_assessment || "No IOC threat intelligence warnings reported."}
                            </p>
                            <IpReputationDisplay rawReputation={ticket.ip_reputation} />
                          </CardContent>
                        </Card>

                        <Card className="bg-card/80 border-border/60">
                          <CardHeader className="pb-2">
                            <CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                              <Network className="h-3.5 w-3.5 text-primary" /> MITRE ATT&CK Mapping
                            </CardTitle>
                          </CardHeader>
                          <CardContent className="space-y-3 text-xs">
                            {/* Techniques */}
                            <div>
                              <span className="text-[11px] font-semibold text-muted-foreground block mb-1">Techniques:</span>
                              {(() => {
                                const rawTech = ticket.mitre;
                                if (!rawTech || rawTech === "None" || rawTech === "Not identified") {
                                  return <span className="text-muted-foreground text-xs">None mapped</span>;
                                }
                                const techList = rawTech.split(",").map((t: string) => t.trim()).filter(Boolean);
                                return (
                                  <div className="flex flex-wrap gap-1.5">
                                    {techList.map((tech: string, idx: number) => (
                                      <Badge key={idx} variant="outline" className="font-mono text-[11px] bg-primary/10 text-primary border-primary/25">
                                        {tech}
                                      </Badge>
                                    ))}
                                  </div>
                                );
                              })()}
                            </div>

                            {/* Associated Tactics */}
                            <div>
                              <span className="text-[11px] font-semibold text-muted-foreground block mb-1">Associated Tactics:</span>
                              {(() => {
                                const rawTactic = ticket.mitre_tactic;
                                if (!rawTactic || rawTactic === "None" || rawTactic === "Not identified") {
                                  return <span className="text-muted-foreground text-xs">None mapped</span>;
                                }
                                const tacticList = rawTactic.split(",").map((t: string) => t.trim()).filter(Boolean);
                                return (
                                  <div className="flex flex-wrap gap-1.5">
                                    {tacticList.map((tactic: string, idx: number) => (
                                      <Badge key={idx} variant="outline" className="text-[10px] bg-sky-500/10 text-sky-400 border-sky-500/25">
                                        {tactic}
                                      </Badge>
                                    ))}
                                  </div>
                                );
                              })()}
                            </div>

                            {ticket.mitre_context && (
                              <>
                                <Separator />
                                <p className="text-[11px] text-muted-foreground leading-relaxed pt-0.5">
                                  {ticket.mitre_context}
                                </p>
                              </>
                            )}
                          </CardContent>
                        </Card>
                      </div>
                    )}

                    {/* AI-Assisted Analysis */}
                    {(ticket.summary || ticket.recommended_action) && (
                      <Card className="bg-card/80 border-border/60">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center justify-between">
                            <span className="flex items-center gap-2">
                              <Sparkles className="h-3.5 w-3.5 text-primary" /> AI-Assisted Analysis
                            </span>
                            <Badge variant="outline" className="text-[10px] bg-primary/10 text-primary border-primary/20">
                              Human-in-the-Loop
                            </Badge>
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-3 text-xs">
                          <div>
                            <span className="font-semibold text-muted-foreground block mb-1">Summary:</span>
                            <p className="text-foreground leading-relaxed">{ticket.summary || "No AI summary available."}</p>
                          </div>
                          {ticket.recommended_action && (
                            <div>
                              <span className="font-semibold text-muted-foreground block mb-1">Recommended Actions:</span>
                              <p className="text-foreground leading-relaxed p-2.5 rounded bg-primary/5 border border-primary/20">
                                {ticket.recommended_action}
                              </p>
                            </div>
                          )}
                        </CardContent>
                      </Card>
                    )}
                  </div>
                </div>
              )}

              {/* Tab 2: AI Incident Reports */}
              {activeTab === "reports" && (
                <div className="space-y-4">
                  {/* Generating overlay spinner */}
                  {generatingReport && (
                    <Card className="border-primary/40 bg-primary/5 p-8 text-center animate-pulse">
                      <div className="flex flex-col items-center justify-center gap-3">
                        <Loader2 className="h-8 w-8 text-primary animate-spin" />
                        <div className="space-y-1">
                          <h4 className="text-base font-bold text-foreground">
                            Generating ISO 27001 Incident Report with LLM...
                          </h4>
                          <p className="text-xs text-muted-foreground">
                            Compiling alert telemetry, L1 investigation notes, and analyst comments into structured Markdown...
                          </p>
                        </div>
                      </div>
                    </Card>
                  )}

                  {reportError && (
                    <div className="p-3 rounded-md bg-destructive/10 border border-destructive/30 text-xs text-destructive">
                      {reportError}
                    </div>
                  )}

                  {/* Header bar: Version selector & Generate Button */}
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-3.5 rounded-lg bg-card border border-border">
                    <div className="flex items-center gap-3">
                      <History className="h-5 w-5 text-primary" />
                      <div>
                        <h4 className="text-xs font-bold uppercase tracking-wider text-foreground">
                          Audit Trail & Version History
                        </h4>
                        <p className="text-[11px] text-muted-foreground">
                          {reports.length === 0
                            ? "No reports generated yet for this incident"
                            : `${reports.length} report version(s) available`}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      {reports.length > 0 && (
                        <Select
                          value={String(selectedReportIndex)}
                          onValueChange={(v) => setSelectedReportIndex(Number(v))}
                        >
                          <SelectTrigger className="w-60 h-8 text-xs font-mono">
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
                      )}

                      {canGenerateReport && (
                        <button
                          disabled={generatingReport}
                          onClick={handleGenerateReport}
                          className="px-3 py-1.5 text-xs font-semibold rounded-md bg-primary text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-50 flex items-center gap-1.5 shadow-sm"
                        >
                          {generatingReport ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <Sparkles className="h-3.5 w-3.5" />
                          )}
                          Generate New Version
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Report Display */}
                  {selectedReport ? (
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

                        {/* Human-in-the-loop Security Warning Banner */}
                        <div className="mt-3 p-3 rounded-md bg-amber-500/10 border border-amber-500/30 flex items-center gap-3 text-xs text-amber-300">
                          <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
                          <div>
                            <span className="font-bold">AI Generated Report — Human-in-the-Loop</span>
                            <p className="text-[11px] text-amber-300/80">
                              ⚠️ This report was generated by AI and reviewed by SOC analysts.
                            </p>
                          </div>
                        </div>
                      </CardHeader>

                      {/* Markdown rendered content with rehype-sanitize */}
                      <CardContent className="p-6 prose prose-invert max-w-none text-sm leading-relaxed space-y-3">
                        <ReactMarkdown rehypePlugins={[rehypeSanitize]}>
                          {selectedReport.content}
                        </ReactMarkdown>
                      </CardContent>
                    </Card>
                  ) : (
                    !generatingReport && (
                      <Card className="p-10 text-center text-muted-foreground border-dashed">
                        <div className="flex flex-col items-center justify-center gap-2">
                          <Sparkles className="h-8 w-8 text-muted-foreground/40" />
                          <p className="text-sm font-medium">No report generated yet for this incident.</p>
                          <p className="text-xs text-muted-foreground">
                            {canGenerateReport
                              ? "Click \"Generate AI Report\" above to compile telemetry, L1 triage notes, and analyst comments into an ISO 27001 compliant Markdown report."
                              : "No incident report has been generated by SOC L2 analysts yet."
                            }
                          </p>
                        </div>
                      </Card>
                    )
                  )}
                </div>
              )}
            </div>
          )}
        </main>
      </div>
    </AuthGuard>
  );
}

function InfoRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex justify-between items-center gap-2">
      <span className="text-muted-foreground">{label}</span>
      <span className={mono ? "font-mono text-xs" : ""}>{value}</span>
    </div>
  );
}
