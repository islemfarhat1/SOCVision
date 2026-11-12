"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import ReactMarkdown from "react-markdown";
import rehypeSanitize from "rehype-sanitize";
import { Sidebar } from "@/components/sidebar";
import { Header } from "@/components/header";
import { Badge } from "@/components/ui/badge";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  ArrowLeft, Sparkles, Loader2, AlertTriangle, CheckCircle2, ChevronDown, Download, Save,
} from "lucide-react";
import {
  fetchTicket, fetchIncidentReports,
  generateIncidentReport, updateTicket, fetchAnalysts, IncidentReport, formatTicketId,
} from "@/lib/api";
import { AuthGuard } from "@/components/auth-guard";
import { useAuth } from "@/lib/use-auth";
import { IpReputationDisplay } from "@/components/ip-reputation";
import { cn } from "@/lib/utils";

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
  llm_provider?: string | null;
  llm_model?: string | null;
};

type Analyst = { id: number; username: string; full_name: string; role: string };
type Notice = { kind: "success" | "error"; text: string };

// Colour is reserved for severity (same rule as the alert pages).
const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-400 border-red-500/30",
  HIGH: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  MEDIUM: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  LOW: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
};

const STATUS_LABELS: Record<string, string> = {
  OPEN: "Open",
  IN_PROGRESS: "In progress",
  CLOSED: "Closed",
};

function splitList(raw?: string | null): string[] {
  if (!raw || raw === "None" || raw === "Not identified") return [];
  return raw.split(",").map((t) => t.trim()).filter(Boolean);
}

/**
 * Older reports were stored wrapped in a ```markdown fence, which renders as a
 * code block. Remove that wrapper (even when the closing fence is missing).
 */
function stripCodeFence(text: string): string {
  const full = text.match(/^\s*```[a-zA-Z]*[ \t]*\r?\n([\s\S]*?)\r?\n?```\s*$/);
  if (full) return full[1].trim();
  return text.replace(/^\s*```(?:markdown|md)?[ \t]*\r?\n/i, "").trim();
}

/** Backend dates are "YYYY-MM-DD HH:MM:SS" or ISO; make both parseable everywhere. */
function formatDate(value?: string | null): string {
  if (!value) return "—";
  const d = new Date(value.includes("T") ? value : value.replace(" ", "T"));
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

export default function TicketDetailPage() {
  const params = useParams();
  const ticketId = params.ticket_id as string;
  const { user } = useAuth();

  const [ticket, setTicket] = useState<TicketDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [activeTab, setActiveTab] = useState<"investigation" | "reports">("investigation");

  const [analysts, setAnalysts] = useState<Analyst[]>([]);
  const [comments, setComments] = useState("");
  const [savingComments, setSavingComments] = useState(false);
  const [updating, setUpdating] = useState(false);

  const [reports, setReports] = useState<IncidentReport[]>([]);
  const [selectedReportIndex, setSelectedReportIndex] = useState(0);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);

  // Mirrors the backend rule: an L2 can only modify incidents assigned to them.
  const isInvestigator = user?.role === "SOC_L2" || user?.role === "ADMIN";
  const canEdit =
    user?.role === "ADMIN" ||
    (user?.role === "SOC_L2" && !!ticket && ticket.assigned_to === user.username);

  useEffect(() => {
    fetchTicket(ticketId)
      .then((data) => {
        setTicket(data);
        setComments(data.comments || "");
      })
      .catch(() => setError("Incident not found"));

    fetchIncidentReports(ticketId)
      .then((data) => setReports(data))
      .catch(() => {});

    if (isInvestigator) {
      fetchAnalysts("SOC_L2").then(setAnalysts).catch(console.error);
    }
  }, [ticketId, isInvestigator]);

  const flash = (n: Notice) => {
    setNotice(n);
    if (n.kind === "success") setTimeout(() => setNotice(null), 4000);
  };

  // Only update the screen once the API has accepted the change.
  const applyUpdate = async (fields: { status?: string; assigned_to?: string; comments?: string }, success: string) => {
    if (!ticket) return false;
    setUpdating(true);
    try {
      await updateTicket(ticket.ticket_id, fields);
      setTicket({ ...ticket, ...fields });
      flash({ kind: "success", text: success });
      return true;
    } catch (err) {
      flash({ kind: "error", text: err instanceof Error ? err.message : "The change could not be saved." });
      return false;
    } finally {
      setUpdating(false);
    }
  };

  const handleStatusChange = (status: string | null) => {
    if (!status || !ticket || status === ticket.status) return;
    applyUpdate({ status }, `Status changed to ${STATUS_LABELS[status] ?? status}.`);
  };

  const handleAssignChange = (assigned_to: string | null) => {
    if (!assigned_to || !ticket || assigned_to === ticket.assigned_to) return;
    const name = analysts.find((a) => a.username === assigned_to)?.full_name ?? assigned_to;
    applyUpdate({ assigned_to }, `Incident reassigned to ${name}.`);
  };

  const handleSaveComments = async () => {
    setSavingComments(true);
    await applyUpdate({ comments }, "Investigation notes saved.");
    setSavingComments(false);
  };

  const handleGenerateReport = async () => {
    setGeneratingReport(true);
    setReportError(null);
    setActiveTab("reports");
    try {
      const newReport = await generateIncidentReport(ticketId);
      setReports((prev) => [newReport, ...prev]);
      setSelectedReportIndex(0);
    } catch (err) {
      setReportError(err instanceof Error ? err.message : "Failed to generate the incident report.");
    } finally {
      setGeneratingReport(false);
    }
  };

  const downloadReport = (report: IncidentReport) => {
    const blob = new Blob([stripCodeFence(report.content)], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${formatTicketId(report.ticket_id)}-report-v${report.version}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const commentsDirty = !!ticket && comments !== (ticket.comments || "");
  const assignee = ticket ? analysts.find((a) => a.username === ticket.assigned_to) : undefined;
  const assigneeName = assignee?.full_name ?? ticket?.assigned_to ?? "Unassigned";
  const selectedReport = reports[selectedReportIndex] ?? null;
  const techniques = splitList(ticket?.mitre);
  const tactics = splitList(ticket?.mitre_tactic);

  return (
    <AuthGuard allowedRoles={["SOC_L2", "MANAGER", "ADMIN"]}>
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header title={ticket ? formatTicketId(ticket.ticket_id) : "Incident"} />
        <main className="flex-1 overflow-y-auto">
          <div className="max-w-6xl mx-auto p-6 space-y-5">
            <Link href="/tickets" className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground">
              <ArrowLeft className="h-4 w-4" />
              Incidents
            </Link>

            {error && <p className="text-sm text-destructive">{error}</p>}
            {!ticket && !error && <p className="text-sm text-muted-foreground">Loading…</p>}

            {notice && (
              <div
                role={notice.kind === "error" ? "alert" : "status"}
                className={cn(
                  "p-3 rounded-md border text-sm",
                  notice.kind === "error"
                    ? "bg-destructive/10 border-destructive/30 text-destructive"
                    : "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
                )}
              >
                {notice.text}
              </div>
            )}

            {ticket && (
              <>
                {/* ── 1. Decision bar ── */}
                <section className="sticky top-0 z-10 -mx-6 px-6 py-4 bg-background/95 backdrop-blur border-b border-border">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div className="space-y-2 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge variant="outline" className={cn("text-xs font-semibold", SEVERITY_STYLES[ticket.severity])}>
                          {ticket.severity}
                        </Badge>
                        <span className="text-sm text-muted-foreground">
                          Score <strong className="text-foreground font-semibold">{ticket.score}</strong>/100
                        </span>
                      </div>
                      <h1 className="text-xl font-semibold leading-tight">{ticket.incident_title}</h1>
                      <p className="text-sm text-muted-foreground">
                        <span className="font-mono text-foreground">{formatTicketId(ticket.ticket_id)}</span>
                        {" · from alert "}
                        <Link href={`/alerts/${ticket.alert_id}`} className="font-mono text-foreground hover:text-primary underline-offset-4 hover:underline">
                          {ticket.alert_id}
                        </Link>
                        {" · "}
                        <span className="font-mono text-foreground">{ticket.source_ip}</span>
                        {ticket.destination_ip && (
                          <>
                            {" → "}
                            <span className="font-mono text-foreground">
                              {ticket.destination_ip}{ticket.destination_port ? `:${ticket.destination_port}` : ""}
                            </span>
                          </>
                        )}
                        {" · opened "}{formatDate(ticket.ticket_created_at)}
                      </p>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      {canEdit ? (
                        <>
                          <Select
                            items={Object.fromEntries(Object.entries(STATUS_LABELS).map(([v, l]) => [v, `Status: ${l}`]))}
                            value={ticket.status}
                            onValueChange={(v) => handleStatusChange(v as string | null)}
                            disabled={updating}
                          >
                            <SelectTrigger className="min-w-44 h-9" aria-label="Incident status">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {Object.entries(STATUS_LABELS).map(([v, l]) => (
                                <SelectItem key={v} value={v}>{l}</SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                          <button
                            disabled={generatingReport}
                            onClick={handleGenerateReport}
                            className="inline-flex items-center gap-2 h-9 px-4 text-sm font-semibold rounded-md bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                          >
                            {generatingReport ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                            {generatingReport ? "Generating…" : reports.length ? "New report version" : "Generate report"}
                          </button>
                        </>
                      ) : (
                        <div className="text-sm text-right">
                          <Badge variant="outline" className="text-xs bg-muted text-foreground border-border">
                            {STATUS_LABELS[ticket.status] ?? ticket.status}
                          </Badge>
                          <p className="text-muted-foreground mt-1">
                            Assigned to {assigneeName} · read only
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                </section>

                {/* ── Tabs ── */}
                <div role="tablist" className="flex gap-1 border-b border-border">
                  {([
                    ["investigation", "Investigation"],
                    ["reports", "Reports"],
                  ] as const).map(([key, label]) => (
                    <button
                      key={key}
                      role="tab"
                      aria-selected={activeTab === key}
                      onClick={() => setActiveTab(key)}
                      className={cn(
                        "px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors",
                        activeTab === key ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"
                      )}
                    >
                      {label}
                      {key === "reports" && reports.length > 0 && (
                        <span className="ml-2 rounded-full px-2 py-0.5 text-xs bg-muted text-muted-foreground">{reports.length}</span>
                      )}
                    </button>
                  ))}
                </div>

                {/* ── 2. Investigation tab ── */}
                {activeTab === "investigation" && (
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                    <div className="lg:col-span-2 space-y-5">
                      {/* L2 work comes first */}
                      <section className="rounded-lg border border-border bg-card">
                        <header className="flex items-center justify-between px-5 py-3 border-b border-border">
                          <h2 className="text-sm font-semibold">L2 investigation notes</h2>
                          {commentsDirty && canEdit && <span className="text-xs text-amber-400">Unsaved changes</span>}
                        </header>
                        <div className="p-5 space-y-3">
                          {canEdit ? (
                            <>
                              <textarea
                                value={comments}
                                onChange={(e) => setComments(e.target.value)}
                                placeholder="Findings, containment actions, evidence reviewed…"
                                rows={7}
                                maxLength={10000}
                                aria-label="L2 investigation notes"
                                className="w-full text-sm p-3 rounded-md bg-background border border-border focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/50 placeholder:text-muted-foreground resize-y"
                              />
                              <div className="flex justify-end">
                                <button
                                  onClick={handleSaveComments}
                                  disabled={savingComments || !commentsDirty}
                                  className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-md border border-border hover:bg-muted disabled:opacity-50"
                                >
                                  {commentsDirty || savingComments ? <Save className="h-4 w-4" /> : <CheckCircle2 className="h-4 w-4 text-emerald-400" />}
                                  {savingComments ? "Saving…" : commentsDirty ? "Save notes" : "Saved"}
                                </button>
                              </div>
                            </>
                          ) : (
                            <p className="text-sm whitespace-pre-wrap text-muted-foreground">
                              {ticket.comments || <span className="italic">No L2 notes yet.</span>}
                            </p>
                          )}
                        </div>
                      </section>

                      {/* L1 hand-off */}
                      <section className="rounded-lg border border-border bg-card p-5 space-y-3">
                        <div className="flex flex-wrap items-baseline justify-between gap-2">
                          <h2 className="text-sm font-semibold">Hand-off from L1</h2>
                          <span className="text-xs text-muted-foreground">
                            Escalated by {ticket.reviewed_by || "—"} · {formatDate(ticket.reviewed_at)}
                          </span>
                        </div>
                        <p className="text-sm whitespace-pre-wrap text-foreground/85">
                          {ticket.investigation_notes || <span className="italic text-muted-foreground">The L1 analyst left no notes.</span>}
                        </p>
                      </section>

                      {/* AI analysis */}
                      <section className="rounded-lg border border-border bg-card">
                        <header className="flex flex-wrap items-center justify-between gap-2 px-5 py-3 border-b border-border">
                          <h2 className="text-sm font-semibold flex items-center gap-2">
                            <Sparkles className="h-4 w-4 text-primary" />
                            AI triage analysis
                          </h2>
                          <span className="text-xs text-muted-foreground">Suggestion — the decision stays with the analyst</span>
                        </header>
                        <div className="p-5 space-y-5">
                          <p className="text-base leading-relaxed">{ticket.summary || "No AI summary available."}</p>
                          {ticket.recommended_action && (
                            <div className="rounded-md border-l-4 border-primary bg-primary/5 px-4 py-3">
                              <h3 className="text-xs font-semibold uppercase tracking-wide text-primary mb-1">Recommended action</h3>
                              <p className="text-sm leading-relaxed">{ticket.recommended_action}</p>
                            </div>
                          )}
                          {ticket.ioc_assessment && (
                            <div>
                              <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">Threat intelligence</h3>
                              <p className="text-sm leading-relaxed text-foreground/85">{ticket.ioc_assessment}</p>
                            </div>
                          )}
                          <IpReputationDisplay rawReputation={ticket.ip_reputation} />
                        </div>
                      </section>
                    </div>

                    {/* Side panel */}
                    <aside className="space-y-5">
                      <section className="rounded-lg border border-border bg-card p-4 space-y-3">
                        <h2 className="text-sm font-semibold">Assignment</h2>
                        <div>
                          <p className="font-medium">{assigneeName}</p>
                          {ticket.assigned_to && (
                            <p className="text-xs text-muted-foreground">SOC L2 · @{ticket.assigned_to}</p>
                          )}
                        </div>
                        {canEdit && analysts.length > 1 && (
                          <Select
                            items={Object.fromEntries(analysts.map((a) => [a.username, `Reassign: ${a.full_name}`]))}
                            value={ticket.assigned_to ?? undefined}
                            onValueChange={(v) => handleAssignChange(v as string | null)}
                            disabled={updating}
                          >
                            <SelectTrigger className="w-full" aria-label="Reassign incident">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {analysts.map((a) => (
                                <SelectItem key={a.username} value={a.username}>{a.full_name}</SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        )}
                      </section>

                      <section className="rounded-lg border border-border bg-card p-4 space-y-3">
                        <h2 className="text-sm font-semibold">MITRE ATT&amp;CK</h2>
                        {techniques.length === 0 && tactics.length === 0 ? (
                          <p className="text-sm text-muted-foreground">No technique mapped by the engine.</p>
                        ) : (
                          <dl className="space-y-3 text-sm">
                            {tactics.length > 0 && (
                              <div>
                                <dt className="text-xs text-muted-foreground mb-1">Tactics</dt>
                                <dd className="flex flex-wrap gap-1.5">
                                  {tactics.map((t) => <Badge key={t} variant="outline" className="text-xs">{t}</Badge>)}
                                </dd>
                              </div>
                            )}
                            {techniques.length > 0 && (
                              <div>
                                <dt className="text-xs text-muted-foreground mb-1">Techniques</dt>
                                <dd className="flex flex-wrap gap-1.5">
                                  {techniques.map((t) => (
                                    <a
                                      key={t}
                                      href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`}
                                      target="_blank"
                                      rel="noreferrer"
                                      className="font-mono text-xs px-2 py-0.5 rounded border border-border hover:border-primary hover:text-primary"
                                    >
                                      {t}
                                    </a>
                                  ))}
                                </dd>
                              </div>
                            )}
                          </dl>
                        )}
                      </section>

                      <details className="group rounded-lg border border-border bg-card">
                        <summary className="flex items-center justify-between px-4 py-3 text-sm font-semibold cursor-pointer list-none">
                          Technical details
                          <ChevronDown className="h-4 w-4 text-muted-foreground transition-transform group-open:rotate-180" />
                        </summary>
                        <dl className="px-4 pb-4 space-y-2 text-sm">
                          <InfoRow label="Attack type" value={ticket.attack_type} />
                          <InfoRow label="Source" value={ticket.source ?? "—"} />
                          <InfoRow label="Source port" value={ticket.source_port?.toString() ?? "—"} mono />
                          <InfoRow label="Frequency" value={ticket.frequency_count?.toLocaleString() ?? "—"} />
                          <InfoRow label="LLM" value={[ticket.llm_provider, ticket.llm_model].filter(Boolean).join(" · ") || "—"} />
                          {ticket.mitre_context && (
                            <div className="pt-2">
                              <dt className="text-xs text-muted-foreground mb-1">AI note on MITRE mapping</dt>
                              <dd className="text-muted-foreground">{ticket.mitre_context}</dd>
                            </div>
                          )}
                        </dl>
                      </details>
                    </aside>
                  </div>
                )}

                {/* ── 3. Reports tab ── */}
                {activeTab === "reports" && (
                  <div className="space-y-4">
                    {generatingReport && (
                      <div role="status" className="flex items-center gap-3 p-4 rounded-lg border border-primary/30 bg-primary/5 text-sm">
                        <Loader2 className="h-5 w-5 text-primary animate-spin" />
                        Generating the incident report from the alert data, L1 hand-off and your notes…
                      </div>
                    )}
                    {reportError && (
                      <div role="alert" className="p-3 rounded-md bg-destructive/10 border border-destructive/30 text-sm text-destructive">
                        {reportError}
                      </div>
                    )}

                    {reports.length === 0 ? (
                      !generatingReport && (
                        <div className="p-10 text-center rounded-lg border border-dashed border-border text-muted-foreground space-y-1">
                          <p className="font-medium text-foreground">No report yet</p>
                          <p className="text-sm">
                            {canEdit
                              ? "Save your investigation notes, then use “Generate report” — the AI drafts a structured Markdown report for you to review."
                              : "The assigned L2 analyst has not generated a report yet."}
                          </p>
                        </div>
                      )
                    ) : (
                      <div className="grid grid-cols-1 lg:grid-cols-4 gap-5">
                        {/* Version list */}
                        <nav aria-label="Report versions" className="space-y-1">
                          {reports.map((r, idx) => (
                            <button
                              key={r.id}
                              onClick={() => setSelectedReportIndex(idx)}
                              aria-current={idx === selectedReportIndex}
                              className={cn(
                                "w-full text-left px-3 py-2 rounded-md text-sm border",
                                idx === selectedReportIndex ? "border-primary bg-primary/5" : "border-transparent hover:bg-muted"
                              )}
                            >
                              <span className="font-medium">Version {r.version}</span>
                              {idx === 0 && <span className="ml-2 text-xs text-primary">latest</span>}
                              <span className="block text-xs text-muted-foreground">
                                {formatDate(r.generated_at)} · {r.generated_by}
                              </span>
                            </button>
                          ))}
                        </nav>

                        {selectedReport && (
                          <article className="lg:col-span-3 rounded-lg border border-border bg-card">
                            <header className="flex flex-wrap items-center justify-between gap-3 px-6 py-4 border-b border-border">
                              <div>
                                <h2 className="font-semibold">Incident report · version {selectedReport.version}</h2>
                                <p className="text-xs text-muted-foreground">
                                  Generated by {selectedReport.generated_by} on {formatDate(selectedReport.generated_at)}
                                </p>
                              </div>
                              <button
                                onClick={() => downloadReport(selectedReport)}
                                className="inline-flex items-center gap-2 px-3 py-1.5 text-sm rounded-md border border-border hover:bg-muted"
                              >
                                <Download className="h-4 w-4" />
                                Download .md
                              </button>
                            </header>
                            <div className="mx-6 mt-4 p-3 rounded-md bg-amber-500/10 border border-amber-500/30 flex gap-3 text-sm text-amber-200">
                              <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5 text-amber-400" />
                              <p>
                                <strong>AI-generated draft.</strong> Check every fact against the evidence before sharing it —
                                an analyst stays responsible for the final report.
                              </p>
                            </div>
                            <div className="report-markdown p-6">
                              <ReactMarkdown rehypePlugins={[rehypeSanitize]}>{stripCodeFence(selectedReport.content)}</ReactMarkdown>
                            </div>
                          </article>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        </main>
      </div>
    </AuthGuard>
  );
}

function InfoRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between items-start gap-3">
      <dt className="text-muted-foreground shrink-0">{label}</dt>
      <dd className={cn("text-right break-all", mono && "font-mono")}>{value}</dd>
    </div>
  );
}
