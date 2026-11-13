"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { Sidebar } from "@/components/sidebar";
import { Header } from "@/components/header";
import { Badge } from "@/components/ui/badge";
import {
  ArrowLeft, Save, CheckCircle2, ShieldOff, ShieldAlert,
  ArrowUpRight, Play, ChevronDown, Sparkles,
} from "lucide-react";
import { fetchAlert, promoteAlert, dismissAlert, updateAlert, fetchAnalysts } from "@/lib/api";
import { AuthGuard } from "@/components/auth-guard";
import { useAuth } from "@/lib/use-auth";
import { IpReputationDisplay } from "@/components/ip-reputation";
import { ScoreBreakdown, type ScoreBreakdownData } from "@/components/score-breakdown";
import { ActivityTimeline } from "@/components/activity-timeline";
import { SEVERITY_STYLES } from "@/components/severity";

type AlertDetail = {
  alert_id: string;
  incident_title: string;
  created_at: string;
  severity: string;
  attack_type: string;
  score: number;
  source_ip: string;
  destination_ip: string;
  source_port: number | null;
  destination_port: number | null;
  protocol: number | null;
  frequency_count: number | null;
  mitre_tactic: string | null;
  mitre: string | null;
  ip_reputation: string | null;
  summary: string | null;
  reasoning: string | null;
  ioc_assessment: string | null;
  mitre_context: string | null;
  recommended_action: string | null;
  source: string | null;
  llm_provider: string | null;
  llm_model: string | null;
  status: string;
  assigned_to: string | null;
  investigation_notes: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
  classification: string | null;
  score_breakdown?: ScoreBreakdownData | null;
};

// Colour is reserved for severity; statuses stay neutral so they don't compete with it.
const STATUS_STYLES: Record<string, string> = {
  NEW: "bg-foreground/10 text-foreground border-foreground/20",
  UNDER_REVIEW: "bg-foreground/10 text-foreground border-foreground/20",
  ESCALATED: "bg-muted text-muted-foreground border-border",
  DISMISSED: "bg-muted text-muted-foreground border-border",
};

const STATUS_LABELS: Record<string, string> = {
  NEW: "New",
  UNDER_REVIEW: "Under review",
  ESCALATED: "Escalated",
  DISMISSED: "Dismissed",
};

function splitList(raw: string | null): string[] {
  if (!raw || raw === "None" || raw === "Not identified") return [];
  return raw.split(",").map((t) => t.trim()).filter(Boolean);
}

function protocolName(protocol: number | null): string {
  if (protocol === 6) return "TCP";
  if (protocol === 17) return "UDP";
  return protocol == null ? "—" : String(protocol);
}

export default function AlertDetailPage() {
  const params = useParams();
  const alertId = params.alert_id as string;
  const { user } = useAuth();

  const [alert, setAlert] = useState<AlertDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Investigation notes state
  const [notes, setNotes] = useState("");
  const [savingNotes, setSavingNotes] = useState(false);
  const [notesSavedMsg, setNotesSavedMsg] = useState(false);

  // Triage & escalation state
  const [l2Analysts, setL2Analysts] = useState<{ id: number; username: string; full_name: string; role: string }[]>([]);
  const [selectedL2, setSelectedL2] = useState<string>("");
  const [showEscalateModal, setShowEscalateModal] = useState(false);
  const [showDismissModal, setShowDismissModal] = useState(false);

  useEffect(() => {
    fetchAlert(alertId)
      .then((data) => {
        setAlert(data);
        setNotes(data.investigation_notes || "");
      })
      .catch(() => setError("Alert not found"));
  }, [alertId]);

  const canAct = user?.role === "SOC_L1" || user?.role === "ADMIN";

  // ── Handlers ────────────────────────────────────────────────────────────────

  const handleStartTriage = async () => {
    if (!alert) return;
    setActionLoading(true);
    try {
      const updated = await updateAlert(alert.alert_id, { status: "UNDER_REVIEW" });
      setAlert(updated);
      setNotes(updated.investigation_notes || "");
    } catch (err) {
      console.error(err);
    } finally {
      setActionLoading(false);
    }
  };

  const handleSaveNotes = async () => {
    if (!alert) return;
    setSavingNotes(true);
    setNotesSavedMsg(false);
    try {
      const updated = await updateAlert(alert.alert_id, { investigation_notes: notes });
      setAlert(updated);
      setNotesSavedMsg(true);
      setTimeout(() => setNotesSavedMsg(false), 3000);
    } catch (err) {
      console.error(err);
    } finally {
      setSavingNotes(false);
    }
  };

  const handleEscalateClick = async () => {
    setActionLoading(true);
    try {
      const analysts = await fetchAnalysts("SOC_L2");
      setL2Analysts(analysts);
      if (analysts.length > 0) setSelectedL2(analysts[0].username);
      setShowEscalateModal(true);
    } catch (err) {
      console.error(err);
    } finally {
      setActionLoading(false);
    }
  };

  const handleConfirmEscalate = async () => {
    if (!alert || !selectedL2) return;
    setActionLoading(true);
    setShowEscalateModal(false);
    try {
      const result = await promoteAlert(alert.alert_id, selectedL2);
      const analystObj = l2Analysts.find(a => a.username === selectedL2);
      const displayName = analystObj ? `${analystObj.full_name} (@${analystObj.username})` : `@${selectedL2}`;
      
      const updated = await fetchAlert(alert.alert_id);
      setAlert(updated);
      setSuccessMsg(`✓ Escalation successful — Ticket ${result.ticket_id} assigned to ${displayName}`);
      setTimeout(() => setSuccessMsg(null), 6000);
    } catch (err) {
      console.error(err);
    } finally {
      setActionLoading(false);
    }
  };

  const handleConfirmDismiss = async () => {
    if (!alert) return;
    setActionLoading(true);
    setShowDismissModal(false);
    try {
      const updated = await dismissAlert(alert.alert_id);
      setAlert(updated);
      setSuccessMsg("✓ Alert marked as False Positive and dismissed.");
      setTimeout(() => setSuccessMsg(null), 6000);
    } catch (err) {
      console.error(err);
    } finally {
      setActionLoading(false);
    }
  };

  // ── Render ───────────────────────────────────────────────────────────────────

  const techniques = alert ? splitList(alert.mitre) : [];
  const tactics = alert ? splitList(alert.mitre_tactic) : [];
  const notesEditable = !!alert && canAct && alert.status === "UNDER_REVIEW";

  return (
    <AuthGuard allowedRoles={["SOC_L1", "MANAGER", "ADMIN"]}>
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header title={alert ? alert.alert_id : "Alert"} />
        <main className="flex-1 overflow-y-auto">
          <div className="max-w-6xl mx-auto p-6 space-y-5">
            <Link
              href="/alerts"
              className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground"
            >
              <ArrowLeft className="h-4 w-4" />
              Alert queue
            </Link>

            {error && <p className="text-sm text-destructive">{error}</p>}
            {!alert && !error && <p className="text-sm text-muted-foreground">Loading…</p>}

            {successMsg && (
              <div role="status" className="p-3 rounded-md bg-emerald-500/10 border border-emerald-500/30 text-sm text-emerald-300">
                {successMsg}
              </div>
            )}

            {alert && (
              <>
                {/* ── 1. Decision bar: what is it, how bad, what can I do ── */}
                <section className="sticky top-0 z-10 -mx-6 px-6 py-4 bg-background/95 backdrop-blur border-b border-border">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div className="space-y-2 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge variant="outline" className={`text-xs font-semibold ${SEVERITY_STYLES[alert.severity] ?? ""}`}>
                          {alert.severity}
                        </Badge>
                        <Badge variant="outline" className={`text-xs ${STATUS_STYLES[alert.status] ?? ""}`}>
                          {STATUS_LABELS[alert.status] ?? alert.status}
                        </Badge>
                        <span className="text-sm text-muted-foreground">
                          Score <strong className="text-foreground font-semibold">{alert.score}</strong>/100
                        </span>
                      </div>
                      <h1 className="text-xl font-semibold leading-tight">{alert.incident_title}</h1>
                      <p className="text-sm text-muted-foreground">
                        <span className="font-mono text-foreground">{alert.source_ip}</span>
                        {" → "}
                        <span className="font-mono text-foreground">
                          {alert.destination_ip}{alert.destination_port ? `:${alert.destination_port}` : ""}
                        </span>
                        {" · "}{alert.attack_type}
                        {" · "}{new Date(alert.created_at).toLocaleString()}
                      </p>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      {canAct && alert.status === "NEW" && (
                        <button
                          disabled={actionLoading}
                          onClick={handleStartTriage}
                          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold rounded-md bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                        >
                          <Play className="h-4 w-4" />
                          {actionLoading ? "Starting…" : "Start triage"}
                        </button>
                      )}
                      {canAct && alert.status === "UNDER_REVIEW" && (
                        <>
                          <button
                            disabled={actionLoading}
                            onClick={() => setShowDismissModal(true)}
                            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-md border border-border hover:bg-muted disabled:opacity-50"
                          >
                            <ShieldOff className="h-4 w-4" />
                            Dismiss as false positive
                          </button>
                          <button
                            disabled={actionLoading}
                            onClick={handleEscalateClick}
                            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold rounded-md bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                          >
                            <ArrowUpRight className="h-4 w-4" />
                            {actionLoading ? "Loading…" : "Escalate to L2"}
                          </button>
                        </>
                      )}
                      {(alert.status === "ESCALATED" || alert.status === "DISMISSED") && (
                        <div className="text-sm text-muted-foreground text-right">
                          <p className="text-foreground font-medium">
                            {alert.status === "ESCALATED"
                              ? `Escalated${alert.assigned_to ? ` to ${alert.assigned_to}` : " to SOC L2"}`
                              : "Dismissed as false positive"}
                          </p>
                          {alert.reviewed_by && (
                            <p>
                              by {alert.reviewed_by}
                              {alert.reviewed_at && ` · ${new Date(alert.reviewed_at).toLocaleString()}`}
                            </p>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                </section>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                  {/* ── 2. Why this score (rule engine), then the AI analysis ── */}
                  <div className="lg:col-span-2 space-y-5">
                    {alert.score_breakdown && (
                      <ScoreBreakdown data={alert.score_breakdown} storedSeverity={alert.severity} />
                    )}
                    <section className="rounded-lg border border-border bg-card">
                      <header className="flex flex-wrap items-center justify-between gap-2 px-5 py-3 border-b border-border">
                        <h2 className="text-sm font-semibold flex items-center gap-2">
                          <Sparkles className="h-4 w-4 text-primary" />
                          AI triage analysis
                        </h2>
                        <span className="text-xs text-muted-foreground">
                          Suggestion — the decision stays with the analyst
                        </span>
                      </header>
                      <div className="p-5 space-y-5">
                        <p className="text-base leading-relaxed">{alert.summary}</p>

                        <div className="rounded-md border-l-4 border-primary bg-primary/5 px-4 py-3">
                          <h3 className="text-xs font-semibold uppercase tracking-wide text-primary mb-1">
                            Recommended action
                          </h3>
                          <p className="text-sm leading-relaxed">{alert.recommended_action}</p>
                        </div>

                        <AnalysisBlock title="AI commentary on the score">{alert.reasoning}</AnalysisBlock>
                        <AnalysisBlock title="Threat intelligence">{alert.ioc_assessment}</AnalysisBlock>
                        <IpReputationDisplay rawReputation={alert.ip_reputation} />
                      </div>
                    </section>
                  </div>

                  {/* ── 3. Side panel: notes, MITRE, technical details ── */}
                  <aside className="space-y-5">
                    <section className="rounded-lg border border-border bg-card">
                      <header className="flex items-center justify-between px-4 py-3 border-b border-border">
                        <h2 className="text-sm font-semibold">Analyst notes</h2>
                        {notesSavedMsg && (
                          <span className="text-xs text-emerald-400 flex items-center gap-1">
                            <CheckCircle2 className="h-3.5 w-3.5" /> Saved
                          </span>
                        )}
                      </header>
                      <div className="p-4 space-y-3">
                        {notesEditable ? (
                          <>
                            <textarea
                              value={notes}
                              onChange={(e) => setNotes(e.target.value)}
                              placeholder="Triage findings, context, instructions for L2…"
                              rows={6}
                              aria-label="Analyst notes"
                              className="w-full text-sm p-3 rounded-md bg-background border border-border focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/50 placeholder:text-muted-foreground resize-y"
                            />
                            <button
                              onClick={handleSaveNotes}
                              disabled={savingNotes}
                              className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 text-sm font-medium rounded-md border border-border hover:bg-muted disabled:opacity-50"
                            >
                              <Save className="h-4 w-4" />
                              {savingNotes ? "Saving…" : "Save notes"}
                            </button>
                          </>
                        ) : (
                          <p className="text-sm whitespace-pre-wrap text-muted-foreground">
                            {alert.investigation_notes || (
                              <span className="italic">
                                {alert.status === "NEW" ? "Start triage to add notes." : "No notes recorded."}
                              </span>
                            )}
                          </p>
                        )}
                      </div>
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
                                {tactics.map((t) => (
                                  <Badge key={t} variant="outline" className="text-xs">{t}</Badge>
                                ))}
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
                        <InfoRow label="Alert ID" value={alert.alert_id} mono />
                        <InfoRow label="Source" value={alert.source ?? "—"} />
                        <InfoRow label="Source port" value={alert.source_port?.toString() ?? "—"} mono />
                        <InfoRow label="Destination port" value={alert.destination_port?.toString() ?? "—"} mono />
                        <InfoRow label="Protocol" value={protocolName(alert.protocol)} />
                        <InfoRow label="Frequency" value={alert.frequency_count?.toLocaleString() ?? "—"} />
                        <InfoRow label="LLM" value={[alert.llm_provider, alert.llm_model].filter(Boolean).join(" · ") || "—"} />
                        {alert.mitre_context && (
                          <div className="pt-2">
                            <dt className="text-xs text-muted-foreground mb-1">AI note on MITRE mapping</dt>
                            <dd className="text-muted-foreground">{alert.mitre_context}</dd>
                          </div>
                        )}
                      </dl>
                    </details>

                    <section className="rounded-lg border border-border bg-card p-4 space-y-3">
                      <h2 className="text-sm font-semibold">Activity</h2>
                      <ActivityTimeline
                        kind="alert"
                        id={alert.alert_id}
                        refreshKey={`${alert.status}|${alert.investigation_notes?.length ?? 0}|${alert.reviewed_at}`}
                      />
                    </section>
                  </aside>
                </div>
              </>
            )}
          </div>
        </main>
      </div>

      {/* ── Dismiss Confirmation Modal ── */}
      {showDismissModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="bg-card border border-border rounded-lg shadow-2xl max-w-md w-full mx-4 p-6 space-y-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-full bg-red-500/10 border border-red-500/20">
                <ShieldOff className="h-5 w-5 text-red-400" />
              </div>
              <h2 className="text-lg font-semibold">Confirm Dismissal</h2>
            </div>
            <p className="text-sm text-muted-foreground">
              You are about to mark this alert as a <strong className="text-foreground">False Positive</strong> and dismiss it.
              This decision will be logged with your name and cannot be undone.
            </p>
            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setShowDismissModal(false)}
                className="px-4 py-2 text-sm rounded-md bg-muted hover:bg-muted/80 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmDismiss}
                className="px-4 py-2 text-sm font-semibold rounded-md bg-red-500 hover:bg-red-600 text-white transition-colors"
              >
                Confirm — False Positive
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Escalate to L2 Modal ── */}
      {showEscalateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="bg-card border border-border rounded-lg shadow-2xl max-w-md w-full mx-4 p-6 space-y-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-full bg-primary/10 border border-primary/20">
                <ShieldAlert className="h-5 w-5 text-primary" />
              </div>
              <h2 className="text-lg font-semibold">Escalate to SOC L2</h2>
            </div>
            <p className="text-sm text-muted-foreground">
              Select the SOC L2 analyst to assign this incident to. A ticket will be automatically created.
            </p>
            {l2Analysts.length === 0 ? (
              <p className="text-sm text-yellow-400 bg-yellow-500/10 rounded p-3 border border-yellow-500/20">
                No SOC L2 analysts available. Please contact your administrator.
              </p>
            ) : (
              <div className="space-y-2">
                <label className="text-xs font-medium text-muted-foreground">Assigned Analyst</label>
                <select
                  value={selectedL2}
                  onChange={(e) => setSelectedL2(e.target.value)}
                  className="w-full p-2.5 text-sm rounded-md bg-background border border-border focus:border-primary focus:outline-none"
                >
                  {l2Analysts.map((a) => (
                    <option key={a.id} value={a.username}>
                      {a.full_name} — {a.username}
                    </option>
                  ))}
                </select>
              </div>
            )}
            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setShowEscalateModal(false)}
                className="px-4 py-2 text-sm rounded-md bg-muted hover:bg-muted/80 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmEscalate}
                disabled={l2Analysts.length === 0 || !selectedL2}
                className="px-4 py-2 text-sm font-semibold rounded-md bg-primary hover:bg-primary/90 text-primary-foreground transition-colors disabled:opacity-50"
              >
                Confirm escalation
              </button>
            </div>
          </div>
        </div>
      )}
    </AuthGuard>
  );
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function InfoRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between items-start gap-3">
      <dt className="text-muted-foreground shrink-0">{label}</dt>
      <dd className={`text-right break-all ${mono ? "font-mono" : ""}`}>{value}</dd>
    </div>
  );
}

function AnalysisBlock({ title, children }: { title: string; children: React.ReactNode }) {
  if (!children) return null;
  return (
    <div>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">{title}</h3>
      <p className="text-sm leading-relaxed text-foreground/85">{children}</p>
    </div>
  );
}
