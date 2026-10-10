"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { Sidebar } from "@/components/sidebar";
import { Header } from "@/components/header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  ArrowLeft, Save, FileText, CheckCircle2,
  ShieldOff, ShieldAlert, User, Clock,
  Cpu, BrainCircuit, Target, Network, Zap
} from "lucide-react";
import { fetchAlert, promoteAlert, dismissAlert, updateAlert, fetchAnalysts } from "@/lib/api";
import { AuthGuard } from "@/components/auth-guard";
import { useAuth } from "@/lib/use-auth";
import { IpReputationDisplay } from "@/components/ip-reputation";

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
};

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

  return (
    <AuthGuard allowedRoles={["SOC_L1", "ADMIN"]}>
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header title={alert ? `${alert.alert_id} — ${alert.incident_title}` : "Alert Detail"} />
        <main className="flex-1 overflow-y-auto p-6 space-y-4">

          {/* Back link */}
          <Link
            href="/alerts"
            className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground w-fit"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to alerts
          </Link>

          {error && <p className="text-sm text-destructive">{error}</p>}
          {!alert && !error && <p className="text-sm text-muted-foreground">Loading…</p>}

          {/* Success banner */}
          {successMsg && (
            <div className="p-3 rounded-md bg-green-500/10 border border-green-500/30 text-sm text-green-400">
              {successMsg}
            </div>
          )}

          {alert && (
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">

              {/* ── Left column: Alert metadata + action buttons ── */}
              <div className="lg:col-span-1 self-start sticky top-0 space-y-4">
                <Card className="h-fit border-border/60 shadow-sm bg-card/80">
                  <CardHeader className="pb-3 border-b border-border/40">
                    <CardTitle className="text-base flex items-center gap-2">
                      <ShieldAlert className="h-4 w-4 text-primary" /> Alert Details
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3 text-sm pt-4">
                    <InfoRow label="Alert ID" value={alert.alert_id} mono />
                    <InfoRow label="Created At" value={new Date(alert.created_at).toLocaleString()} />

                    <div className="flex justify-between items-center">
                      <span className="text-muted-foreground">Severity</span>
                      <Badge variant="outline" className={SEVERITY_STYLES[alert.severity]}>
                        {alert.severity}
                      </Badge>
                    </div>

                    <div className="flex justify-between items-center">
                      <span className="text-muted-foreground">Status</span>
                      <Badge variant="outline" className={STATUS_STYLES[alert.status] ?? ""}>
                        {alert.status.replace(/_/g, " ")}
                      </Badge>
                    </div>

                    <InfoRow label="Attack Type" value={alert.attack_type} />
                    <InfoRow label="Score" value={String(alert.score)} />
                    <InfoRow label="Source" value={alert.source ?? "—"} />

                    <Separator className="bg-border/40" />

                    <InfoRow label="Source IP" value={alert.source_ip} mono />
                    <InfoRow label="Source Port" value={alert.source_port?.toString() ?? "—"} mono />
                    <InfoRow label="Destination IP" value={alert.destination_ip} mono />
                    <InfoRow label="Dest. Port" value={alert.destination_port?.toString() ?? "—"} mono />
                    <InfoRow
                      label="Protocol"
                      value={
                        alert.protocol === 6 ? "TCP"
                          : alert.protocol === 17 ? "UDP"
                          : String(alert.protocol ?? "—")
                      }
                    />
                    <InfoRow label="Frequency" value={alert.frequency_count?.toLocaleString() ?? "—"} />

                    <Separator className="bg-border/40" />

                    <div className="flex flex-col gap-1.5">
                      <span className="text-muted-foreground">MITRE Tactics</span>
                      {(() => {
                        const rawTactic = alert.mitre_tactic;
                        if (!rawTactic || rawTactic === "None" || rawTactic === "Not identified") {
                          return <span className="text-right text-xs">None mapped</span>;
                        }
                        const tacticList = rawTactic.split(",").map((t: string) => t.trim()).filter(Boolean);
                        return (
                          <div className="flex flex-wrap gap-1.5 justify-end">
                            {tacticList.map((tactic: string, idx: number) => (
                              <Badge key={idx} variant="outline" className="text-[10px] bg-sky-500/10 text-sky-400 border-sky-500/25">
                                {tactic}
                              </Badge>
                            ))}
                          </div>
                        );
                      })()}
                    </div>

                    <div className="flex flex-col gap-1.5">
                      <span className="text-muted-foreground">MITRE Techniques</span>
                      {(() => {
                        const rawTech = alert.mitre;
                        if (!rawTech || rawTech === "None" || rawTech === "Not identified") {
                          return <span className="text-right text-xs">None mapped</span>;
                        }
                        const techList = rawTech.split(",").map((t: string) => t.trim()).filter(Boolean);
                        return (
                          <div className="flex flex-wrap gap-1.5 justify-end">
                            {techList.map((tech: string, idx: number) => (
                              <Badge key={idx} variant="outline" className="font-mono text-[10px] bg-primary/10 text-primary border-primary/25">
                                {tech}
                              </Badge>
                            ))}
                          </div>
                        );
                      })()}
                    </div>

                    <Separator className="bg-border/40" />

                    <InfoRow label="LLM Provider" value={alert.llm_provider ?? "—"} />
                    <InfoRow label="LLM Model" value={alert.llm_model ?? "—"} />

                    {/* ── Triage actions (SOC L1 / ADMIN only) ── */}
                    {canAct && (
                      <>
                        <Separator className="bg-border/40" />

                        {/* NEW → Start triage */}
                        {alert.status === "NEW" && (
                          <button
                            disabled={actionLoading}
                            onClick={handleStartTriage}
                            className="w-full px-3 py-2 text-xs font-semibold rounded-md bg-sky-500/15 text-sky-400 border border-sky-500/30 hover:bg-sky-500/25 transition-colors disabled:opacity-50"
                          >
                            {actionLoading ? "…" : "▶ Start Triage"}
                          </button>
                        )}

                        {/* UNDER_REVIEW → Escalate or Dismiss */}
                        {alert.status === "UNDER_REVIEW" && (
                          <div className="flex flex-col gap-2">
                            <button
                              disabled={actionLoading}
                              onClick={handleEscalateClick}
                              className="w-full px-3 py-2 text-xs font-semibold rounded-md bg-violet-500/15 text-violet-400 border border-violet-500/30 hover:bg-violet-500/25 transition-colors disabled:opacity-50"
                            >
                              {actionLoading ? "…" : "⬆ Escalate to SOC L2"}
                            </button>
                            <button
                              disabled={actionLoading}
                              onClick={() => setShowDismissModal(true)}
                              className="w-full px-3 py-2 text-xs font-semibold rounded-md bg-slate-500/15 text-slate-400 border border-slate-500/30 hover:bg-slate-500/25 transition-colors disabled:opacity-50"
                            >
                              ✕ Dismiss (False Positive)
                            </button>
                          </div>
                        )}
                      </>
                    )}

                    {/* ── Post-decision metadata ── */}
                    {(alert.status === "DISMISSED" || alert.status === "ESCALATED") && (
                      <>
                        <Separator className="bg-border/40" />
                        <div className="space-y-2 text-xs">
                          {alert.status === "DISMISSED" && (
                            <div className="p-2.5 rounded bg-slate-500/10 border border-slate-500/20 space-y-1 text-slate-300">
                              <div className="flex items-center gap-2 font-semibold text-slate-400">
                                <ShieldOff className="h-4 w-4 shrink-0" />
                                <span>Classification: False Positive</span>
                              </div>
                              {alert.reviewed_by && (
                                <p className="text-[11px] text-muted-foreground">
                                  Reviewed by: <span className="font-semibold text-foreground">{alert.reviewed_by}</span>
                                </p>
                              )}
                              {alert.reviewed_at && (
                                <p className="text-[11px] text-muted-foreground">
                                  Reviewed at: <span className="font-mono text-foreground">{new Date(alert.reviewed_at).toLocaleString()}</span>
                                </p>
                              )}
                            </div>
                          )}

                          {alert.status === "ESCALATED" && (
                            <div className="p-2.5 rounded bg-violet-500/10 border border-violet-500/20 space-y-1.5 text-violet-300">
                              <div className="flex items-center gap-2 font-semibold text-violet-400">
                                <ShieldAlert className="h-4 w-4 shrink-0" />
                                <span>Escalated to: SOC L2</span>
                              </div>
                              <div className="space-y-1 text-[11px] pt-0.5">
                                <div>
                                  <span className="text-muted-foreground">Assigned to: </span>
                                  <strong className="text-foreground">{alert.assigned_to || "Unassigned"}</strong>
                                </div>
                                {alert.assigned_to && (
                                  <div>
                                    <span className="text-muted-foreground">Username: </span>
                                    <span className="font-mono text-violet-300 font-semibold">{alert.assigned_to}</span>
                                  </div>
                                )}
                                {alert.reviewed_by && (
                                  <div>
                                    <span className="text-muted-foreground">Escalated by: </span>
                                    <strong className="text-foreground">{alert.reviewed_by}</strong>
                                  </div>
                                )}
                                {alert.reviewed_at && (
                                  <div>
                                    <span className="text-muted-foreground">Reviewed at: </span>
                                    <span className="font-mono text-foreground">{new Date(alert.reviewed_at).toLocaleString()}</span>
                                  </div>
                                )}
                              </div>
                            </div>
                          )}
                        </div>
                      </>
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* ── Right column: Investigation Workspace ── */}
              <div className="lg:col-span-3 flex flex-col gap-4">

                {/* Unified AI Analysis Report */}
                <Card className="bg-card/80 border-border/60 overflow-hidden shadow-sm">
                  <CardHeader className="bg-muted/10 border-b border-border/40 pb-4">
                    <div className="flex items-start justify-between">
                      <div>
                        <CardTitle className="text-lg flex items-center gap-2">
                          <Cpu className="h-5 w-5 text-primary" />
                          AI Triage Report
                        </CardTitle>
                        <p className="text-xs text-muted-foreground mt-1">Automated analysis and context for investigation</p>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="p-0">
                    {/* Summary Area */}
                    <div className="p-5 border-b border-border/40 bg-background/40">
                      <h4 className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                        <FileText className="h-3.5 w-3.5" /> Executive Summary
                      </h4>
                      <p className="text-sm leading-relaxed text-foreground">{alert.summary}</p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-border/40">
                      {/* Score & Reasoning */}
                      <div className="p-5 space-y-3">
                         <h4 className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                           <BrainCircuit className="h-3.5 w-3.5" /> Scoring Reasoning
                         </h4>
                         <p className="text-sm leading-relaxed text-muted-foreground">{alert.reasoning}</p>
                      </div>
                      
                      {/* IOC Assessment & IP Reputation */}
                      <div className="p-5 space-y-3">
                         <h4 className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                           <Target className="h-3.5 w-3.5" /> Threat Intelligence & Reputation
                         </h4>
                         <p className="text-sm leading-relaxed text-muted-foreground">{alert.ioc_assessment}</p>
                         <IpReputationDisplay rawReputation={alert.ip_reputation} />
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-border/40 border-t border-border/40">
                      {/* MITRE */}
                       <div className="p-5 space-y-3 bg-muted/5">
                          <h4 className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                            <Network className="h-3.5 w-3.5" /> MITRE ATT&CK
                          </h4>
                          {(() => {
                            const ctx = alert.mitre_context ?? "";
                            const hasTechnique = !!(alert.mitre && alert.mitre !== "None" && alert.mitre !== "Not identified");
                            const FALLBACK_MARKERS = [
                              "no mitre att&ck mapping",
                              "no att&ck mapping",
                              "aucune technique mitre",
                              "mappee par le moteur",
                              "not mapped",
                            ];
                            const isFallbackText = FALLBACK_MARKERS.some(m => ctx.toLowerCase().includes(m));
                            // If context is missing or contains fallback text but we have a known technique,
                            // auto-generate a clean description instead.
                            if (hasTechnique && (!ctx || isFallbackText)) {
                              const techs = alert.mitre!.split(",").map((t: string) => t.trim()).filter(Boolean);
                              const tactics = (alert.mitre_tactic ?? "").split(",").map((t: string) => t.trim()).filter(Boolean);
                              const parts = techs.map((tech: string, i: number) =>
                                tactics[i] ? `${tech} (${tactics[i]})` : tech
                              );
                              return (
                                <p className="text-sm leading-relaxed text-muted-foreground">
                                  This alert maps to MITRE ATT&amp;CK: {parts.join(", ")}.
                                </p>
                              );
                            }
                            return (
                              <p className="text-sm leading-relaxed text-muted-foreground">
                                {ctx || "No MITRE ATT\u0026CK mapping has been determined for this alert."}
                              </p>
                            );
                          })()}
                       </div>
                      
                      {/* Recommended Action */}
                      <div className="p-5 space-y-3 bg-emerald-500/5">
                         <h4 className="text-[11px] font-bold uppercase tracking-wider text-emerald-500 flex items-center gap-1.5">
                           <Zap className="h-3.5 w-3.5" /> Recommended Action
                         </h4>
                         <p className="text-sm leading-relaxed text-emerald-400/90">{alert.recommended_action}</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Investigation Notes */}
                <Card className="border-primary/30 bg-card/90 shadow-lg shadow-primary/5">
                  <CardHeader className="pb-3 border-b border-border/40">
                    <CardTitle className="text-base flex items-center justify-between">
                      <span className="flex items-center gap-2">
                        <FileText className="h-4 w-4 text-primary" />
                        Analyst Investigation Notes
                      </span>
                      {notesSavedMsg && (
                        <span className="text-xs text-emerald-400 flex items-center gap-1">
                          <CheckCircle2 className="h-3.5 w-3.5" /> Saved!
                        </span>
                      )}
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="p-4 space-y-3">
                    {/* Editable only when UNDER_REVIEW */}
                    {canAct && alert.status === "UNDER_REVIEW" ? (
                      <>
                        <textarea
                          value={notes}
                          onChange={(e) => setNotes(e.target.value)}
                          placeholder="Log your triage findings, context, or instructions for the L2 team here before making a decision…"
                          rows={5}
                          className="w-full text-sm p-3 rounded-md bg-background/60 border border-border/80 focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/50 transition-all placeholder:text-muted-foreground/60 resize-y"
                        />
                        <div className="flex justify-end pt-1">
                          <button
                            onClick={handleSaveNotes}
                            disabled={savingNotes}
                            className="px-4 py-2 text-xs font-semibold rounded-md bg-primary text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-50 flex items-center gap-1.5 shadow-sm"
                          >
                            <Save className="h-3.5 w-3.5" />
                            {savingNotes ? "Saving…" : "Save Notes"}
                          </button>
                        </div>
                      </>
                    ) : (
                      <div className="text-sm p-4 rounded-md bg-background/40 border border-border/50 min-h-[100px] whitespace-pre-wrap text-muted-foreground">
                        {alert.investigation_notes
                          ? alert.investigation_notes
                          : <span className="italic opacity-60">No investigation notes recorded for this alert.</span>
                        }
                      </div>
                    )}
                  </CardContent>
                </Card>

              </div>
            </div>
          )}
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
              <div className="p-2 rounded-full bg-purple-500/10 border border-purple-500/20">
                <ShieldAlert className="h-5 w-5 text-purple-400" />
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
                className="px-4 py-2 text-sm font-semibold rounded-md bg-purple-600 hover:bg-purple-700 text-white transition-colors disabled:opacity-50"
              >
                ⬆ Confirm Escalation
              </button>
            </div>
          </div>
        </div>
      )}
    </AuthGuard>
  );
}

// ── Helper ───────────────────────────────────────────────────────────────────

function InfoRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between items-start gap-2">
      <span className="text-muted-foreground shrink-0">{label}</span>
      <span className={`text-right break-all ${mono ? "font-mono text-xs" : ""}`}>{value}</span>
    </div>
  );
}
