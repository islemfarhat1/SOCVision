"use client";

import { useEffect, useState } from "react";
import { Sidebar } from "@/components/sidebar";
import { Header } from "@/components/header";
import { AuthGuard } from "@/components/auth-guard";
import { StateDot } from "@/components/status";
import { SeverityBadge } from "@/components/severity";
import { fetchSystemStatus, type SystemStatus } from "@/lib/api";
import { parseDate } from "@/lib/time";

function Section({ title, description, children }: { title: string; description?: string; children: React.ReactNode }) {
  return (
    <section className="grid grid-cols-1 md:grid-cols-[240px_1fr] gap-4 md:gap-8 py-8 border-b border-border last:border-0">
      <div>
        <h2 className="text-sm font-semibold">{title}</h2>
        {description && <p className="mt-1 text-sm text-muted-foreground leading-relaxed">{description}</p>}
      </div>
      <div className="rounded-lg border border-border bg-card divide-y divide-border">{children}</div>
    </section>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-1 px-4 py-3 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-right">{children}</span>
    </div>
  );
}

export default function SettingsPage() {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    fetchSystemStatus().then(setStatus).catch(() => setError(true));
  }, []);

  return (
    <AuthGuard>
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header title="Settings" />
        <main className="flex-1 overflow-y-auto">
          <div className="max-w-5xl mx-auto px-6 py-2">
            {error && (
              <p role="alert" className="mt-6 text-sm text-destructive">Could not load the platform status. Check that the API is running.</p>
            )}
            {!status && !error && <p className="mt-6 text-sm text-muted-foreground">Loading…</p>}

            {status && (
              <>
                <p className="mt-6 text-xs text-muted-foreground">
                  Live values read from the API · version {status.version} · checked {parseDate(status.checked_at)?.toLocaleString()}
                </p>

                <Section title="Platform" description="Services the console depends on.">
                  <Row label="Database">
                    <StateDot ok={status.database === "connected"} label={status.database === "connected" ? "Connected" : "Unreachable"} />
                  </Row>
                  <Row label="Wazuh webhook">
                    <StateDot
                      ok={status.wazuh_webhook_enabled}
                      warn
                      label={status.wazuh_webhook_enabled ? "Enabled (token configured)" : "Disabled — no token configured"}
                    />
                  </Row>
                </Section>

                <Section
                  title="Threat intelligence"
                  description="External IP reputation. A lookup that fails is reported as “not checked”, never as clean."
                >
                  <Row label="VirusTotal">
                    <StateDot ok={status.threat_intel.virustotal_configured} warn label={status.threat_intel.virustotal_configured ? "API key configured" : "No API key"} />
                  </Row>
                  <Row label="AbuseIPDB">
                    <StateDot ok={status.threat_intel.abuseipdb_configured} warn label={status.threat_intel.abuseipdb_configured ? "API key configured" : "No API key"} />
                  </Row>
                  <Row label="MITRE ATT&CK">Built-in mapping of detection rules</Row>
                </Section>

                <Section
                  title="AI assistant"
                  description="Explains alerts and drafts incident reports. It never escalates, dismisses or closes anything: decisions stay with the analyst."
                >
                  <Row label="Ollama (local)">
                    <StateDot ok={status.llm.ollama_reachable} label={status.llm.ollama_reachable ? "Reachable" : "Not reachable"} />
                  </Row>
                  <Row label="Local models, in order of use">
                    <span className="flex flex-wrap justify-end gap-x-4 gap-y-1">
                      {status.llm.local_models.map((m, i) => (
                        <span key={m.name} className="inline-flex items-center gap-1.5">
                          <span className="text-muted-foreground">{i + 1}.</span>
                          <span className="font-mono">{m.name}</span>
                          <span className={m.installed ? "text-emerald-400" : "text-muted-foreground"}>
                            {m.installed ? "installed" : "not installed"}
                          </span>
                        </span>
                      ))}
                    </span>
                  </Row>
                  <Row label="Cloud fallback (OpenRouter)">
                    {status.llm.cloud_fallback_configured ? (
                      <span>
                        Enabled · <span className="font-mono">{status.llm.cloud_models.join(", ")}</span>
                        <span className="block text-xs text-amber-300">Alert data leaves the lab when the local models fail.</span>
                      </span>
                    ) : (
                      <span className="text-muted-foreground">Disabled — no API key, analysis stays local</span>
                    )}
                  </Row>
                  <Row label="Automatic decisions">Disabled (human-in-the-loop)</Row>
                </Section>

                <Section
                  title="Risk scoring"
                  description="Deterministic points added by the scoring engine. These are the values the backend applies."
                >
                  <Row label="Priority thresholds">
                    <span className="flex flex-wrap justify-end gap-2">
                      {status.scoring.priority_thresholds.map(([min, priority]) => (
                        <span key={priority} className="inline-flex items-center gap-1.5">
                          <SeverityBadge severity={priority} />
                          <span className="tabular-nums text-muted-foreground">≥ {min}</span>
                        </span>
                      ))}
                    </span>
                  </Row>
                  <Row label="IP reputation">
                    <span className="tabular-nums">
                      {Object.entries(status.scoring.reputation_points).map(([k, v]) => `${k} +${v}`).join(" · ")} · other / not checked +0
                    </span>
                  </Row>
                  <Row label="MITRE technique mapped">
                    <span className="tabular-nums">+{status.scoring.mitre_points}</span>
                  </Row>
                  <Row label="Frequency (Wazuh events)">
                    <span className="tabular-nums">
                      {status.scoring.wazuh_frequency_tiers.map(([n, pts]) => `≥ ${n}: +${pts}`).join(" · ")}
                    </span>
                  </Row>
                  <Row label="Frequency (CICIDS2017 flows)">
                    <span className="tabular-nums">
                      {status.scoring.flow_frequency_tiers.map(([n, pts]) => `> ${n.toLocaleString()}: +${pts}`).join(" · ")}
                    </span>
                  </Row>
                  <div className="px-4 py-3">
                    <p className="text-sm text-muted-foreground mb-2">Attack type (base points)</p>
                    <table className="w-full text-sm">
                      <tbody>
                        {Object.entries(status.scoring.attack_types).map(([type, pts]) => (
                          <tr key={type} className="border-t border-border first:border-0">
                            <td className="py-1.5">{type}</td>
                            <td className="py-1.5 text-right tabular-nums text-muted-foreground">+{pts}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Section>
              </>
            )}
          </div>
        </main>
      </div>
    </AuthGuard>
  );
}
