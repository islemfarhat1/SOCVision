"use client";

import { Badge } from "@/components/ui/badge";
import { ShieldCheck, ShieldAlert, ShieldX, HelpCircle, Server } from "lucide-react";

type VirusTotalData = {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  [key: string]: any;
};

type AbuseIPDBData = {
  confidence?: number | string;
  confidence_score?: number | string;
  abuse_confidence_score?: number | string;
  reports?: number | string;
  total_reports?: number | string;
  [key: string]: any;
};

type ParsedReputation = {
  reputation?: string;
  score?: number;
  sources?: {
    VirusTotal?: VirusTotalData;
    AbuseIPDB?: AbuseIPDBData;
    [key: string]: any;
  };
};

function parseReputationData(raw: string | null | undefined): { parsed: ParsedReputation | null; rawString: string } {
  if (!raw || raw === "—" || raw.trim() === "") {
    return { parsed: null, rawString: "No data" };
  }

  const trimmed = raw.trim();

  // Try standard JSON parse
  try {
    const json = JSON.parse(trimmed);
    if (typeof json === "object" && json !== null) {
      return { parsed: json, rawString: trimmed };
    }
  } catch (e) {
    // Not standard JSON, try fixing Python single-quoted dict string
  }

  try {
    // Convert python single quotes to valid JSON quotes
    const formattedJson = trimmed
      .replace(/'/g, '"')
      .replace(/None/g, "null")
      .replace(/True/g, "true")
      .replace(/False/g, "false");
    const json = JSON.parse(formattedJson);
    if (typeof json === "object" && json !== null) {
      return { parsed: json, rawString: trimmed };
    }
  } catch (e) {
    // Failed fallback parsing
  }

  return { parsed: null, rawString: trimmed };
}

export function IpReputationDisplay({ rawReputation }: { rawReputation: string | null | undefined }) {
  const { parsed, rawString } = parseReputationData(rawReputation);

  if (!parsed) {
    // If it's a simple word like "Clean" or unparseable string
    const isClean = rawString.toLowerCase().includes("clean");
    const isMalicious = rawString.toLowerCase().includes("malicious");
    const isSuspicious = rawString.toLowerCase().includes("suspicious");

    return (
      <div className="flex items-center gap-2">
        <Badge
          variant="outline"
          className={
            isClean
              ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30 font-semibold"
              : isMalicious
              ? "bg-red-500/10 text-red-400 border-red-500/30 font-semibold"
              : isSuspicious
              ? "bg-amber-500/10 text-amber-400 border-amber-500/30 font-semibold"
              : "bg-muted text-muted-foreground"
          }
        >
          ● {rawString.toUpperCase()}
        </Badge>
      </div>
    );
  }

  const repStatus = (parsed.reputation || "UNKNOWN").toUpperCase();
  const vt = parsed.sources?.VirusTotal || parsed.sources?.virustotal;
  const abuse = parsed.sources?.AbuseIPDB || parsed.sources?.abuseipdb;

  const isClean = repStatus === "CLEAN";
  const isMalicious = repStatus === "MALICIOUS";
  const isSuspicious = repStatus === "SUSPICIOUS";
  const isInternal = repStatus.includes("INTERNAL") || repStatus.includes("PRIVATE");

  return (
    <div className="space-y-3.5 p-3.5 rounded-lg bg-background/50 border border-border/60">
      {/* Header Badge */}
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
          <Server className="h-3.5 w-3.5 text-primary" /> IP Reputation Assessment
        </span>
        <Badge
          variant="outline"
          className={
            isInternal
              ? "bg-slate-500/15 text-slate-400 border-slate-500/30 font-bold px-2.5 py-0.5"
              : isClean
              ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30 font-bold px-2.5 py-0.5"
              : isMalicious
              ? "bg-red-500/15 text-red-400 border-red-500/30 font-bold px-2.5 py-0.5"
              : isSuspicious
              ? "bg-amber-500/15 text-amber-400 border-amber-500/30 font-bold px-2.5 py-0.5"
              : "bg-muted text-muted-foreground font-bold px-2.5 py-0.5"
          }
        >
          ● {repStatus}
        </Badge>
      </div>

      {/* Sources Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs pt-1">
        {isInternal && (
          <div className="p-2.5 rounded border border-border/40 bg-card/60 space-y-2 col-span-1 sm:col-span-2">
            <div className="flex items-center justify-between font-semibold text-foreground border-b border-border/30 pb-1">
              <span>External Threat Intelligence</span>
            </div>
            <p className="text-muted-foreground pt-1">
              External reputation checks (VirusTotal, AbuseIPDB) are not applicable for internal or private IP addresses.
            </p>
          </div>
        )}

        {/* VirusTotal Section */}
        {!isInternal && vt && (
          <div className="p-2.5 rounded border border-border/40 bg-card/60 space-y-2">
            <div className="flex items-center justify-between font-semibold text-foreground border-b border-border/30 pb-1">
              <span>VirusTotal</span>
              <span className="text-[10px] text-muted-foreground font-mono">Feed</span>
            </div>
            <div className="space-y-1 font-mono text-[11px]">
              <div className="flex justify-between">
                <span className="text-muted-foreground font-sans">Malicious</span>
                <span className={vt.malicious && vt.malicious > 0 ? "text-red-400 font-bold" : "text-foreground"}>
                  {vt.malicious ?? 0}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground font-sans">Suspicious</span>
                <span className={vt.suspicious && vt.suspicious > 0 ? "text-amber-400 font-bold" : "text-foreground"}>
                  {vt.suspicious ?? 0}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground font-sans">Harmless</span>
                <span className="text-emerald-400 font-semibold">{vt.harmless ?? 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground font-sans">Undetected</span>
                <span className="text-muted-foreground">{vt.undetected ?? 0}</span>
              </div>
            </div>
          </div>
        )}

        {/* AbuseIPDB Section */}
        {!isInternal && abuse && (
          <div className="p-2.5 rounded border border-border/40 bg-card/60 space-y-2">
            <div className="flex items-center justify-between font-semibold text-foreground border-b border-border/30 pb-1">
              <span>AbuseIPDB</span>
              <span className="text-[10px] text-muted-foreground font-mono">Feed</span>
            </div>
            <div className="space-y-1 font-mono text-[11px]">
              <div className="flex justify-between">
                <span className="text-muted-foreground font-sans">Confidence</span>
                <span className="text-foreground font-semibold">
                  {abuse.confidence ?? abuse.confidence_score ?? abuse.abuse_confidence_score ?? 0}%
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground font-sans">Reports</span>
                <span className="text-foreground">
                  {abuse.reports ?? abuse.total_reports ?? 0}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
