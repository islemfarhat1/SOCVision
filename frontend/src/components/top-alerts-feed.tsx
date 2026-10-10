"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { fetchAlerts } from "@/lib/api";
import { ArrowUpRight, ShieldAlert, Sparkles } from "lucide-react";

type Alert = {
  alert_id: string;
  incident_title: string;
  created_at: string;
  severity: string;
  score: number;
  source_ip: string;
  destination_ip: string;
  status: string;
  mitre: string | null;
};

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-400 border-red-500/40 shadow-sm shadow-red-500/20 animate-pulse",
  HIGH: "bg-orange-500/20 text-orange-400 border-orange-500/40",
  MEDIUM: "bg-yellow-500/20 text-yellow-400 border-yellow-500/40",
  LOW: "bg-green-500/20 text-green-400 border-green-500/40",
};

const STATUS_STYLES: Record<string, string> = {
  NEW: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  UNDER_REVIEW: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  ESCALATED: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  DISMISSED: "bg-slate-500/15 text-slate-400 border-slate-500/30",
};

export function TopAlertsFeed() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = () => {
      fetchAlerts({ sort: "score", order: "desc", size: "8" })
        .then(setAlerts)
        .catch(console.error)
        .finally(() => setLoading(false));
    };

    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <Card className="bg-card/80 backdrop-blur-sm border-border/60 shadow-lg">
      <CardHeader className="flex flex-row items-center justify-between pb-3">
        <div className="space-y-1">
          <CardTitle className="text-base font-semibold flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-red-400" />
            Top Critical Alerts Stream
          </CardTitle>
          <p className="text-xs text-muted-foreground">
            Highest threat score alerts requiring analyst attention
          </p>
        </div>
        <Link
          href="/alerts"
          className="text-xs font-medium text-primary hover:underline flex items-center gap-1"
        >
          View Full Queue <ArrowUpRight className="h-3.5 w-3.5" />
        </Link>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-y border-border/60 bg-muted/30 text-left text-muted-foreground text-xs">
                <th className="p-3 font-medium">Alert ID</th>
                <th className="p-3 font-medium">Incident Title</th>
                <th className="p-3 font-medium">Severity</th>
                <th className="p-3 font-medium">Score</th>
                <th className="p-3 font-medium">Source → Target</th>
                <th className="p-3 font-medium">Status</th>
                <th className="p-3 font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={7} className="p-6 text-center text-muted-foreground text-xs">
                    Loading top threat alerts...
                  </td>
                </tr>
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-6 text-center text-muted-foreground text-xs">
                    No active critical alerts
                  </td>
                </tr>
              ) : (
                alerts.map((a) => (
                  <tr
                    key={a.alert_id}
                    className="border-b border-border/40 hover:bg-accent/40 transition-colors"
                  >
                    <td className="p-3 font-mono text-xs">
                      <Link
                        href={`/alerts/${a.alert_id}`}
                        className="text-primary hover:underline font-semibold"
                      >
                        {a.alert_id}
                      </Link>
                    </td>
                    <td className="p-3 text-xs max-w-[220px] truncate font-medium" title={a.incident_title}>
                      {a.incident_title}
                    </td>
                    <td className="p-3">
                      <Badge variant="outline" className={SEVERITY_STYLES[a.severity] ?? ""}>
                        {a.severity}
                      </Badge>
                    </td>
                    <td className="p-3 font-mono text-xs font-bold text-foreground">
                      {a.score}
                    </td>
                    <td className="p-3 font-mono text-xs text-muted-foreground">
                      <span className="text-foreground">{a.source_ip}</span>
                      <span className="mx-1 text-muted-foreground/60">→</span>
                      <span>{a.destination_ip}</span>
                    </td>
                    <td className="p-3">
                      <Badge variant="outline" className={STATUS_STYLES[a.status] ?? ""}>
                        {a.status.replace(/_/g, " ")}
                      </Badge>
                    </td>
                    <td className="p-3">
                      {a.status === "NEW" || a.status === "UNDER_REVIEW" ? (
                        <Link
                          href={`/alerts/${a.alert_id}`}
                          className="px-2.5 py-1 text-xs font-semibold rounded bg-primary/15 text-primary border border-primary/30 hover:bg-primary/25 transition-colors"
                        >
                          Triage →
                        </Link>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}
