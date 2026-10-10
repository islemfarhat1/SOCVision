"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Sidebar } from "@/components/sidebar";
import { Header } from "@/components/header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { fetchAlerts } from "@/lib/api";
import { AuthGuard } from "@/components/auth-guard";
import { Loader2 } from "lucide-react";

type Alert = {
  id: number;
  alert_id: string;
  incident_title: string;
  created_at: string;
  severity: string;
  attack_type: string;
  score: number;
  source_ip: string;
  destination_ip: string;
  status: string;
};

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-500 border-red-500/30",
  HIGH: "bg-orange-500/15 text-orange-500 border-orange-500/30",
  MEDIUM: "bg-yellow-500/15 text-yellow-500 border-yellow-500/30",
  LOW: "bg-green-500/15 text-green-500 border-green-500/30",
};

const STATUS_STYLES: Record<string, string> = {
  NEW: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  UNDER_REVIEW: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  ESCALATED: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  DISMISSED: "bg-slate-500/15 text-slate-400 border-slate-500/30",
};

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [severity, setSeverity] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const pageSize = 20;

  useEffect(() => { setPage(1); }, [severity, search, statusFilter]);

  useEffect(() => {
    const params: Record<string, string> = {
      sort: "score", order: "desc",
      page: String(page), size: String(pageSize),
    };
    if (severity !== "all") params.severity = severity;
    if (search) params.search = search;
    if (statusFilter !== "all") params.status = statusFilter;

    setLoading(true);
    const load = () => {
      fetchAlerts(params)
        .then(setAlerts)
        .catch(console.error)
        .finally(() => setLoading(false));
    };

    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, [severity, search, statusFilter, page]);

  return (
    <AuthGuard allowedRoles={["SOC_L1", "ADMIN"]}>
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header title="Alert Queue" />
        <main className="flex-1 overflow-y-auto p-6 space-y-4">

          {/* Filters */}
          <div className="flex gap-3 flex-wrap">
            <Input
              placeholder="Search IP or title…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="max-w-xs"
            />
            <Select value={severity} onValueChange={(v) => setSeverity(v ?? "all")}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="CRITICAL">CRITICAL</SelectItem>
                <SelectItem value="HIGH">HIGH</SelectItem>
                <SelectItem value="MEDIUM">MEDIUM</SelectItem>
                <SelectItem value="LOW">LOW</SelectItem>
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v ?? "all")}>
              <SelectTrigger className="w-44">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                <SelectItem value="NEW">New</SelectItem>
                <SelectItem value="UNDER_REVIEW">Under Review</SelectItem>
                <SelectItem value="ESCALATED">Escalated</SelectItem>
                <SelectItem value="DISMISSED">Dismissed</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Table */}
          <Card className="bg-card/80 border-border/60 shadow-sm overflow-hidden">
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-muted/20 text-muted-foreground">
                    <tr className="border-b border-border/30 text-left text-xs">
                      <th className="p-3 font-medium">Alert ID</th>
                      <th className="p-3 font-medium">Incident Title</th>
                      <th className="p-3 font-medium">Severity</th>
                      <th className="p-3 font-medium">Score</th>
                      <th className="p-3 font-medium">Attack Type</th>
                      <th className="p-3 font-medium">Source IP</th>
                      <th className="p-3 font-medium">Destination IP</th>
                      <th className="p-3 font-medium">Status</th>
                      <th className="p-3 font-medium">Created At</th>
                      <th className="p-3 font-medium">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {loading ? (
                      <tr><td colSpan={10} className="p-8 text-center text-muted-foreground"><Loader2 className="h-5 w-5 animate-spin mx-auto opacity-50" /></td></tr>
                    ) : alerts.length === 0 ? (
                      <tr><td colSpan={10} className="p-8 text-center text-muted-foreground">No alerts found matching your criteria.</td></tr>
                    ) : (
                      alerts.map((a) => (
                        <tr key={a.alert_id} className="odd:bg-muted/10 even:bg-transparent border-b border-border/20 hover:bg-accent/30 transition-colors">
                          <td className="p-3 font-mono text-xs text-primary font-semibold">
                            {a.alert_id}
                          </td>
                          <td className="p-3 text-xs max-w-[180px] truncate" title={a.incident_title}>
                            {a.incident_title}
                          </td>
                          <td className="p-3">
                            <Badge variant="outline" className={`text-[10px] ${SEVERITY_STYLES[a.severity]}`}>
                              {a.severity}
                            </Badge>
                          </td>
                          <td className="p-3">
                            <span className={`inline-flex items-center justify-center h-5 w-5 rounded text-[10px] font-bold ${
                              a.severity === 'CRITICAL' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 
                              a.severity === 'HIGH' ? 'bg-orange-500/10 text-orange-400 border border-orange-500/20' : 
                              'bg-muted text-muted-foreground border border-border'
                            }`}>
                              {a.score}
                            </span>
                          </td>
                          <td className="p-3 text-xs">{a.attack_type}</td>
                          <td className="p-3 font-mono text-[11px] text-muted-foreground">{a.source_ip}</td>
                          <td className="p-3 font-mono text-[11px] text-muted-foreground">{a.destination_ip}</td>
                          <td className="p-3">
                            <Badge variant="outline" className={`text-[10px] ${STATUS_STYLES[a.status] ?? ""}`}>
                              {a.status.replace(/_/g, " ")}
                            </Badge>
                          </td>
                          <td className="p-3 text-xs text-muted-foreground whitespace-nowrap">
                            {new Date(a.created_at).toLocaleString()}
                          </td>
                          <td className="p-3">
                            {(a.status === "NEW" || a.status === "UNDER_REVIEW") ? (
                              <Link
                                href={`/alerts/${a.alert_id}`}
                                className="px-2.5 py-1 text-xs font-semibold rounded-md bg-primary/20 text-primary border border-primary/30 hover:bg-primary/30 transition-colors whitespace-nowrap"
                              >
                                Triage →
                              </Link>
                            ) : (
                              <Link
                                href={`/alerts/${a.alert_id}`}
                                className="px-2.5 py-1 text-xs font-semibold rounded-md bg-muted text-muted-foreground border border-border hover:bg-accent transition-colors whitespace-nowrap"
                              >
                                View
                              </Link>
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

          {/* Pagination */}
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <span>Page {page} — {alerts.length} alerts shown</span>
            <div className="flex gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="px-3 py-1 rounded-md border border-border disabled:opacity-40 hover:bg-accent transition-colors"
              >
                Previous
              </button>
              <button
                onClick={() => setPage((p) => p + 1)}
                disabled={alerts.length < pageSize}
                className="px-3 py-1 rounded-md border border-border disabled:opacity-40 hover:bg-accent transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        </main>
      </div>
    </AuthGuard>
  );
}
