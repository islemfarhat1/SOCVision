"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Sidebar } from "@/components/sidebar";
import { Header } from "@/components/header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { fetchTickets, updateTicket, fetchAnalysts, formatTicketId } from "@/lib/api";
import { AuthGuard } from "@/components/auth-guard";
import { useAuth, Role } from "@/lib/use-auth";

type Ticket = {
  id: number;
  ticket_id: string;
  alert_id: string;
  incident_title: string;
  severity: string;
  attack_type: string;
  score: number;
  source_ip: string;
  assigned_to: string | null;
  status: string;
  comments: string | null;
  ticket_created_at: string;
};

type Analyst = { id: number; username: string; full_name: string; role: string };

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-400 border-red-500/30",
  HIGH: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  MEDIUM: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  LOW: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
};

const TICKET_STATUS_STYLES: Record<string, string> = {
  OPEN: "bg-sky-500/15 text-sky-400 border-sky-500/30",
  IN_PROGRESS: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  CLOSED: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
};

export default function IncidentsPage() {
  const { user } = useAuth();
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [loading, setLoading] = useState(true);

  // Only SOC_L2 and ADMIN can edit incidents
  const canEdit = user?.role === "SOC_L2" || user?.role === "ADMIN";

  useEffect(() => {
    const load = () => {
      fetchTickets()
        .then(setTickets)
        .finally(() => setLoading(false));
    };
    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <AuthGuard allowedRoles={["SOC_L2", "SOC_MANAGER", "MANAGER", "ADMIN"]}>
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header title="Incidents Queue" />
        <main className="flex-1 overflow-y-auto p-6 space-y-4">
          <Card className="bg-card/80 border-border/60 shadow-sm overflow-hidden">
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-muted/20 text-muted-foreground">
                    <tr className="border-b border-border/30 text-left text-xs">
                      <th className="p-3 font-medium">Ticket ID</th>
                      <th className="p-3 font-medium">Original Alert</th>
                      <th className="p-3 font-medium">Incident</th>
                      <th className="p-3 font-medium">Severity</th>
                      <th className="p-3 font-medium">Score</th>
                      <th className="p-3 font-medium">Status</th>
                      <th className="p-3 font-medium">Assigned To</th>
                      <th className="p-3 font-medium">Comments</th>
                    </tr>
                  </thead>
                  <tbody>
                    {loading ? (
                      <tr><td colSpan={8} className="p-8 text-center text-muted-foreground">Loading incidents...</td></tr>
                    ) : tickets.length === 0 ? (
                      <tr><td colSpan={8} className="p-8 text-center text-muted-foreground">No incidents found in the queue.</td></tr>
                    ) : (
                      tickets.map((t) => (
                        <tr key={t.ticket_id} className="odd:bg-muted/10 even:bg-transparent border-b border-border/20 hover:bg-accent/30 transition-colors">
                          <td className="p-3 font-mono text-xs font-semibold text-primary">
                            <Link href={`/tickets/${formatTicketId(t.ticket_id)}`} className="hover:underline">
                              {formatTicketId(t.ticket_id)}
                            </Link>
                          </td>
                          <td className="p-3">
                            <span className="font-mono text-xs text-muted-foreground bg-muted/40 px-1.5 py-0.5 rounded border border-border/40 select-all">
                              {t.alert_id}
                            </span>
                          </td>
                          <td className="p-3 text-xs max-w-[220px] truncate" title={t.incident_title}>
                            {t.incident_title}
                          </td>
                          <td className="p-3">
                            <Badge variant="outline" className={`text-[10px] ${SEVERITY_STYLES[t.severity]}`}>
                              {t.severity}
                            </Badge>
                          </td>
                          <td className="p-3">
                            <span className={`inline-flex items-center justify-center h-5 w-7 rounded text-[10px] font-bold font-mono ${
                              t.severity === 'CRITICAL' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 
                              t.severity === 'HIGH' ? 'bg-orange-500/10 text-orange-400 border border-orange-500/20' : 
                              'bg-muted text-muted-foreground border border-border'
                            }`}>
                              {t.score}
                            </span>
                          </td>
                          <td className="p-3">
                            <StatusCell
                              ticketId={t.ticket_id}
                              status={t.status}
                              userRole={user?.role}
                              canEdit={canEdit}
                              onStatus={(status) =>
                                setTickets((prev) =>
                                  prev.map((x) =>
                                    x.ticket_id === t.ticket_id ? { ...x, status } : x
                                  )
                                )
                              }
                            />
                          </td>
                          <td className="p-3">
                            <AssignCell
                              ticketId={t.ticket_id}
                              assignedTo={t.assigned_to}
                              canEdit={canEdit}
                              onAssigned={(name) =>
                                setTickets((prev) =>
                                  prev.map((x) =>
                                    x.ticket_id === t.ticket_id ? { ...x, assigned_to: name } : x
                                  )
                                )
                              }
                            />
                          </td>
                          <td className="p-3 text-xs text-muted-foreground max-w-[150px] truncate" title={t.comments ?? ""}>
                            {t.comments || <span className="italic text-muted-foreground/60 text-[11px]">No L2 comments</span>}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </main>
      </div>
    </AuthGuard>
  );
}

// ─── StatusCell ───────────────────────────────────────────────────────────────

function StatusCell({
  ticketId,
  status,
  onStatus,
  userRole,
  canEdit,
}: {
  ticketId: string;
  status: string;
  onStatus: (status: string) => void;
  userRole?: Role;
  canEdit?: boolean;
}) {
  const [editing, setEditing] = useState(false);

  const save = async (value: string | null) => {
    if (!value) return;
    await updateTicket(ticketId, { status: value });
    onStatus(value);
    setEditing(false);
  };

  if (editing && canEdit) {
    return (
      <Select value={status} onValueChange={save}>
        <SelectTrigger className="w-36 h-8 text-xs">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="OPEN">Open</SelectItem>
          <SelectItem value="IN_PROGRESS">In Progress</SelectItem>
          {userRole !== "SOC_L1" && (
            <SelectItem value="CLOSED">Closed</SelectItem>
          )}
        </SelectContent>
      </Select>
    );
  }

  return canEdit ? (
    <button
      onClick={() => setEditing(true)}
      className="text-xs text-muted-foreground hover:text-foreground hover:underline"
    >
      <Badge variant="outline" className={TICKET_STATUS_STYLES[status] ?? ""}>
        {status.replace("_", " ")}
      </Badge>
    </button>
  ) : (
    <Badge variant="outline" className={TICKET_STATUS_STYLES[status] ?? ""}>
      {status.replace("_", " ")}
    </Badge>
  );
}

// ─── AssignCell ──────────────────────────────────────────────────────────────

function AssignCell({
  ticketId,
  assignedTo,
  canEdit,
  onAssigned,
}: {
  ticketId: string;
  assignedTo: string | null;
  canEdit?: boolean;
  onAssigned: (name: string | null) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [analysts, setAnalysts] = useState<Analyst[]>([]);

  useEffect(() => {
    if (analysts.length === 0) {
      fetchAnalysts()
        .then(setAnalysts)
        .catch(console.error);
    }
  }, [analysts.length]);

  const assign = async (username: string) => {
    await updateTicket(ticketId, { assigned_to: username });
    onAssigned(username);
    setEditing(false);
  };

  const matchedAnalyst = analysts.find(a => a.username === assignedTo);
  const displayName = matchedAnalyst ? matchedAnalyst.full_name : (assignedTo || "Unassigned");

  if (editing && canEdit) {
    return (
      <div className="absolute z-10 bg-card border border-border rounded-md p-3 space-y-2 w-56 shadow-lg">
        <Select
          onValueChange={(value) => {
            if (typeof value === "string" && value) {
              assign(value);
            }
          }}
        >
          <SelectTrigger className="h-7 text-xs">
            <SelectValue placeholder="Select analyst" />
          </SelectTrigger>
          <SelectContent>
            {analysts.length === 0 ? (
              <SelectItem value="none" disabled>Aucun analyste SOC trouvé</SelectItem>
            ) : (
              analysts.map((a) => (
                <SelectItem key={a.id} value={a.username}>
                  {a.full_name} ({a.role})
                </SelectItem>
              ))
            )}
          </SelectContent>
        </Select>
        <div className="flex justify-end">
          <button
            onClick={() => setEditing(false)}
            className="text-xs px-2 py-1 rounded-md border border-border hover:bg-accent"
          >
            Close
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="relative">
      {canEdit ? (
        <button
          onClick={() => setEditing(true)}
          className="text-xs text-muted-foreground hover:text-foreground hover:underline text-left"
        >
          {displayName}
        </button>
      ) : (
        <span className="text-xs text-muted-foreground">{displayName}</span>
      )}
    </div>
  );
}