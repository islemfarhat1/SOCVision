const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api";

function getHeaders() {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("auth_token");
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  }
  return headers;
}

export type IncidentReport = {
  id: number;
  ticket_id: string;
  generated_by: string;
  generated_at: string;
  content: string;
  version: number;
};

// ─── Auth ────────────────────────────────────────────────────────────────────

export async function login(username: string, password: string) {
  const res = await fetch(`${API_BASE_URL}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) throw new Error("Invalid credentials");
  return res.json();
}

export async function fetchAuthMe() {
  const res = await fetch(`${API_BASE_URL}/auth/me`, { headers: getHeaders() });
  if (!res.ok) throw new Error("Unauthorized");
  return res.json();
}

// ─── Dashboard & Statistics ──────────────────────────────────────────────────

export async function fetchDashboard() {
  const res = await fetch(`${API_BASE_URL}/dashboard`, { headers: getHeaders() });
  if (!res.ok) throw new Error("Failed to fetch dashboard");
  return res.json();
}

export async function fetchTopEntities() {
  const res = await fetch(`${API_BASE_URL}/statistics/top-entities`, { headers: getHeaders() });
  if (!res.ok) throw new Error("Failed to fetch top entities");
  return res.json();
}

// ─── Alerts ──────────────────────────────────────────────────────────────────

export async function fetchAlerts(params?: Record<string, string>) {
  const query = params ? `?${new URLSearchParams(params)}` : "";
  const res = await fetch(`${API_BASE_URL}/alerts${query}`, { headers: getHeaders() });
  if (!res.ok) throw new Error("Failed to fetch alerts");
  return res.json();
}

export async function fetchAlert(alertId: string) {
  const res = await fetch(`${API_BASE_URL}/alerts/${alertId}`, { headers: getHeaders() });
  if (!res.ok) throw new Error("Failed to fetch alert");
  return res.json();
}

export async function promoteAlert(alertId: string, assignedTo: string) {
  const res = await fetch(`${API_BASE_URL}/alerts/${alertId}/promote`, {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({ assigned_to: assignedTo }),
  });
  if (!res.ok) throw new Error("Failed to promote alert");
  return res.json();
}

export async function dismissAlert(alertId: string) {
  const res = await fetch(`${API_BASE_URL}/alerts/${alertId}`, {
    method: "PATCH",
    headers: getHeaders(),
    body: JSON.stringify({ status: "DISMISSED", classification: "FALSE_POSITIVE" }),
  });
  if (!res.ok) throw new Error("Failed to dismiss alert");
  return res.json();
}

export async function updateAlert(alertId: string, data: { status?: string; investigation_notes?: string; classification?: string }) {
  const res = await fetch(`${API_BASE_URL}/alerts/${alertId}`, {
    method: "PATCH",
    headers: getHeaders(),
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error("Failed to update alert");
  return res.json();
}

export async function updateAlertStatus(alertId: string, status: string) {
  return updateAlert(alertId, { status });
}

// ─── Ticket ID Helpers ───────────────────────────────────────────────────────

export function formatTicketId(id?: string | null): string {
  if (!id) return "—";
  if (id.startsWith("INC-")) return `TCK-${id.slice(4)}`;
  return id;
}

export function normalizeTicketId(id: string): string {
  if (id.startsWith("TCK-")) return `INC-${id.slice(4)}`;
  return id;
}

// ─── Tickets (Incidents) ─────────────────────────────────────────────────────

export async function fetchTickets(params?: Record<string, string>) {
  const query = params ? `?${new URLSearchParams(params)}` : "";
  const res = await fetch(`${API_BASE_URL}/tickets${query}`, { headers: getHeaders() });
  if (!res.ok) throw new Error("Failed to fetch tickets");
  return res.json();
}

export async function fetchTicket(ticketId: string) {
  const id = normalizeTicketId(ticketId);
  const res = await fetch(`${API_BASE_URL}/tickets/${id}`, { headers: getHeaders() });
  if (!res.ok) {
    const res2 = await fetch(`${API_BASE_URL}/tickets/${ticketId}`, { headers: getHeaders() });
    if (!res2.ok) throw new Error("Failed to fetch ticket");
    return res2.json();
  }
  return res.json();
}

export async function updateTicket(ticketId: string, updates: { status?: string; assigned_to?: string | null; comments?: string }) {
  const id = normalizeTicketId(ticketId);
  const res = await fetch(`${API_BASE_URL}/tickets/${id}`, {
    method: "PATCH",
    headers: getHeaders(),
    body: JSON.stringify(updates),
  });
  if (!res.ok) throw new Error("Failed to update ticket");
  return res.json();
}

export async function generateIncidentReport(ticketId: string): Promise<IncidentReport> {
  const id = normalizeTicketId(ticketId);
  const res = await fetch(`${API_BASE_URL}/tickets/${id}/generate-report`, {
    method: "POST",
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error("Failed to generate incident report");
  return res.json();
}

export async function fetchIncidentReports(ticketId: string): Promise<IncidentReport[]> {
  const id = normalizeTicketId(ticketId);
  const res = await fetch(`${API_BASE_URL}/tickets/${id}/reports`, {
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error("Failed to fetch incident reports");
  return res.json();
}

// ─── Users ───────────────────────────────────────────────────────────────────

export async function fetchAnalysts(role?: string) {
  const query = role ? `?role=${role}` : "";
  const res = await fetch(`${API_BASE_URL}/users${query}`, { headers: getHeaders() });
  if (!res.ok) throw new Error("Failed to fetch analysts");
  return res.json();
}