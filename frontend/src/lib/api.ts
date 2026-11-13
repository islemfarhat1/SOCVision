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

// ─── System ──────────────────────────────────────────────────────────────────

export type ApiHealth = { status: "healthy" | "degraded"; database: string; timestamp: string };

/** Real API + database status (GET /api/health, no authentication required). */
export async function fetchHealth(): Promise<ApiHealth> {
  const res = await fetch(`${API_BASE_URL}/health`, { cache: "no-store" });
  if (!res.ok) throw new Error("API unavailable");
  return res.json();
}

export type SystemStatus = {
  version: string;
  checked_at: string;
  database: string;
  threat_intel: { virustotal_configured: boolean; abuseipdb_configured: boolean };
  llm: {
    ollama_reachable: boolean;
    local_models: { name: string; installed: boolean }[];
    cloud_fallback_configured: boolean;
    cloud_models: string[];
  };
  wazuh_webhook_enabled: boolean;
  scoring: {
    attack_types: Record<string, number>;
    wazuh_frequency_tiers: [number, number][];
    flow_frequency_tiers: [number, number][];
    reputation_points: Record<string, number>;
    mitre_points: number;
    priority_thresholds: [number, string][];
  };
};

/** Real platform configuration and scoring model (authenticated). */
export async function fetchSystemStatus(): Promise<SystemStatus> {
  const res = await fetch(`${API_BASE_URL}/system/status`, { headers: getHeaders(), cache: "no-store" });
  if (!res.ok) throw new Error("Failed to load the platform status");
  return res.json();
}

// ─── Auth ────────────────────────────────────────────────────────────────────

export async function login(username: string, password: string) {
  const res = await fetch(`${API_BASE_URL}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (res.status === 429) {
    const minutes = Math.ceil(Number(res.headers.get("Retry-After") ?? "900") / 60);
    throw new Error(`Too many failed attempts. Try again in ${minutes} minute${minutes > 1 ? "s" : ""}.`);
  }
  if (res.status === 403) {
    // Disabled account: the API only says so after a correct password.
    const body = await res.json().catch(() => null);
    throw new Error(typeof body?.detail === "string" ? body.detail : "This account is disabled.");
  }
  if (!res.ok) throw new Error("Invalid credentials. Please check your username and password.");
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

export type AlertStatusCounts = Record<"NEW" | "UNDER_REVIEW" | "ESCALATED" | "DISMISSED", number>;

/** One page of the alert queue plus the total number of matching alerts. */
export async function fetchAlertPage<T>(params: Record<string, string>): Promise<{ alerts: T[]; total: number }> {
  const res = await fetch(`${API_BASE_URL}/alerts?${new URLSearchParams(params)}`, { headers: getHeaders() });
  if (!res.ok) throw new Error("Failed to fetch alerts");
  const alerts: T[] = await res.json();
  const total = Number(res.headers.get("X-Total-Count") ?? alerts.length);
  return { alerts, total };
}

export async function fetchAlertStatusCounts(params: Record<string, string>): Promise<AlertStatusCounts> {
  const res = await fetch(`${API_BASE_URL}/alerts/status-counts?${new URLSearchParams(params)}`, {
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error("Failed to fetch alert counts");
  return res.json();
}

export type TimelineEvent = {
  at: string | null;
  actor: string;
  action: string;
  source: "recorded" | "record" | "reconstructed";
  details: Record<string, string | number | null>;
  alert_id: string | null;
  ticket_id: string | null;
};

/** Activity of one alert, or of a whole incident (alert + ticket + reports). */
export async function fetchTimeline(kind: "alert" | "ticket", id: string): Promise<TimelineEvent[]> {
  const path = kind === "alert" ? `alerts/${id}` : `tickets/${normalizeTicketId(id)}`;
  const res = await fetch(`${API_BASE_URL}/${path}/timeline`, { headers: getHeaders(), cache: "no-store" });
  if (!res.ok) throw new Error("Failed to load the activity");
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
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    const detail = typeof body?.detail === "string" ? body.detail : null;
    throw new Error(detail ?? "The change could not be saved.");
  }
  return res.json();
}

export async function generateIncidentReport(ticketId: string): Promise<IncidentReport> {
  const id = normalizeTicketId(ticketId);
  const res = await fetch(`${API_BASE_URL}/tickets/${id}/generate-report`, {
    method: "POST",
    headers: getHeaders(),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new Error(body?.detail ?? "Failed to generate the incident report. Please try again.");
  }
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

// ─── Administration (ADMIN only) ─────────────────────────────────────────────

export type ManagedUser = {
  id: number;
  username: string;
  full_name: string;
  role: "SOC_L1" | "SOC_L2" | "MANAGER" | "ADMIN";
  disabled: boolean;
  active_incidents: number;
};

export type AccountEvent = {
  occurred_at: string;
  actor: string;
  action: string;
  details: Record<string, string>;
};

async function adminRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE_URL}/admin${path}`, { ...init, headers: getHeaders(), cache: "no-store" });
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    const detail = body?.detail;
    // FastAPI validation errors come as a list
    const message = typeof detail === "string" ? detail : Array.isArray(detail) ? detail.map((d) => d.msg).join(" · ") : null;
    throw new Error(message ?? "The request failed.");
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}

export const adminApi = {
  listUsers: () => adminRequest<ManagedUser[]>("/users"),
  createUser: (user: { username: string; full_name: string; role: string; password: string }) =>
    adminRequest<ManagedUser>("/users", { method: "POST", body: JSON.stringify(user) }),
  updateUser: (username: string, changes: { full_name?: string; role?: string; disabled?: boolean }) =>
    adminRequest<ManagedUser>(`/users/${encodeURIComponent(username)}`, { method: "PATCH", body: JSON.stringify(changes) }),
  resetPassword: (username: string, password: string) =>
    adminRequest<void>(`/users/${encodeURIComponent(username)}/password`, { method: "POST", body: JSON.stringify({ password }) }),
  accountEvents: () => adminRequest<AccountEvent[]>("/audit"),
};

/** Change one's own password (the current password is required). */
export async function changeOwnPassword(currentPassword: string, newPassword: string): Promise<void> {
  const res = await fetch(`${API_BASE_URL}/auth/password`, {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
  if (res.ok) return;
  if (res.status === 429) {
    const minutes = Math.ceil(Number(res.headers.get("Retry-After") ?? "900") / 60);
    throw new Error(`Too many failed attempts. Try again in ${minutes} minute${minutes > 1 ? "s" : ""}.`);
  }
  const body = await res.json().catch(() => null);
  const detail = body?.detail;
  throw new Error(typeof detail === "string" ? detail : "The new password must have at least 10 characters.");
}
