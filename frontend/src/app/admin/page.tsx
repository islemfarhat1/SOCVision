"use client";

import { Fragment, useCallback, useEffect, useState } from "react";
import { KeyRound, Plus, RefreshCw } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Header } from "@/components/header";
import { AuthGuard } from "@/components/auth-guard";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { adminApi, type AccountEvent, type ManagedUser } from "@/lib/api";
import { useAuth } from "@/lib/use-auth";
import { parseDate, timeAgo } from "@/lib/time";
import { cn } from "@/lib/utils";

const ROLE_LABELS: Record<string, string> = {
  SOC_L1: "SOC L1 · Triage",
  SOC_L2: "SOC L2 · Investigation",
  MANAGER: "Manager",
  ADMIN: "Administrator",
};

type Notice = { kind: "success" | "error"; text: string };

/** 16 characters from an unambiguous alphabet, generated in the browser. */
function generatePassword(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_!";
  const bytes = new Uint32Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
}

function describeEvent(e: AccountEvent): string {
  const who = e.details.username ?? "an account";
  switch (e.action) {
    case "USER_CREATED": return `created ${who} as ${ROLE_LABELS[e.details.role] ?? e.details.role}`;
    case "USER_ROLE_CHANGED": return `changed ${who}: ${ROLE_LABELS[e.details.from] ?? e.details.from} → ${ROLE_LABELS[e.details.to] ?? e.details.to}`;
    case "USER_DISABLED": return `disabled ${who}`;
    case "USER_ENABLED": return `re-enabled ${who}`;
    case "USER_RENAMED": return `renamed ${who} to ${e.details.to}`;
    case "PASSWORD_RESET": return `reset the password of ${who}`;
    default: return e.action.toLowerCase();
  }
}

function RoleSelect({ value, onChange, disabled, label }: {
  value: string;
  onChange: (v: string) => void;
  disabled?: boolean;
  label: string;
}) {
  return (
    <Select items={ROLE_LABELS} value={value} onValueChange={(v) => v && onChange(v as string)} disabled={disabled}>
      <SelectTrigger className="w-52" aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {Object.entries(ROLE_LABELS).map(([v, l]) => <SelectItem key={v} value={v}>{l}</SelectItem>)}
      </SelectContent>
    </Select>
  );
}

function PasswordField({ value, onChange, id }: { value: string; onChange: (v: string) => void; id: string }) {
  return (
    <div className="flex gap-2">
      <Input id={id} value={value} onChange={(e) => onChange(e.target.value)} autoComplete="new-password"
             className="font-mono" placeholder="At least 10 characters" />
      <button type="button" onClick={() => onChange(generatePassword())}
              className="inline-flex items-center gap-1.5 px-3 rounded-md border border-border text-sm hover:bg-muted shrink-0">
        <RefreshCw className="h-3.5 w-3.5" /> Generate
      </button>
    </div>
  );
}

export default function AdminPage() {
  const { user } = useAuth();
  const [users, setUsers] = useState<ManagedUser[] | null>(null);
  const [events, setEvents] = useState<AccountEvent[]>([]);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [busy, setBusy] = useState(false);

  const [showCreate, setShowCreate] = useState(false);
  const [draft, setDraft] = useState({ full_name: "", username: "", role: "SOC_L1", password: "" });
  const [resetFor, setResetFor] = useState<string | null>(null);
  const [resetPassword, setResetPassword] = useState("");
  const [confirmToggle, setConfirmToggle] = useState<string | null>(null);

  const reload = useCallback(async () => {
    const [u, e] = await Promise.all([adminApi.listUsers(), adminApi.accountEvents()]);
    setUsers(u);
    setEvents(e);
  }, []);

  useEffect(() => {
    let cancelled = false;
    Promise.all([adminApi.listUsers(), adminApi.accountEvents()])
      .then(([u, e]) => {
        if (cancelled) return;
        setUsers(u);
        setEvents(e);
      })
      .catch((err) => !cancelled && setNotice({ kind: "error", text: err.message }));
    return () => {
      cancelled = true;
    };
  }, []);

  const run = async (action: () => Promise<unknown>, success: string) => {
    setBusy(true);
    setNotice(null);
    try {
      await action();
      await reload();
      setNotice({ kind: "success", text: success });
      return true;
    } catch (err) {
      setNotice({ kind: "error", text: err instanceof Error ? err.message : "The request failed." });
      return false;
    } finally {
      setBusy(false);
    }
  };

  const createAccount = async (e: React.FormEvent) => {
    e.preventDefault();
    const ok = await run(() => adminApi.createUser({ ...draft, username: draft.username.trim().toLowerCase() }),
      `Account ${draft.username} created. Give the temporary password to its owner through a private channel.`);
    if (ok) {
      setDraft({ full_name: "", username: "", role: "SOC_L1", password: "" });
      setShowCreate(false);
    }
  };

  return (
    <AuthGuard allowedRoles={["ADMIN"]}>
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header title="Users & access" />
        <main className="flex-1 overflow-y-auto">
          <div className="max-w-6xl mx-auto p-6 space-y-6">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <p className="text-sm text-muted-foreground max-w-2xl">
                Accounts are never deleted: a disabled account can no longer sign in, but its incidents, reports and
                audit history stay attributed to it. Role changes and deactivations apply to open sessions immediately.
              </p>
              <button
                onClick={() => setShowCreate((v) => !v)}
                className="inline-flex items-center gap-2 h-9 px-4 rounded-md bg-primary text-primary-foreground text-sm font-semibold hover:bg-primary/90"
              >
                <Plus className="h-4 w-4" /> Add account
              </button>
            </div>

            {notice && (
              <div role={notice.kind === "error" ? "alert" : "status"}
                   className={cn("p-3 rounded-md border text-sm",
                     notice.kind === "error" ? "bg-destructive/10 border-destructive/30 text-red-300" : "bg-emerald-500/10 border-emerald-500/30 text-emerald-300")}>
                {notice.text}
              </div>
            )}

            {showCreate && (
              <form onSubmit={createAccount} className="rounded-lg border border-border bg-card p-5 grid gap-4 md:grid-cols-2">
                <h2 className="md:col-span-2 text-sm font-semibold">New account</h2>
                <label className="space-y-1.5 text-sm">
                  <span className="font-medium">Full name</span>
                  <Input value={draft.full_name} onChange={(e) => setDraft({ ...draft, full_name: e.target.value })} required minLength={2} />
                </label>
                <label className="space-y-1.5 text-sm">
                  <span className="font-medium">Username</span>
                  <Input value={draft.username} onChange={(e) => setDraft({ ...draft, username: e.target.value })}
                         required pattern="[a-z0-9._\-]{3,32}" className="font-mono" placeholder="firstname.lastname" />
                  <span className="text-xs text-muted-foreground">Lowercase letters, digits, dot, dash or underscore.</span>
                </label>
                <div className="space-y-1.5 text-sm">
                  <span className="font-medium block">Role</span>
                  <RoleSelect value={draft.role} onChange={(role) => setDraft({ ...draft, role })} label="Role of the new account" />
                </div>
                <div className="space-y-1.5 text-sm">
                  <label htmlFor="new-password" className="font-medium block">Temporary password</label>
                  <PasswordField id="new-password" value={draft.password} onChange={(password) => setDraft({ ...draft, password })} />
                </div>
                <div className="md:col-span-2 flex justify-end gap-2">
                  <button type="button" onClick={() => setShowCreate(false)} className="h-9 px-4 rounded-md border border-border text-sm hover:bg-muted">
                    Cancel
                  </button>
                  <button type="submit" disabled={busy} className="h-9 px-4 rounded-md bg-primary text-primary-foreground text-sm font-semibold disabled:opacity-50">
                    Create account
                  </button>
                </div>
              </form>
            )}

            <div className="rounded-lg border border-border bg-card overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                    <th className="px-4 py-3 font-medium">Account</th>
                    <th className="px-4 py-3 font-medium w-60">Role</th>
                    <th className="px-4 py-3 font-medium w-28">Status</th>
                    <th className="px-4 py-3 font-medium w-32 text-right">Active incidents</th>
                    <th className="px-4 py-3 font-medium w-72 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {!users ? (
                    <tr><td colSpan={5} className="p-10 text-center text-muted-foreground">Loading accounts…</td></tr>
                  ) : users.map((u) => {
                    const self = u.username === user?.username;
                    return (
                      <Fragment key={u.username}>
                        <tr className={cn("border-b border-border", u.disabled && "text-muted-foreground")}>
                          <td className="px-4 py-3">
                            <p className="font-medium">
                              {u.full_name}
                              {self && <span className="ml-2 text-xs text-primary">you</span>}
                            </p>
                            <p className="text-xs font-mono text-muted-foreground">{u.username}</p>
                          </td>
                          <td className="px-4 py-3">
                            <RoleSelect
                              value={u.role}
                              label={`Role of ${u.username}`}
                              disabled={self || busy}
                              onChange={(role) => run(() => adminApi.updateUser(u.username, { role }),
                                `${u.username} is now ${ROLE_LABELS[role]}. The change applies to their open session immediately.`)}
                            />
                          </td>
                          <td className="px-4 py-3">
                            <span className="inline-flex items-center gap-2">
                              <span aria-hidden className={cn("h-2 w-2 rounded-full", u.disabled ? "bg-muted-foreground" : "bg-emerald-500")} />
                              {u.disabled ? "Disabled" : "Active"}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-right tabular-nums">{u.active_incidents}</td>
                          <td className="px-4 py-3">
                            <div className="flex justify-end gap-2">
                              <button
                                onClick={() => { setResetFor(resetFor === u.username ? null : u.username); setResetPassword(""); setConfirmToggle(null); }}
                                className="inline-flex items-center gap-1.5 h-8 px-3 rounded-md border border-border text-sm hover:bg-muted whitespace-nowrap"
                              >
                                <KeyRound className="h-3.5 w-3.5" /> Reset password
                              </button>
                              {!self && (
                                <button
                                  onClick={() => { setConfirmToggle(confirmToggle === u.username ? null : u.username); setResetFor(null); }}
                                  className="h-8 px-3 rounded-md border border-border text-sm hover:bg-muted whitespace-nowrap"
                                >
                                  {u.disabled ? "Enable" : "Disable"}
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>

                        {resetFor === u.username && (
                          <tr className="border-b border-border bg-muted/30">
                            <td colSpan={5} className="px-4 py-3">
                              <div className="flex flex-wrap items-center gap-3">
                                <label htmlFor={`reset-${u.username}`} className="text-sm">New password for <span className="font-mono">{u.username}</span></label>
                                <div className="w-96 max-w-full">
                                  <PasswordField id={`reset-${u.username}`} value={resetPassword} onChange={setResetPassword} />
                                </div>
                                <button
                                  disabled={busy || resetPassword.length < 10}
                                  onClick={async () => {
                                    if (await run(() => adminApi.resetPassword(u.username, resetPassword),
                                      `Password of ${u.username} reset. Give it to them through a private channel.`)) setResetFor(null);
                                  }}
                                  className="h-9 px-4 rounded-md bg-primary text-primary-foreground text-sm font-semibold disabled:opacity-50"
                                >
                                  Save password
                                </button>
                              </div>
                            </td>
                          </tr>
                        )}

                        {confirmToggle === u.username && (
                          <tr className="border-b border-border bg-muted/30">
                            <td colSpan={5} className="px-4 py-3">
                              <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
                                <p>
                                  {u.disabled
                                    ? `Re-enable ${u.full_name}? They will be able to sign in again.`
                                    : `Disable ${u.full_name}? They will be signed out and unable to sign in.`}
                                  {!u.disabled && u.active_incidents > 0 && (
                                    <span className="block text-amber-300">
                                      {u.active_incidents} active incident{u.active_incidents > 1 ? "s are" : " is"} still assigned to this account: reassign {u.active_incidents > 1 ? "them" : "it"} from the incident page.
                                    </span>
                                  )}
                                </p>
                                <div className="flex gap-2">
                                  <button onClick={() => setConfirmToggle(null)} className="h-8 px-3 rounded-md border border-border hover:bg-muted">Cancel</button>
                                  <button
                                    disabled={busy}
                                    onClick={async () => {
                                      if (await run(() => adminApi.updateUser(u.username, { disabled: !u.disabled }),
                                        `${u.username} ${u.disabled ? "re-enabled" : "disabled"}.`)) setConfirmToggle(null);
                                    }}
                                    className={cn("h-8 px-3 rounded-md font-semibold disabled:opacity-50",
                                      u.disabled ? "bg-primary text-primary-foreground" : "bg-destructive text-white")}
                                  >
                                    {u.disabled ? "Enable account" : "Disable account"}
                                  </button>
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <section className="rounded-lg border border-border bg-card">
              <header className="px-5 py-3 border-b border-border">
                <h2 className="text-sm font-semibold">Recent account changes</h2>
                <p className="text-xs text-muted-foreground">From the audit log. Passwords are never recorded.</p>
              </header>
              {events.length === 0 ? (
                <p className="p-6 text-sm text-muted-foreground">No account change recorded yet.</p>
              ) : (
                <ul className="divide-y divide-border">
                  {events.map((e, i) => (
                    <li key={`${e.occurred_at}-${i}`} className="flex flex-wrap items-baseline justify-between gap-2 px-5 py-2.5 text-sm">
                      <span><span className="font-medium">{e.actor}</span> {describeEvent(e)}</span>
                      <span className="text-xs text-muted-foreground" title={parseDate(e.occurred_at)?.toLocaleString()}>
                        {timeAgo(e.occurred_at)}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        </main>
      </div>
    </AuthGuard>
  );
}
