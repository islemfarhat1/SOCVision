"use client";

import { useState } from "react";
import { Sidebar, ROLE_LABELS } from "@/components/sidebar";
import { Header } from "@/components/header";
import { AuthGuard } from "@/components/auth-guard";
import { Input } from "@/components/ui/input";
import { changeOwnPassword } from "@/lib/api";
import { useAuth } from "@/lib/use-auth";
import { cn } from "@/lib/utils";

const MIN_LENGTH = 10;

export default function AccountPage() {
  const { user } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ kind: "success" | "error"; text: string } | null>(null);

  const tooShort = next.length > 0 && next.length < MIN_LENGTH;
  const mismatch = confirm.length > 0 && confirm !== next;
  const canSubmit = current.length > 0 && next.length >= MIN_LENGTH && confirm === next && !busy;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setResult(null);
    try {
      await changeOwnPassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      setResult({ kind: "success", text: "Password changed. Use the new one at your next sign-in." });
    } catch (err) {
      setResult({ kind: "error", text: err instanceof Error ? err.message : "The password could not be changed." });
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthGuard>
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header title="My account" />
        <main className="flex-1 overflow-y-auto">
          <div className="max-w-3xl mx-auto p-6 space-y-8">
            <section className="rounded-lg border border-border bg-card divide-y divide-border">
              {[
                ["Name", user?.full_name],
                ["Username", user?.username],
                ["Role", user ? ROLE_LABELS[user.role] ?? user.role : undefined],
              ].map(([label, value]) => (
                <div key={label} className="flex justify-between gap-4 px-4 py-3 text-sm">
                  <span className="text-muted-foreground">{label}</span>
                  <span className={cn(label === "Username" && "font-mono")}>{value ?? "—"}</span>
                </div>
              ))}
              <p className="px-4 py-3 text-xs text-muted-foreground">Your name and role are managed by an administrator.</p>
            </section>

            <form onSubmit={submit} className="rounded-lg border border-border bg-card p-5 space-y-4" noValidate>
              <div>
                <h2 className="text-sm font-semibold">Change password</h2>
                <p className="text-sm text-muted-foreground">
                  At least {MIN_LENGTH} characters. A long passphrase is easier to remember and harder to guess.
                </p>
              </div>

              <div className="space-y-1.5 text-sm">
                <label htmlFor="current-password" className="block font-medium">Current password</label>
                <Input id="current-password" type="password" autoComplete="current-password" value={current}
                       onChange={(e) => setCurrent(e.target.value)} />
              </div>
              <div className="space-y-1.5 text-sm">
                <label htmlFor="new-password" className="block font-medium">New password</label>
                <Input id="new-password" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)}
                       aria-invalid={tooShort} aria-describedby="new-hint" />
                <p id="new-hint" className={cn("text-xs", tooShort ? "text-amber-300" : "text-muted-foreground")}>
                  {next.length}/{MIN_LENGTH} characters minimum
                </p>
              </div>
              <div className="space-y-1.5 text-sm">
                <label htmlFor="confirm-password" className="block font-medium">Confirm new password</label>
                <Input id="confirm-password" type="password" autoComplete="new-password" value={confirm}
                       onChange={(e) => setConfirm(e.target.value)} aria-invalid={mismatch} aria-describedby="confirm-hint" />
                {mismatch && <p id="confirm-hint" className="text-xs text-amber-300">The two passwords do not match.</p>}
              </div>

              {result && (
                <div role={result.kind === "error" ? "alert" : "status"}
                     className={cn("p-3 rounded-md border text-sm",
                       result.kind === "error" ? "bg-destructive/10 border-destructive/30 text-red-300" : "bg-emerald-500/10 border-emerald-500/30 text-emerald-300")}>
                  {result.text}
                </div>
              )}

              <div className="flex justify-end">
                <button type="submit" disabled={!canSubmit}
                        className="h-9 px-4 rounded-md bg-primary text-primary-foreground text-sm font-semibold hover:bg-primary/90 disabled:opacity-50">
                  {busy ? "Saving…" : "Change password"}
                </button>
              </div>
            </form>
          </div>
        </main>
      </div>
    </AuthGuard>
  );
}
