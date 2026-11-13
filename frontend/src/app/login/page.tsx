"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Input } from "@/components/ui/input";
import { AlertCircle, Loader2 } from "lucide-react";
import { login } from "@/lib/api";
import { useAuth } from "@/lib/use-auth";
import { BrandMark, Wordmark } from "@/components/brand";

const CAPABILITIES = [
  ["Ingestion", "Wazuh lab alerts and the CICIDS2017 dataset, normalised into one queue."],
  ["Prioritisation", "Deterministic risk score, IP reputation and MITRE ATT&CK mapping."],
  ["Analyst decision", "AI explanations assist triage; escalation and closure stay with the analyst."],
];

export default function LoginPage() {
  const router = useRouter();
  const { user } = useAuth();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (user) {
      router.push("/");
    }
  }, [user, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) {
      setError("Enter your username and password.");
      return;
    }

    setError(null);
    setLoading(true);

    try {
      const data = await login(username, password);
      localStorage.setItem("auth_token", data.access_token);
      localStorage.setItem("auth_user", JSON.stringify({
        full_name: data.full_name,
        role: data.role,
        username: data.username || username,
      }));
      window.location.href = "/"; // Force reload to apply auth state
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex-1 min-h-screen grid lg:grid-cols-[minmax(0,1fr)_480px] bg-background">
      {/* ── Product panel ── */}
      <section className="hidden lg:flex flex-col justify-between border-r border-border bg-sidebar px-14 py-12">
        <div className="flex items-center gap-2.5">
          <BrandMark />
          <Wordmark className="text-lg" />
        </div>

        <div className="max-w-lg space-y-10">
          <div className="space-y-3">
            <p className="text-xs font-medium uppercase tracking-wider text-primary">Security operations</p>
            <h1 className="text-3xl font-semibold leading-tight tracking-tight">
              Alert triage and incident investigation for SOC analysts.
            </h1>
          </div>
          <dl className="space-y-5">
            {CAPABILITIES.map(([title, text]) => (
              <div key={title} className="grid grid-cols-[140px_1fr] gap-4 border-t border-border pt-4">
                <dt className="text-sm font-medium">{title}</dt>
                <dd className="text-sm text-muted-foreground leading-relaxed">{text}</dd>
              </div>
            ))}
          </dl>
        </div>

        <p className="text-xs text-muted-foreground">
          Lab prototype · ENICarthage
        </p>
      </section>

      {/* ── Sign-in form ── */}
      <main className="flex flex-col justify-center px-6 sm:px-12 py-12">
        <div className="w-full max-w-sm mx-auto space-y-8">
          <div className="flex items-center gap-2.5 lg:hidden">
            <BrandMark />
            <Wordmark className="text-lg" />
          </div>

          <div className="space-y-1.5">
            <h2 className="text-xl font-semibold">Sign in</h2>
            <p className="text-sm text-muted-foreground">Use your SOC analyst account.</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4" noValidate>
            <div className="space-y-1.5">
              <label htmlFor="username" className="text-sm font-medium">Username</label>
              <Input
                id="username"
                type="text"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoFocus
                className="h-10 text-sm"
              />
            </div>

            <div className="space-y-1.5">
              <label htmlFor="password" className="text-sm font-medium">Password</label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="h-10 text-sm"
              />
            </div>

            {error && (
              <div role="alert" className="flex items-start gap-2 p-3 rounded-md border border-destructive/40 bg-destructive/10 text-sm text-red-300">
                <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full h-10 rounded-md bg-primary text-primary-foreground text-sm font-semibold hover:bg-primary/90 disabled:opacity-60 inline-flex items-center justify-center gap-2"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              {loading ? "Signing in…" : "Sign in"}
            </button>
          </form>

          <p className="text-xs text-muted-foreground border-t border-border pt-4">
            Authorized personnel only. Repeated failed attempts temporarily lock the account.
          </p>
        </div>
      </main>
    </div>
  );
}
