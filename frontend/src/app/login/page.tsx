"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Shield, User, Lock, ArrowRight, AlertCircle } from "lucide-react";
import { login } from "@/lib/api";
import { useAuth } from "@/lib/use-auth";

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
      setError("Please enter both username and password.");
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
    } catch (err: any) {
      setError("Invalid credentials. Please check your username and password.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full h-full min-h-screen flex-1 flex items-center justify-center bg-background relative overflow-hidden p-4 select-none">
      {/* Background Cyber Ambient Lights */}
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-primary/20 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-blue-600/15 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-purple-500/5 rounded-full blur-[160px] pointer-events-none" />

      {/* Main Login Box */}
      <Card className="w-full max-w-md bg-card/80 backdrop-blur-xl border-border/80 shadow-2xl relative z-10 overflow-hidden border">
        {/* Glowing Top Accent Bar */}
        <div className="h-1.5 w-full bg-gradient-to-r from-blue-600 via-primary to-purple-600" />

        <CardHeader className="flex flex-col items-center gap-3 pt-8 pb-4 text-center">
          {/* Logo Badge */}
          <div className="p-3.5 rounded-2xl bg-primary/10 border border-primary/20 shadow-inner flex items-center justify-center">
            <Shield className="h-9 w-9 text-primary animate-pulse" />
          </div>
          <div>
            <CardTitle className="text-2xl font-bold tracking-tight text-foreground">
              SOCVision
            </CardTitle>
            <p className="text-xs text-muted-foreground mt-1">
              Autonomous Threat Intelligence & Triage Portal
            </p>
          </div>
        </CardHeader>

        <CardContent className="px-8 pb-8 space-y-6">
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Username Input */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground flex items-center gap-1.5">
                <User className="h-3.5 w-3.5 text-primary" /> Username
              </label>
              <div className="relative">
                <Input
                  type="text"
                  placeholder="Enter your username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoFocus
                  className="h-11 pl-3 pr-3 bg-background/60 border-border/80 focus:border-primary transition-all text-sm"
                />
              </div>
            </div>

            {/* Password Input */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground flex items-center gap-1.5">
                <Lock className="h-3.5 w-3.5 text-primary" /> Password
              </label>
              <div className="relative">
                <Input
                  type="password"
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="h-11 pl-3 pr-3 bg-background/60 border-border/80 focus:border-primary transition-all text-sm font-mono"
                />
              </div>
            </div>

            {/* Error Display */}
            {error && (
              <div className="p-3 rounded-md bg-destructive/15 border border-destructive/30 text-xs text-destructive flex items-center gap-2 animate-in fade-in slide-in-from-top-1">
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full h-11 mt-2 rounded-md bg-primary hover:bg-primary/90 text-primary-foreground text-sm font-semibold shadow-lg shadow-primary/20 transition-all duration-200 active:scale-[0.99] disabled:opacity-50 flex items-center justify-center gap-2 group cursor-pointer"
            >
              {loading ? (
                <>
                  <div className="h-4 w-4 border-2 border-primary-foreground border-t-transparent rounded-full animate-spin" />
                  <span>Authenticating...</span>
                </>
              ) : (
                <>
                  <span>Sign In to Terminal</span>
                  <ArrowRight className="h-4 w-4 group-hover:translate-x-0.5 transition-transform" />
                </>
              )}
            </button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}