"use client";

import { useAuth, Role } from "@/lib/use-auth";
import { Shield } from "lucide-react";
import Link from "next/link";

type AuthGuardProps = {
  children: React.ReactNode;
  allowedRoles?: Role[];
  redirectTo?: string;
};

export function AuthGuard({ children, allowedRoles, redirectTo = "/" }: AuthGuardProps) {
  const { user, isLoading, isAuthenticated } = useAuth();

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          <span className="text-sm text-muted-foreground">Loading...</span>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return null;
  }

  // Role-based access check
  if (allowedRoles && user && !allowedRoles.includes(user.role)) {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-4 text-center max-w-md p-8">
          <div className="p-4 rounded-full bg-red-500/10 border border-red-500/30">
            <Shield className="h-10 w-10 text-red-400" />
          </div>
          <h1 className="text-2xl font-bold text-foreground">403 — Access Denied</h1>
          <p className="text-sm text-muted-foreground">
            This area is restricted. Your role <span className="font-semibold text-foreground">({user.role.replace("_", " ")})</span> does not have permission to access this page.
          </p>
          <Link
            href={redirectTo}
            className="mt-2 px-4 py-2 text-xs font-semibold rounded-md bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
          >
            ← Back to Dashboard
          </Link>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
