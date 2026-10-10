"use client";

import { useEffect, useState } from "react";
import { fetchAuthMe } from "@/lib/api";
import { useRouter, usePathname } from "next/navigation";

export type Role = "SOC_L1" | "SOC_L2" | "SOC_MANAGER" | "MANAGER" | "ADMIN";

export type AuthUser = {
  username: string;
  full_name: string;
  role: Role;
};

export function useAuth() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    let isMounted = true;
    
    const loadUser = async () => {
      setIsLoading(true);
      const token = localStorage.getItem("auth_token");
      
      if (!token) {
        if (isMounted) {
          setUser(null);
          setIsLoading(false);
          if (pathname !== "/login") {
            router.push("/login");
          }
        }
        return;
      }
      
      try {
        // Optionnel : vérifier si on a déjà un cache local valide
        const cachedUserStr = localStorage.getItem("auth_user");
        if (cachedUserStr && isMounted) {
          setUser(JSON.parse(cachedUserStr));
        }

        // On rafraîchit avec l'API
        const userData = await fetchAuthMe();
        if (isMounted) {
          setUser(userData);
          localStorage.setItem("auth_user", JSON.stringify(userData));
        }
      } catch (e) {
        // Token invalide ou expiré
        localStorage.removeItem("auth_token");
        localStorage.removeItem("auth_user");
        if (isMounted) {
          setUser(null);
          if (pathname !== "/login") {
            router.push("/login");
          }
        }
      } finally {
        if (isMounted) setIsLoading(false);
      }
    };

    loadUser();

    return () => {
      isMounted = false;
    };
  }, [pathname, router]);

  const logout = () => {
    localStorage.removeItem("auth_token");
    localStorage.removeItem("auth_user");
    setUser(null);
    router.push("/login");
  };

  return { user, isLoading, logout, isAuthenticated: !!user };
}
