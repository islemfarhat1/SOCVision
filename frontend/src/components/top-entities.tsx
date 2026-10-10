"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { fetchTopEntities } from "@/lib/api";
import { Shield, Target, ExternalLink, ArrowRight } from "lucide-react";

type Entity = { ip: string; count: number };
type TopEntities = { top_attackers: Entity[]; top_victims: Entity[] };

function EntityBar({
  entity,
  maxCount,
  type,
}: {
  entity: Entity;
  maxCount: number;
  type: "attacker" | "victim";
}) {
  const pct = Math.max(10, Math.round((entity.count / maxCount) * 100));
  const isAttacker = type === "attacker";

  return (
    <div className="space-y-1.5 p-2 rounded bg-accent/20 hover:bg-accent/40 transition-colors">
      <div className="flex items-center justify-between text-xs">
        <div className="flex items-center gap-2">
          <span className="font-mono font-semibold text-foreground">{entity.ip}</span>
          <Link
            href={`/alerts?search=${encodeURIComponent(entity.ip)}`}
            className="text-[10px] text-primary opacity-70 hover:opacity-100 flex items-center gap-0.5"
            title="Filter alerts by this IP"
          >
            filter <ExternalLink className="h-2.5 w-2.5" />
          </Link>
        </div>
        <span className="font-mono text-xs font-bold text-muted-foreground">
          {entity.count} {entity.count === 1 ? "alert" : "alerts"}
        </span>
      </div>
      <div className="h-2 rounded-full bg-muted/60 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ${
            isAttacker
              ? "bg-gradient-to-r from-red-500 to-orange-500 shadow-sm shadow-red-500/50"
              : "bg-gradient-to-r from-sky-500 to-indigo-500"
          }`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

export function TopEntities() {
  const [data, setData] = useState<TopEntities | null>(null);

  useEffect(() => {
    const load = () => fetchTopEntities().then(setData).catch(() => {});
    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, []);

  if (!data) return null;

  const maxAttacker = Math.max(...data.top_attackers.map((e) => e.count), 1);
  const maxVictim = Math.max(...data.top_victims.map((e) => e.count), 1);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <Card className="bg-card/80 backdrop-blur-sm border-border/60 shadow-lg">
        <CardHeader className="pb-3">
          <CardTitle className="text-base font-semibold flex items-center gap-2">
            <Shield className="h-5 w-5 text-red-400" />
            Top Attacker IPs (External Threats)
          </CardTitle>
          <p className="text-xs text-muted-foreground">
            Hostile IP addresses generating the highest alert volume
          </p>
        </CardHeader>
        <CardContent className="space-y-2">
          {data.top_attackers.length === 0 ? (
            <p className="text-xs text-muted-foreground">No attacker data available</p>
          ) : (
            data.top_attackers.map((e) => (
              <EntityBar key={e.ip} entity={e} maxCount={maxAttacker} type="attacker" />
            ))
          )}
        </CardContent>
      </Card>

      <Card className="bg-card/80 backdrop-blur-sm border-border/60 shadow-lg">
        <CardHeader className="pb-3">
          <CardTitle className="text-base font-semibold flex items-center gap-2">
            <Target className="h-5 w-5 text-indigo-400" />
            Top Target Assets (Internal Victims)
          </CardTitle>
          <p className="text-xs text-muted-foreground">
            Internal servers & endpoints receiving the most attacks
          </p>
        </CardHeader>
        <CardContent className="space-y-2">
          {data.top_victims.length === 0 ? (
            <p className="text-xs text-muted-foreground">No target asset data available</p>
          ) : (
            data.top_victims.map((e) => (
              <EntityBar key={e.ip} entity={e} maxCount={maxVictim} type="victim" />
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}