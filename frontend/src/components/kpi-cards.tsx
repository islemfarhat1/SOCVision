"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { AlertTriangle, ShieldAlert, Activity, CheckCircle2, Flame, Shield, Radio } from "lucide-react";
import { fetchDashboard } from "@/lib/api";

type Statistics = {
  total_alerts: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
};

export function KpiCards() {
  const [stats, setStats] = useState<Statistics | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = () => {
      fetchDashboard()
        .then((data) => setStats(data.statistics))
        .catch(() => setError("Failed to load statistics"));
    };

    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, []);

  if (error) {
    return <p className="text-sm text-destructive">{error}</p>;
  }

  if (!stats) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {[1, 2, 3, 4].map((i) => (
          <Card key={i} className="bg-card/60 border-border/50">
            <CardHeader className="pb-2">
              <Skeleton className="h-4 w-24" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-8 w-16" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  // Calculate Threat Level
  const threatLevel =
    stats.critical > 5
      ? { label: "DEFCON 2 — CRITICAL", color: "bg-red-500/20 text-red-400 border-red-500/40 animate-pulse", icon: Flame }
      : stats.critical > 0 || stats.high > 10
      ? { label: "DEFCON 3 — HIGH THREAT", color: "bg-orange-500/20 text-orange-400 border-orange-500/40", icon: AlertTriangle }
      : { label: "DEFCON 4 — ELEVATED", color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/40", icon: Shield };

  const ThreatIcon = threatLevel.icon;

  const cards = [
    {
      label: "Total Pipeline Telemetry",
      value: stats.total_alerts,
      subtext: "Alerts captured from CICIDS & Wazuh",
      icon: Activity,
      color: "text-blue-400",
      glow: "border-blue-500/20 bg-blue-500/5",
    },
    {
      label: "Critical Risk Alerts",
      value: stats.critical,
      subtext: "Immediate response required",
      icon: ShieldAlert,
      color: "text-red-400",
      glow: "border-red-500/30 bg-red-500/10 shadow-lg shadow-red-500/5",
    },
    {
      label: "High Priority Threats",
      value: stats.high,
      subtext: "High severity incidents",
      icon: AlertTriangle,
      color: "text-orange-400",
      glow: "border-orange-500/20 bg-orange-500/5",
    },
    {
      label: "Medium & Low Telemetry",
      value: stats.medium + stats.low,
      subtext: "Monitored background events",
      icon: CheckCircle2,
      color: "text-emerald-400",
      glow: "border-emerald-500/20 bg-emerald-500/5",
    },
  ];

  return (
    <div className="space-y-4">
      {/* SOC Live Threat Status Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-3.5 rounded-lg bg-card/80 backdrop-blur-md border border-border/60 shadow-md gap-3">
        <div className="flex items-center gap-3">
          <div className="relative">
            <span className="relative flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
            </span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-foreground flex items-center gap-1.5">
                <Radio className="h-3.5 w-3.5 text-emerald-400 animate-pulse" />
                SOC Monitoring Active
              </span>
              <span className="text-[10px] text-muted-foreground font-mono">
                • Real-time Stream
              </span>
            </div>
            <p className="text-[11px] text-muted-foreground">
              Automated ingestion & LLM threat analysis online
            </p>
          </div>
        </div>

        <div className={`px-3 py-1.5 rounded-full border text-xs font-bold flex items-center gap-1.5 ${threatLevel.color}`}>
          <ThreatIcon className="h-4 w-4" />
          <span>{threatLevel.label}</span>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {cards.map((card) => {
          const Icon = card.icon;
          return (
            <Card
              key={card.label}
              className={`backdrop-blur-sm transition-all duration-200 hover:border-primary/40 ${card.glow}`}
            >
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
                  {card.label}
                </CardTitle>
                <div className={`p-2 rounded-lg bg-background/50 border border-border/40 ${card.color}`}>
                  <Icon className="h-4 w-4" />
                </div>
              </CardHeader>
              <CardContent className="space-y-1">
                <div className="text-3xl font-extrabold tracking-tight font-mono">{card.value}</div>
                <p className="text-[11px] text-muted-foreground">{card.subtext}</p>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}