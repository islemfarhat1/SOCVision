"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Legend,
} from "recharts";
import { fetchDashboard } from "@/lib/api";
import { PieChart as PieIcon, BarChart3, ShieldCheck } from "lucide-react";

type DashboardData = {
  statistics: {
    total_alerts: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    by_attack_type: Record<string, number>;
  };
};

const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#10b981",
};

// Custom dark tooltip
function CustomTooltip({ active, payload, label }: any) {
  if (active && payload && payload.length) {
    return (
      <div className="bg-slate-900/95 border border-slate-700/80 p-2.5 rounded-lg shadow-xl text-xs text-slate-100 backdrop-blur-md">
        <p className="font-semibold">{label || payload[0].name}</p>
        <p className="text-primary font-mono font-bold mt-1">
          {payload[0].value} alerts ({Math.round((payload[0].value / (payload[0].payload?.total || 1)) * 100) || 0}%)
        </p>
      </div>
    );
  }
  return null;
}

export function Charts({ mode = "all" }: { mode?: "all" | "attacks" | "severity" }) {
  const [data, setData] = useState<DashboardData | null>(null);

  useEffect(() => {
    const load = () => {
      fetchDashboard().then(setData).catch(() => {});
    };

    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, []);

  if (!data) return null;

  const total = data.statistics.total_alerts || 1;

  const severityData = [
    { name: "Critical", value: data.statistics.critical, total },
    { name: "High", value: data.statistics.high, total },
    { name: "Medium", value: data.statistics.medium, total },
    { name: "Low", value: data.statistics.low, total },
  ];

  const attackData = Object.entries(data.statistics.by_attack_type).map(
    ([name, value]) => ({ name, value, total })
  );

  const showSeverity = mode === "all" || mode === "severity";
  const showAttacks = mode === "all" || mode === "attacks";

  return (
    <div className={`grid grid-cols-1 ${showSeverity && showAttacks ? "lg:grid-cols-2" : "grid-cols-1"} gap-4`}>
      {showSeverity && (
        <Card className="bg-card/80 backdrop-blur-sm border-border/60 shadow-lg">
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center justify-between">
              <span className="flex items-center gap-2">
                <PieIcon className="h-4 w-4 text-primary" />
                Severity Breakdown
              </span>
              <span className="text-xs text-muted-foreground font-mono font-normal">
                {total} total
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            <div className="h-[280px] relative">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={65}
                    outerRadius={95}
                    paddingAngle={4}
                    strokeWidth={1}
                    stroke="#1e293b"
                  >
                    {severityData.map((entry) => (
                      <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name]} />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                  <Legend
                    verticalAlign="bottom"
                    height={36}
                    formatter={(value) => (
                      <span className="text-xs font-medium text-slate-300 mx-1">{value}</span>
                    )}
                  />
                </PieChart>
              </ResponsiveContainer>
              {/* Donut Center text */}
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none pb-8">
                <span className="text-2xl font-extrabold font-mono text-foreground">{total}</span>
                <span className="text-[10px] text-muted-foreground uppercase tracking-widest font-semibold">
                  Alerts
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {showAttacks && (
        <Card className="bg-card/80 backdrop-blur-sm border-border/60 shadow-lg">
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-blue-400" />
              Attack Vector Distribution
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={attackData} layout="vertical" margin={{ left: 100, right: 20 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#334155" opacity={0.4} />
                <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11, fill: "#94a3b8" }} />
                <YAxis
                  type="category"
                  dataKey="name"
                  width={100}
                  interval={0}
                  tick={{ fontSize: 11, fill: "#cbd5e1" }}
                />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="value" fill="#3b82f6" radius={[0, 6, 6, 0]} barSize={18} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      )}
    </div>
  );
}