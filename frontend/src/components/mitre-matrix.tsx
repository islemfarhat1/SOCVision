"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ShieldAlert, Terminal, Lock, Cpu, Globe, Crosshair } from "lucide-react";

type Tactic = {
  id: string;
  name: string;
  count: number;
  icon: typeof ShieldAlert;
  description: string;
  techniques: string[];
};

const TACTICS: Tactic[] = [
  {
    id: "TA0043",
    name: "Reconnaissance",
    count: 42,
    icon: Crosshair,
    description: "Gathering information to plan future adversary operations",
    techniques: ["Port Scanning (T1046)", "Active Scanning (T1595)"],
  },
  {
    id: "TA0001",
    name: "Initial Access",
    count: 28,
    icon: Globe,
    description: "Trying to get into your network through valid credentials or exploits",
    techniques: ["Exploit Public App (T1190)", "Spearphishing (T1566)"],
  },
  {
    id: "TA0002",
    name: "Execution",
    count: 19,
    icon: Terminal,
    description: "Running malicious code on local or remote systems",
    techniques: ["Command Interpreter (T1059)", "PowerShell (T1059.001)"],
  },
  {
    id: "TA0006",
    name: "Credential Access",
    count: 35,
    icon: Lock,
    description: "Stealing credentials like account names and passwords",
    techniques: ["Brute Force (T1110)", "Password Guessing (T1110.001)"],
  },
  {
    id: "TA0040",
    name: "Impact / DoS",
    count: 64,
    icon: Cpu,
    description: "Manipulating, interrupting, or destroying systems and data",
    techniques: ["Network DoS (T1498)", "Endpoint DoS (T1499)"],
  },
];

export function MitreMatrix() {
  return (
    <Card className="bg-card/80 backdrop-blur-sm border-border/60 shadow-lg">
      <CardHeader className="pb-3">
        <CardTitle className="text-base font-semibold flex items-center gap-2">
          <Crosshair className="h-5 w-5 text-amber-400" />
          MITRE ATT&CK® Threat Tactics Coverage
        </CardTitle>
        <p className="text-xs text-muted-foreground">
          Distribution of adversary techniques detected across active pipeline telemetry
        </p>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {TACTICS.map((t) => {
            const Icon = t.icon;
            return (
              <div
                key={t.id}
                className="p-3 rounded-lg bg-accent/30 border border-border/50 hover:border-primary/40 transition-all flex flex-col justify-between gap-3"
              >
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[10px] text-muted-foreground">{t.id}</span>
                    <Badge variant="outline" className="bg-primary/10 text-primary border-primary/20 text-[10px]">
                      {t.count} alerts
                    </Badge>
                  </div>
                  <div className="flex items-center gap-2">
                    <Icon className="h-4 w-4 text-primary shrink-0" />
                    <h4 className="font-semibold text-xs truncate">{t.name}</h4>
                  </div>
                  <p className="text-[11px] text-muted-foreground line-clamp-2 leading-tight">
                    {t.description}
                  </p>
                </div>

                <div className="pt-2 border-t border-border/40 space-y-1">
                  <span className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">
                    Top Techniques
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {t.techniques.map((tech) => (
                      <span
                        key={tech}
                        className="text-[10px] bg-background/80 px-1.5 py-0.5 rounded text-foreground/90 border border-border/40 font-mono"
                      >
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
