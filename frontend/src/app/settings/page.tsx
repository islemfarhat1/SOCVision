"use client";

import { Sidebar } from "@/components/sidebar";
import { Header } from "@/components/header";
import { AuthGuard } from "@/components/auth-guard";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  Settings2,
  Shield,
  Brain,
  Activity,
  Database,
  Wifi,
  Bot,
  Zap,
  CheckCircle2,
  Cpu,
  Lock,
} from "lucide-react";

// ── Shared Subcomponents ──────────────────────────────────────────────────────

function SectionHeader({
  icon: Icon,
  title,
}: {
  icon: React.ElementType;
  title: string;
}) {
  return (
    <div className="flex items-center gap-2 mb-1">
      <Icon className="h-4 w-4 text-primary shrink-0" />
      <span className="text-sm font-semibold text-foreground uppercase tracking-wider">
        {title}
      </span>
    </div>
  );
}

function DetailRow({ label, value, mono = false }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex justify-between items-center py-2.5 border-b border-border/30 last:border-0 text-sm">
      <span className="text-muted-foreground font-medium">{label}</span>
      <span className={`text-foreground font-semibold ${mono ? "font-mono text-xs" : ""}`}>{value}</span>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function SettingsPage() {
  const SCORING_MODEL = [
    { factor: "Type d'attaque", weight: 30 },
    { factor: "Réputation IOC", weight: 30 },
    { factor: "Fréquence", weight: 20 },
    { factor: "Contexte MITRE", weight: 20 },
  ];

  return (
    <AuthGuard>
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header title="Settings — Informations & Configuration Générale" />
        <main className="flex-1 overflow-y-auto p-6 bg-background">
          <div className="max-w-5xl mx-auto space-y-6">

            {/* ── Section 1: Informations Générales ── */}
            <Card className="bg-card/80 border-border/60 shadow-sm">
              <CardHeader className="pb-3 border-b border-border/40">
                <CardTitle className="text-sm">
                  <SectionHeader icon={Shield} title="1. Informations générales" />
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-4 space-y-1">
                <DetailRow label="Plateforme" value="SOCVision" />
                <DetailRow label="Périmètre" value="Analyse, qualification et investigation des alertes de sécurité" />
                <DetailRow label="Données de test" value="CICIDS2017 et alertes simulées" />
                <DetailRow label="Approche décisionnelle" value={
                  <Badge variant="outline" className="bg-primary/10 text-primary border-primary/20 text-xs">
                    Human-in-the-Loop
                  </Badge>
                } />
              </CardContent>
            </Card>

            {/* ── Row 2: Pipeline SOC & Risk Scoring Model ── */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card className="bg-card/80 border-border/60 shadow-sm">
                <CardHeader className="pb-3 border-b border-border/40">
                  <CardTitle className="text-sm">
                    <SectionHeader icon={Settings2} title="2. Pipeline SOC" />
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-4">
                  <DetailRow label="Qualification L1" value="Règles déterministes" />
                  <DetailRow label="Escalade" value="Création d'un ticket de suivi L2" />
                  <DetailRow label="Ticket" value="Identifiant TCK-XXXXXX" mono />
                </CardContent>
              </Card>

              <Card className="bg-card/80 border-border/60 shadow-sm">
                <CardHeader className="pb-3 border-b border-border/40">
                  <CardTitle className="text-sm">
                    <SectionHeader icon={Zap} title="Scoring de Risque Multi-Facteurs" />
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-4 space-y-3">
                  {SCORING_MODEL.map((item) => (
                    <div key={item.factor} className="space-y-1">
                      <div className="flex justify-between text-xs">
                        <span className="text-muted-foreground font-medium">{item.factor}</span>
                        <span className="font-semibold text-foreground font-mono">{item.weight}%</span>
                      </div>
                      <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                        <div
                          className="h-full bg-primary/70 rounded-full"
                          style={{ width: `${item.weight}%` }}
                        />
                      </div>
                    </div>
                  ))}
                  <div className="flex justify-between text-xs pt-2 border-t border-border/40">
                    <span className="font-semibold text-foreground">Total</span>
                    <span className="font-bold text-primary font-mono">100%</span>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* ── Section 3: AI Assistant Configuration ── */}
            <Card className="bg-card/80 border-border/60 shadow-sm">
              <CardHeader className="pb-3 border-b border-border/40">
                <CardTitle className="text-sm">
                  <SectionHeader icon={Brain} title="3. AI Assistant Configuration" />
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-4 space-y-1">
                <DetailRow label="LLM Provider" value="Ollama" />
                <DetailRow label="Deployment" value="Local" />
                <DetailRow label="Model" value="qwen2.5:7b" mono />
                <DetailRow label="Role" value="Alert explanation, contextual summary and recommended actions" />
                <DetailRow label="Automatic Decision" value={
                  <span className="flex items-center gap-1.5 text-xs text-amber-400 font-semibold">
                    <Lock className="h-3.5 w-3.5" />
                    Disabled
                  </span>
                } />
                <DetailRow label="Decision Model" value={
                  <Badge variant="outline" className="bg-primary/10 text-primary border-primary/20 text-xs">
                    Human-in-the-Loop
                  </Badge>
                } />
              </CardContent>
            </Card>

            {/* ── Section 4: Threat Intelligence ── */}
            <Card className="bg-card/80 border-border/60 shadow-sm">
              <CardHeader className="pb-3 border-b border-border/40">
                <CardTitle className="text-sm">
                  <SectionHeader icon={Shield} title="4. Threat Intelligence" />
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-4">
                <div className="flex items-center justify-between py-2.5 border-b border-border/30">
                  <span className="text-sm text-muted-foreground font-medium">VirusTotal</span>
                  <span className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
                    <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                    Configuré
                  </span>
                </div>
                <div className="flex items-center justify-between py-2.5 border-b border-border/30">
                  <span className="text-sm text-muted-foreground font-medium">AbuseIPDB</span>
                  <span className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
                    <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                    Configuré
                  </span>
                </div>
                <div className="flex items-center justify-between py-2.5 border-0">
                  <span className="text-sm text-muted-foreground font-medium">MITRE ATT&CK</span>
                  <span className="flex items-center gap-1.5 text-xs font-semibold text-sky-400">
                    <span className="h-2 w-2 rounded-full bg-sky-400" />
                    Intégré
                  </span>
                </div>
              </CardContent>
            </Card>

            {/* ── Section 5: État de la plateforme ── */}
            <Card className="bg-card/80 border-border/60 shadow-sm">
              <CardHeader className="pb-3 border-b border-border/40">
                <CardTitle className="text-sm">
                  <SectionHeader icon={Activity} title="5. État de la plateforme" />
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-4">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {[
                    { label: "Backend API", icon: Wifi, status: "Actif" },
                    { label: "Base SQLite", icon: Database, status: "Disponible" },
                    { label: "Pipeline de traitement", icon: CheckCircle2, status: "Actif" },
                    { label: "Service IA", icon: Cpu, status: "Actif" },
                  ].map(({ label, icon: Icon, status }) => (
                    <div
                      key={label}
                      className="flex flex-col items-center gap-2 p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/15 text-center shadow-inner"
                    >
                      <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                        <Icon className="h-5 w-5 text-emerald-400 animate-pulse" />
                      </div>
                      <span className="text-xs font-bold text-foreground leading-tight mt-1">{label}</span>
                      <span className="flex items-center gap-1 text-[10px] font-bold text-emerald-400 uppercase tracking-wider">
                        {status}
                      </span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <p className="text-xs text-muted-foreground text-center pt-2">
              Le LLM fonctionne localement comme copilote d'aide à la décision. L'ensemble des contrôles reste supervisé par les analystes SOC.
            </p>
          </div>
        </main>
      </div>
    </AuthGuard>
  );
}