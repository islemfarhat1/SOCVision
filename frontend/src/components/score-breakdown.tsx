import { AlertTriangle } from "lucide-react";
import { SeverityBadge } from "@/components/severity";
import { cn } from "@/lib/utils";

export type ScoreFactor = {
  key: "attack_type" | "frequency" | "ip_reputation" | "mitre";
  label: string;
  points: number;
  detail: string;
  covered?: boolean;
};

export type ScoreBreakdownData = {
  origin: "stored" | "recomputed";
  factors: ScoreFactor[];
  total: number;
  priority: string;
  threshold: { priority: string; min: number };
  next_threshold: { priority: string; min: number } | null;
  stored_score: number | null;
  matches_stored_score: boolean;
  scale: number[];
};

const SEGMENT = ["bg-primary", "bg-primary/70", "bg-primary/50", "bg-primary/35"];

/**
 * Deterministic explanation of the risk score, straight from the rule engine.
 * Kept visually separate from the AI analysis: the engine decides, the AI explains.
 */
export function ScoreBreakdown({ data, storedSeverity }: { data: ScoreBreakdownData; storedSeverity?: string }) {
  const olderRules = !data.matches_stored_score;
  const shownScore = olderRules && data.stored_score != null ? data.stored_score : data.total;
  const shownPriority = olderRules && storedSeverity ? storedSeverity : data.priority;
  const width = (pts: number) => `${Math.min(100, Math.max(0, pts))}%`;

  return (
    <section className="rounded-lg border border-border bg-card" aria-labelledby="score-title">
      <header className="flex flex-wrap items-start justify-between gap-3 px-5 py-3 border-b border-border">
        <div>
          <h2 id="score-title" className="text-sm font-semibold">Risk score</h2>
          <p className="text-xs text-muted-foreground">Rule engine · deterministic, not decided by the AI</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-2xl font-semibold tabular-nums leading-none">{shownScore}</span>
          <span className="text-sm text-muted-foreground">/100</span>
          <SeverityBadge severity={shownPriority} />
        </div>
      </header>

      <div className="p-5 space-y-5">
        {olderRules && (
          <div role="note" className="flex gap-3 rounded-md border border-amber-500/35 bg-amber-500/10 px-3 py-2.5 text-sm text-amber-100">
            <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5 text-amber-400" aria-hidden />
            <p>
              Scored with an earlier version of the rules (stored score {data.stored_score}). With the current rules
              this alert would score <strong>{data.total}</strong> ({data.priority}). The breakdown below uses the current rules.
            </p>
          </div>
        )}

        {/* Stacked bar: how each factor fills the 0–100 scale */}
        <div>
          <div className="relative h-2.5 rounded-sm bg-muted overflow-hidden flex" role="img"
               aria-label={data.factors.map((f) => `${f.label} ${f.points} points`).join(", ")}>
            {data.factors.map((f, i) =>
              f.points > 0 ? <div key={f.key} className={SEGMENT[i]} style={{ width: width(f.points) }} /> : null
            )}
          </div>
          <div className="relative h-4 mt-1 text-[11px] text-muted-foreground tabular-nums" aria-hidden>
            <span className="absolute left-0">0</span>
            {data.scale.map((v) => (
              <span key={v} className="absolute -translate-x-1/2" style={{ left: `${v}%` }}>{v}</span>
            ))}
            <span className="absolute right-0">100</span>
          </div>
        </div>

        <ol className="divide-y divide-border border-y border-border">
          {data.factors.map((f, i) => (
            <li key={f.key} className="flex items-start gap-3 py-2.5">
              <span aria-hidden className={cn("mt-1.5 h-2.5 w-2.5 rounded-sm shrink-0", f.points > 0 ? SEGMENT[i] : "bg-muted")} />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium">{f.label}</p>
                <p className={cn("text-sm", f.covered === false ? "text-amber-300" : "text-muted-foreground")}>{f.detail}</p>
              </div>
              <span className={cn("text-sm tabular-nums font-semibold", f.points === 0 && "text-muted-foreground font-normal")}>
                +{f.points}
              </span>
            </li>
          ))}
          <li className="flex items-center justify-between py-2.5 text-sm">
            <span className="font-medium">{olderRules ? "Total with the current rules" : "Total"}</span>
            <span className="tabular-nums font-semibold">{data.total}</span>
          </li>
        </ol>

        <p className="text-sm text-muted-foreground">
          {data.threshold.min > 0 ? (
            <>{data.total} ≥ {data.threshold.min} → <strong className="text-foreground">{data.priority}</strong></>
          ) : (
            <>{data.total} → <strong className="text-foreground">{data.priority}</strong>{data.next_threshold && <> (below {data.next_threshold.min})</>}</>
          )}
          {data.next_threshold && (
            <> · {data.next_threshold.priority} starts at {data.next_threshold.min} ({data.next_threshold.min - data.total} more points)</>
          )}
          <span className="block text-xs mt-1">
            {data.origin === "stored"
              ? "Points recorded by the engine when the alert was scored."
              : "Recomputed by the engine from the alert data."}
          </span>
        </p>
      </div>
    </section>
  );
}
