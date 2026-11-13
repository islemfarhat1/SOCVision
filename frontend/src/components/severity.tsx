import { cn } from "@/lib/utils";

/**
 * Severity colours used everywhere in the console.
 * LOW is a neutral blue-grey, not green: in a SOC, green means "healthy / resolved",
 * and a low-severity alert is still an alert to look at.
 */
export const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-300 border-red-500/40",
  HIGH: "bg-orange-500/15 text-orange-300 border-orange-500/40",
  MEDIUM: "bg-amber-400/12 text-amber-200 border-amber-400/35",
  LOW: "bg-slate-400/12 text-slate-300 border-slate-400/35",
};

/** Solid colour of each severity, for bars and markers. */
export const SEVERITY_FILL: Record<string, string> = {
  CRITICAL: "bg-red-500",
  HIGH: "bg-orange-500",
  MEDIUM: "bg-amber-400",
  LOW: "bg-slate-400",
};

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-sm border px-1.5 py-px text-[11px] font-semibold uppercase tracking-wide leading-5",
        SEVERITY_STYLES[severity] ?? "bg-muted text-muted-foreground border-border",
        className
      )}
    >
      {severity}
    </span>
  );
}
