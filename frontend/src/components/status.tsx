import { cn } from "@/lib/utils";

/** Incident (ticket) workflow states: a coloured dot + plain label, no pill. */
const TICKET_STATUS: Record<string, { label: string; dot: string }> = {
  OPEN: { label: "Open", dot: "bg-sky-400" },
  IN_PROGRESS: { label: "In progress", dot: "bg-amber-400" },
  CLOSED: { label: "Closed", dot: "bg-emerald-500" },
};

export const TICKET_STATUS_LABELS: Record<string, string> = Object.fromEntries(
  Object.entries(TICKET_STATUS).map(([k, v]) => [k, v.label])
);

export function TicketStatus({ status, className }: { status: string; className?: string }) {
  const conf = TICKET_STATUS[status] ?? { label: status, dot: "bg-muted-foreground" };
  return (
    <span className={cn("inline-flex items-center gap-2 text-sm whitespace-nowrap", className)}>
      <span aria-hidden className={cn("h-2 w-2 rounded-full", conf.dot)} />
      {conf.label}
    </span>
  );
}

/** Configuration state used on the settings page. */
export function StateDot({ ok, label, warn }: { ok: boolean; label: string; warn?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2 text-sm">
      <span aria-hidden className={cn("h-2 w-2 rounded-full", ok ? "bg-emerald-500" : warn ? "bg-amber-400" : "bg-red-500")} />
      {label}
    </span>
  );
}
