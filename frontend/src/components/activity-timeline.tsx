"use client";

import { useEffect, useState } from "react";
import { fetchTimeline, formatTicketId, type TimelineEvent } from "@/lib/api";
import { parseDate, timeAgo } from "@/lib/time";
import { cn } from "@/lib/utils";

const STATUS_WORDS: Record<string, string> = {
  NEW: "new", UNDER_REVIEW: "under review", ESCALATED: "escalated", DISMISSED: "dismissed",
  OPEN: "open", IN_PROGRESS: "in progress", CLOSED: "closed",
};
const word = (v: unknown) => STATUS_WORDS[String(v)] ?? String(v ?? "—");
const SOURCE_NAMES: Record<string, string> = { wazuh: "Wazuh lab", cicids: "CICIDS2017 dataset" };

/** Plain-language description of an audit event. */
function describe(e: TimelineEvent): { title: string; detail?: string; tone?: "warn" | "ok" } {
  const d = e.details ?? {};
  switch (e.action) {
    case "ALERT_RECEIVED":
      return {
        title: "Alert received",
        detail: [d.source && `from ${SOURCE_NAMES[String(d.source)] ?? d.source}`, d.score != null && `score ${d.score}`, d.severity]
          .filter(Boolean).join(" · "),
      };
    case "ALERT_TRIAGE_STARTED":
      return { title: "Triage started" };
    case "ALERT_NOTES_UPDATED":
      return { title: "Triage notes updated", detail: d.length != null ? `${d.length} characters` : undefined };
    case "ALERT_DISMISSED":
      return { title: "Dismissed as false positive" };
    case "ALERT_CLASSIFIED":
      return { title: "Classification changed", detail: `${d.from ?? "—"} → ${d.to ?? "—"}` };
    case "ALERT_STATUS_CHANGED":
      return { title: "Status changed", detail: `${word(d.from)} → ${word(d.to)}` };
    case "ALERT_ESCALATED":
      return {
        title: "Escalated to SOC L2",
        detail: [d.assigned_to && `assigned to ${d.assigned_to}`, (e.ticket_id || d.ticket_id) && formatTicketId(String(e.ticket_id || d.ticket_id))]
          .filter(Boolean).join(" · "),
      };
    case "NOTIFICATION_SENT":
      return { title: "Email notification sent", detail: "n8n workflow", tone: "ok" };
    case "NOTIFICATION_FAILED":
      return { title: "Email notification failed", detail: `n8n${d.error ? ` · ${d.error}` : ""} — notify the analyst another way`, tone: "warn" };
    case "NOTIFICATION_SKIPPED":
      return { title: "No email notification", detail: d.reason ? String(d.reason) : undefined };
    case "TICKET_STATUS_CHANGED":
      return { title: "Incident status changed", detail: `${word(d.from)} → ${word(d.to)}` };
    case "TICKET_REASSIGNED":
      return { title: "Incident reassigned", detail: `${d.from ?? "—"} → ${d.to ?? "—"}` };
    case "TICKET_NOTES_UPDATED":
      return { title: "Investigation notes updated", detail: d.length != null ? `${d.length} characters` : undefined };
    case "REPORT_GENERATED":
      return { title: `Report version ${d.version ?? "?"} generated`, detail: "AI-drafted, to be reviewed" };
    default:
      return { title: e.action.replaceAll("_", " ").toLowerCase() };
  }
}

const SYSTEM_ACTORS = new Set(["system", "wazuh-webhook"]);

/**
 * Who did what, when — from the append-only audit log. Steps that predate the log are
 * reconstructed from the record fields and labelled as such.
 * `refreshKey` changes whenever the page saves something, to reload the list.
 */
export function ActivityTimeline({ kind, id, refreshKey }: {
  kind: "alert" | "ticket";
  id: string;
  refreshKey?: string;
}) {
  const [events, setEvents] = useState<TimelineEvent[] | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetchTimeline(kind, id)
      .then((data) => {
        if (cancelled) return;
        setEvents(data);
        setError(false);
      })
      .catch(() => !cancelled && setError(true));
    return () => {
      cancelled = true;
    };
  }, [kind, id, refreshKey]);

  if (error) return <p className="text-sm text-destructive">Could not load the activity.</p>;
  if (!events) return <p className="text-sm text-muted-foreground">Loading activity…</p>;
  if (events.length === 0) return <p className="text-sm text-muted-foreground">No activity recorded yet.</p>;

  const hasReconstructed = events.some((e) => e.source === "reconstructed");

  return (
    <div className="space-y-3">
      <ol className="relative">
        {events.map((e, i) => {
          const { title, detail, tone } = describe(e);
          const date = parseDate(e.at);
          const last = i === events.length - 1;
          return (
            <li key={`${e.action}-${e.at}-${i}`} className="relative pl-6 pb-4">
              {!last && <span aria-hidden className="absolute left-[5px] top-3 bottom-0 w-px bg-border" />}
              <span
                aria-hidden
                className={cn(
                  "absolute left-0 top-1.5 h-[11px] w-[11px] rounded-full border-2 border-background",
                  tone === "warn" ? "bg-amber-400" : tone === "ok" ? "bg-emerald-500" : e.source === "reconstructed" ? "bg-muted-foreground/50" : "bg-primary"
                )}
              />
              <div className="flex flex-wrap items-baseline gap-x-2 text-sm">
                <span className={cn("font-medium", tone === "warn" && "text-amber-300")}>{title}</span>
                <span className={cn("text-xs", SYSTEM_ACTORS.has(e.actor) ? "text-muted-foreground" : "text-foreground/80")}>
                  {SYSTEM_ACTORS.has(e.actor) ? e.actor : `by ${e.actor}`}
                </span>
              </div>
              {detail && <p className="text-sm text-muted-foreground">{detail}</p>}
              <p className="text-xs text-muted-foreground" title={date?.toLocaleString()}>
                {date ? `${date.toLocaleString()} · ${timeAgo(e.at)}` : "date unknown"}
                {e.source === "reconstructed" && <span className="ml-1.5 italic">· reconstructed</span>}
              </p>
            </li>
          );
        })}
      </ol>
      {hasReconstructed && (
        <p className="text-xs text-muted-foreground border-t border-border pt-3">
          “Reconstructed” steps predate the audit log: they are derived from the alert’s recorded fields
          (creation date, reviewer and review date). Every action taken in SOCVision is now logged.
        </p>
      )}
    </div>
  );
}
