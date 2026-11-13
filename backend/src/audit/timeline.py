"""
Chronologie d'une alerte / d'un incident (principe : traçabilité).

Trois sources, triées ensemble :
- recorded      : événements du journal audit_events (actions faites dans l'application)
- record        : rapports d'incident (table incident_reports, auteur et date réels)
- reconstructed : étapes déduites des champs existants (created_at, reviewed_by/at)
                  pour les données antérieures au journal. Elles sont marquées comme
                  telles et ne sont ajoutées que si l'événement enregistré n'existe pas.
"""

from datetime import datetime


def _aware(value):
    """Parse a stored timestamp; naive values (older rows) are server local time."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace(" ", "T").replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.astimezone()


def _event(at, actor, action, source, details=None, alert_id=None, ticket_id=None):
    return {
        "at": at.isoformat(timespec="seconds") if at else None,
        "actor": actor or "system",
        "action": action,
        "source": source,
        "details": details or {},
        "alert_id": alert_id,
        "ticket_id": ticket_id,
    }


def build_timeline(alert: dict | None, recorded: list[dict], ticket: dict | None = None, reports: list[dict] | None = None):
    events = []
    recorded_actions = {e["action"] for e in recorded}

    for e in recorded:
        events.append(_event(_aware(e["occurred_at"]), e["actor"], e["action"], "recorded", e.get("details"),
                             e.get("alert_id"), e.get("ticket_id")))

    if alert:
        alert_id = alert.get("alert_id")
        if "ALERT_RECEIVED" not in recorded_actions:
            events.append(_event(
                _aware(alert.get("created_at")), "system", "ALERT_RECEIVED", "reconstructed",
                {"source": alert.get("source"), "score": alert.get("score"), "severity": alert.get("severity")},
                alert_id=alert_id,
            ))
        status = alert.get("status")
        if status == "ESCALATED" and "ALERT_ESCALATED" not in recorded_actions and alert.get("reviewed_at"):
            events.append(_event(
                _aware(alert.get("reviewed_at")), alert.get("reviewed_by"), "ALERT_ESCALATED", "reconstructed",
                {"assigned_to": alert.get("assigned_to"), "ticket_id": (ticket or {}).get("ticket_id")},
                alert_id=alert_id,
            ))
        if status == "DISMISSED" and "ALERT_DISMISSED" not in recorded_actions and alert.get("reviewed_at"):
            events.append(_event(
                _aware(alert.get("reviewed_at")), alert.get("reviewed_by"), "ALERT_DISMISSED", "reconstructed",
                alert_id=alert_id,
            ))

    for r in reports or []:
        events.append(_event(_aware(r.get("generated_at")), r.get("generated_by"), "REPORT_GENERATED", "record",
                             {"version": r.get("version")}, ticket_id=r.get("ticket_id")))

    # Undated events go last; stable order otherwise.
    events.sort(key=lambda e: (e["at"] is None, _aware(e["at"]) or datetime.max.astimezone()))
    return events
