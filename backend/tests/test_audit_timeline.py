"""Journal d'audit et chronologie (principe : traçabilité). Base jetable (voir conftest.py)."""

import uuid

from fastapi.testclient import TestClient

from src.api.main import app
from src.api.routers import alerts as alerts_router
from src.audit.timeline import build_timeline
from src.dependencies import get_current_user

client = TestClient(app)
db = alerts_router.db


def as_user(username, role):
    app.dependency_overrides[get_current_user] = lambda: {"username": username, "role": role}


def new_alert(**overrides):
    alert_id = f"ALRT-{uuid.uuid4().hex[:6].upper()}"
    db.insert_alert({
        "alert_id": alert_id, "created_at": "2026-11-13 10:00:00", "severity": "CRITICAL",
        "attack_type": "SSH Bruteforce (Hydra)", "score": 80, "source_ip": "192.168.56.20",
        "destination_ip": "192.168.56.10", "incident_title": "SSH Brute Force Attack Detected",
        "source": "wazuh", **overrides,
    })
    return alert_id


def actions(events):
    return [e["action"] for e in events]


def test_alert_actions_are_recorded_with_actor_and_changes():
    alert_id = new_alert()
    as_user("ahmed.salem", "SOC_L1")
    try:
        client.patch(f"/api/alerts/{alert_id}", json={"status": "UNDER_REVIEW"})
        client.patch(f"/api/alerts/{alert_id}", json={"investigation_notes": "Hydra from the lab attacker VM"})
        client.patch(f"/api/alerts/{alert_id}", json={"investigation_notes": "Hydra from the lab attacker VM"})  # unchanged
        client.patch(f"/api/alerts/{alert_id}", json={"status": "DISMISSED"})
        timeline = client.get(f"/api/alerts/{alert_id}/timeline").json()
    finally:
        app.dependency_overrides.clear()

    recorded = [e for e in timeline if e["source"] == "recorded"]
    assert actions(recorded) == ["ALERT_TRIAGE_STARTED", "ALERT_NOTES_UPDATED", "ALERT_DISMISSED"]
    assert all(e["actor"] == "ahmed.salem" for e in recorded)
    assert recorded[0]["details"] == {"from": "NEW", "to": "UNDER_REVIEW"}
    # alert inserted directly (no webhook event): its reception is reconstructed from created_at
    assert timeline[0]["action"] == "ALERT_RECEIVED" and timeline[0]["source"] == "reconstructed"


def test_escalation_records_ticket_and_notification_outcome(monkeypatch):
    alert_id = new_alert()
    monkeypatch.setattr(alerts_router, "notify_n8n", lambda alert: {"status": "failed", "error": "ConnectionError"})
    as_user("ahmed.salem", "SOC_L1")
    try:
        ticket_id = client.post(f"/api/alerts/{alert_id}/promote", json={"assigned_to": "ala.mabrouk"}).json()["ticket_id"]
        as_user("ala.mabrouk", "SOC_L2")
        client.patch(f"/api/tickets/{ticket_id}", json={"status": "CLOSED"})
        client.patch(f"/api/tickets/{ticket_id}", json={"comments": "Lab attack confirmed, credentials rotated."})
        timeline = client.get(f"/api/tickets/{ticket_id}/timeline").json()
    finally:
        app.dependency_overrides.clear()

    assert actions(timeline) == [
        "ALERT_RECEIVED", "ALERT_ESCALATED", "NOTIFICATION_FAILED", "TICKET_STATUS_CHANGED", "TICKET_NOTES_UPDATED",
    ]
    escalation = timeline[1]
    assert escalation["actor"] == "ahmed.salem" and escalation["ticket_id"] == ticket_id
    assert escalation["details"] == {"assigned_to": "ala.mabrouk"}
    assert timeline[2]["details"] == {"channel": "n8n", "error": "ConnectionError"}
    assert timeline[3]["details"] == {"from": "IN_PROGRESS", "to": "CLOSED"}


def test_timeline_requires_authentication():
    assert client.get("/api/alerts/ALRT-000000/timeline").status_code == 401


def test_legacy_escalation_is_reconstructed_once():
    alert = {"alert_id": "A", "created_at": "2026-08-13 14:39:55", "status": "ESCALATED",
             "reviewed_by": "ahmed.salem", "reviewed_at": "2026-08-13T14:50:50", "assigned_to": "ala.mabrouk"}
    reports = [{"ticket_id": "INC-1", "generated_by": "ala.mabrouk", "generated_at": "2026-08-27 11:16:56", "version": 2},
               {"ticket_id": "INC-1", "generated_by": "ala.mabrouk", "generated_at": "2026-08-13 14:53:18", "version": 1}]
    events = build_timeline(alert, [], ticket={"ticket_id": "INC-1"}, reports=reports)
    assert actions(events) == ["ALERT_RECEIVED", "ALERT_ESCALATED", "REPORT_GENERATED", "REPORT_GENERATED"]
    assert [e["source"] for e in events] == ["reconstructed", "reconstructed", "record", "record"]
    assert [e["details"].get("version") for e in events[2:]] == [1, 2]

    # once the escalation is recorded, it is not reconstructed a second time
    recorded = [{"occurred_at": "2026-08-13T13:50:50+00:00", "actor": "ahmed.salem", "action": "ALERT_ESCALATED",
                 "alert_id": "A", "ticket_id": "INC-1", "details": {}}]
    assert actions(build_timeline(alert, recorded)).count("ALERT_ESCALATED") == 1


def test_naive_and_utc_timestamps_sort_together():
    recorded = [{"occurred_at": "2030-01-01T00:00:00+00:00", "actor": "x", "action": "LATE", "details": {}}]
    events = build_timeline({"alert_id": "A", "created_at": "2026-01-01 08:00:00", "status": "NEW"}, recorded)
    assert actions(events) == ["ALERT_RECEIVED", "LATE"]
