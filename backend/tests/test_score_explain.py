"""Explication déterministe du score (rule engine), affichée à l'analyste."""

import json

import pandas as pd
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.routers import alerts as alerts_router
from src.database.database_manager import DatabaseManager
from src.dependencies import get_current_user
from src.scoring.explain import explain_score

PRIVATE_REP = json.dumps({"reputation": "Internal / Private IP", "score": 0, "assessment_status": "not_applicable",
                          "sources": {"External reputation": "Not applicable"}})


def nikto_alert(**overrides):
    alert = {
        "alert_id": "ALRT-1", "source": "wazuh", "attack_type": "Web Vulnerability Scan (Nikto)", "score": 90,
        "frequency_count": 10, "mitre": "T1595.002", "ip_reputation": PRIVATE_REP, "source_ip": "192.168.56.20",
        "score_details": None,
    }
    alert.update(overrides)
    return alert


def points(explanation):
    return {f["key"]: f["points"] for f in explanation["factors"]}


def test_recomputed_breakdown_matches_stored_score():
    e = explain_score(nikto_alert())
    assert e["origin"] == "recomputed"
    assert points(e) == {"attack_type": 60, "frequency": 15, "ip_reputation": 0, "mitre": 15}
    assert e["total"] == 90 and e["priority"] == "CRITICAL"
    assert e["threshold"] == {"priority": "CRITICAL", "min": 70}
    assert e["next_threshold"] is None
    assert e["scale"] == [20, 40, 70]
    assert e["matches_stored_score"] is True
    assert "≥ 8 → +15" in e["factors"][1]["detail"]
    assert "private" in e["factors"][2]["detail"]

    legacy_private = json.dumps({"reputation": "Internal / Private IP", "score": 0, "isInternal": True})
    assert "not checked externally" in explain_score(nikto_alert(ip_reputation=legacy_private))["factors"][2]["detail"]


def test_stored_details_are_the_source_of_truth():
    stored = json.dumps({"attack_type": 45, "frequency": 15, "ip_reputation": 0, "mitre": 15})
    e = explain_score(nikto_alert(score=75, score_details=stored))
    assert e["origin"] == "stored"
    assert points(e)["attack_type"] == 45
    assert e["total"] == 75 and e["matches_stored_score"] is True


def test_alert_scored_with_older_rules_is_flagged():
    e = explain_score(nikto_alert(score=50))
    assert e["matches_stored_score"] is False
    assert e["stored_score"] == 50 and e["total"] == 90


def test_attack_type_missing_from_rules_is_explicit():
    e = explain_score(nikto_alert(attack_type="Web Attack – Sql Injection", source="cicids",
                                  frequency_count=21, mitre=None, score=0))
    first = e["factors"][0]
    assert first["covered"] is False and first["points"] == 0
    assert "not covered by the scoring rules" in first["detail"]
    assert e["priority"] == "LOW"
    assert e["next_threshold"] == {"priority": "MEDIUM", "min": 20}


def test_failed_lookup_and_python_repr_reputation():
    not_checked = json.dumps({"reputation": "not_checked", "assessment_status": "not_checked", "sources": {}})
    e = explain_score(nikto_alert(ip_reputation=not_checked, source_ip="8.8.8.8"))
    assert "not checked" in e["factors"][2]["detail"] and e["factors"][2]["points"] == 0

    legacy = "{'reputation': 'malicious', 'score': 100, 'sources': {'VirusTotal': None}}"
    e = explain_score(nikto_alert(ip_reputation=legacy, source_ip="8.8.8.8", score=110))
    assert e["factors"][2]["points"] == 20 and e["factors"][2]["detail"] == "malicious"


def test_score_details_round_trip_in_database(tmp_path):
    db = DatabaseManager(db_path=str(tmp_path / "soc.db"))
    details = {"attack_type": 60, "frequency": 15, "ip_reputation": 0, "mitre": 15}
    db.insert_alert({
        "alert_id": "ALRT-RT", "created_at": "2026-11-13 10:00:00", "severity": "CRITICAL",
        "attack_type": "Web Vulnerability Scan (Nikto)", "score": 90, "source_ip": "192.168.56.20",
        "destination_ip": "192.168.56.10", "score_details": json.dumps(details),
    })
    row = db.get_alerts_dataframe().iloc[0].to_dict()
    assert json.loads(row["score_details"]) == details
    assert explain_score(row)["origin"] == "stored"


def test_alert_detail_endpoint_returns_breakdown(monkeypatch):
    monkeypatch.setattr(alerts_router.db, "get_alerts_dataframe", lambda: pd.DataFrame([{
        **nikto_alert(), "id": 1, "created_at": "2026-11-13 10:00:00", "severity": "CRITICAL",
        "destination_ip": "192.168.56.10", "status": "NEW",
    }]))
    app.dependency_overrides[get_current_user] = lambda: {"username": "l1", "role": "SOC_L1"}
    try:
        r = TestClient(app).get("/api/alerts/ALRT-1")
    finally:
        app.dependency_overrides.clear()
    assert r.status_code == 200
    breakdown = r.json()["score_breakdown"]
    assert breakdown["total"] == 90 and len(breakdown["factors"]) == 4
