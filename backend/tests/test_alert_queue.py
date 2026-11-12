"""Tests de la file d'alertes : filtres, recherche, tri, total et compteurs par statut."""

import os

import pandas as pd
import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")

from fastapi.testclient import TestClient  # noqa: E402

from src.api.main import app  # noqa: E402
from src.api.routers import alerts as alerts_router  # noqa: E402
from src.dependencies import get_current_user  # noqa: E402

client = TestClient(app)

ROWS = [
    # id, alert_id, title, attack_type, severity, score, status, source, src, dst, created_at
    (1, "ALRT-AAA111", "SSH Brute Force Attack Detected", "SSH Bruteforce (Hydra)", "CRITICAL", 80, "NEW", "wazuh", "192.168.56.20", "192.168.56.10", "2026-08-13T14:40:00"),
    (2, "ALRT-BBB222", "Web Vulnerability Scan Detected", "Web Vulnerability Scan (Nikto)", "CRITICAL", 90, "UNDER_REVIEW", "wazuh", "192.168.56.20", "192.168.56.10", "2026-08-13T14:43:00"),
    (3, "ALRT-CCC333", "DDoS Attack Detected", "DDoS", "HIGH", 60, "ESCALATED", "cicids", "172.16.0.1", "192.168.10.50", "2026-08-13T14:25:00"),
    (4, "ALRT-DDD444", "Port Scan Detected", "PortScan", "LOW", 20, "DISMISSED", "cicids", "10.0.0.5", "192.168.10.51", "2026-08-12T09:00:00"),
    (5, "ALRT-EEE555", "SSH Login Success", "SSH Login Success", "MEDIUM", 35, "NEW", "wazuh", "192.168.56.30", "192.168.56.10", "2026-08-14T08:00:00"),
]
COLUMNS = ["id", "alert_id", "incident_title", "attack_type", "severity", "score", "status",
           "source", "source_ip", "destination_ip", "created_at"]


@pytest.fixture(autouse=True)
def fake_alerts(monkeypatch):
    monkeypatch.setattr(alerts_router.db, "get_alerts_dataframe",
                        lambda: pd.DataFrame(ROWS, columns=COLUMNS))
    app.dependency_overrides[get_current_user] = lambda: {"username": "l1", "role": "SOC_L1"}
    yield
    app.dependency_overrides.clear()


def ids(response):
    return [a["alert_id"] for a in response.json()]


def test_multiple_statuses_and_total_header():
    r = client.get("/api/alerts", params={"status": "NEW,UNDER_REVIEW", "size": 2, "sort": "score"})
    assert r.status_code == 200
    assert r.headers["X-Total-Count"] == "3"
    assert ids(r) == ["ALRT-BBB222", "ALRT-AAA111"]  # page of 2, highest score first


def test_search_covers_title_id_and_type_case_insensitive():
    assert ids(client.get("/api/alerts", params={"search": "ssh"})) == ["ALRT-EEE555", "ALRT-AAA111"]
    assert ids(client.get("/api/alerts", params={"search": "ccc333"})) == ["ALRT-CCC333"]
    assert ids(client.get("/api/alerts", params={"search": "nikto"})) == ["ALRT-BBB222"]
    assert ids(client.get("/api/alerts", params={"search": "172.16"})) == ["ALRT-CCC333"]


def test_search_treats_input_as_plain_text_not_regex():
    r = client.get("/api/alerts", params={"search": "(.*"})
    assert r.status_code == 200
    assert r.json() == []


def test_sort_by_created_at_ascending():
    r = client.get("/api/alerts", params={"sort": "created_at", "order": "asc"})
    assert ids(r)[0] == "ALRT-DDD444"


def test_unknown_sort_field_is_ignored():
    assert client.get("/api/alerts", params={"sort": "password_hash"}).status_code == 200


def test_status_counts_follow_filters():
    r = client.get("/api/alerts/status-counts")
    assert r.json() == {"NEW": 2, "UNDER_REVIEW": 1, "ESCALATED": 1, "DISMISSED": 1}

    r = client.get("/api/alerts/status-counts", params={"source": "wazuh"})
    assert r.json() == {"NEW": 2, "UNDER_REVIEW": 1, "ESCALATED": 0, "DISMISSED": 0}


def test_status_counts_route_is_not_shadowed_by_alert_detail():
    # /alerts/{alert_id} must not swallow /alerts/status-counts
    assert client.get("/api/alerts/status-counts").status_code == 200
