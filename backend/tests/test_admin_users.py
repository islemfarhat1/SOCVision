"""Gestion des comptes par l'Admin, avec de vrais jetons (base jetable, voir conftest.py)."""

import uuid

from fastapi.testclient import TestClient

from src.api.main import app
from src.api.routers import admin as admin_router
from src.api.routers import auth as auth_router
from src.login_rate_limiter import LoginRateLimiter
from src.security import create_access_token

client = TestClient(app)
db = admin_router.db
ADMIN = "karim.bouazizi"  # seeded administrator


def headers(username):
    user = db.get_user(username)
    token = create_access_token({"sub": username, "full_name": user["full_name"], "role": user["role"]})
    return {"Authorization": f"Bearer {token}"}


def new_account(role="SOC_L1", password="Initial-Pass-123"):
    username = f"test.{uuid.uuid4().hex[:8]}"
    r = client.post("/api/admin/users", headers=headers(ADMIN),
                    json={"username": username, "full_name": "Test Analyst", "role": role, "password": password})
    assert r.status_code == 201, r.text
    return username


def login(username, password):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def setup_function():
    auth_router.login_limiter = LoginRateLimiter(1000, 60)  # keep these tests independent of lockouts


def test_only_admins_can_manage_accounts():
    assert client.get("/api/admin/users", headers=headers("ahmed.salem")).status_code == 403
    assert client.get("/api/admin/users").status_code == 401
    users = client.get("/api/admin/users", headers=headers(ADMIN)).json()
    assert {"username", "role", "disabled", "active_incidents"} <= set(users[0])
    assert all("password" not in key for u in users for key in u)


def test_create_account_validation_and_login():
    username = new_account(password="Initial-Pass-123")
    assert login(username, "Initial-Pass-123").status_code == 200

    duplicate = client.post("/api/admin/users", headers=headers(ADMIN),
                            json={"username": username, "full_name": "X Y", "role": "SOC_L1", "password": "Another-Pass-1"})
    assert duplicate.status_code == 409
    for bad in ({"username": "Bad Name!", "password": "Long-enough-1"}, {"username": "ok.name", "password": "short"}):
        r = client.post("/api/admin/users", headers=headers(ADMIN), json={"full_name": "X Y", "role": "SOC_L1", **bad})
        assert r.status_code == 422
    assert client.post("/api/admin/users", headers=headers(ADMIN),
                       json={"username": "ok.name", "full_name": "X Y", "role": "SOC_L3", "password": "Long-enough-1"}
                       ).status_code == 422


def test_disabling_blocks_login_and_existing_session_immediately():
    username = new_account(password="Initial-Pass-123")
    session = headers(username)
    assert client.get("/api/alerts", headers=session).status_code == 200

    assert client.patch(f"/api/admin/users/{username}", headers=headers(ADMIN), json={"disabled": True}).status_code == 200
    assert client.get("/api/alerts", headers=session).status_code == 401          # token still valid, account not
    r = login(username, "Initial-Pass-123")
    assert r.status_code == 403 and "disabled" in r.json()["detail"]
    assert login(username, "wrong-password").status_code == 401                    # no hint without the password

    client.patch(f"/api/admin/users/{username}", headers=headers(ADMIN), json={"disabled": False})
    assert login(username, "Initial-Pass-123").status_code == 200


def test_role_change_applies_to_open_sessions():
    username = new_account(role="SOC_L1")
    session = headers(username)  # token issued while SOC_L1
    assert client.get("/api/alerts", headers=session).status_code == 200
    client.patch(f"/api/admin/users/{username}", headers=headers(ADMIN), json={"role": "SOC_L2"})
    assert client.get("/api/alerts", headers=session).status_code == 403          # L2 has no alert queue
    assert client.get("/api/tickets", headers=session).status_code == 200


def test_admin_cannot_lock_themselves_out():
    me = headers(ADMIN)
    assert client.patch(f"/api/admin/users/{ADMIN}", headers=me, json={"role": "SOC_L1"}).status_code == 400
    assert client.patch(f"/api/admin/users/{ADMIN}", headers=me, json={"disabled": True}).status_code == 400
    assert db.get_user(ADMIN)["role"] == "ADMIN"


def test_password_reset_and_audit_trail_without_secrets():
    username = new_account(password="Initial-Pass-123")
    assert client.post(f"/api/admin/users/{username}/password", headers=headers(ADMIN),
                       json={"password": "Brand-New-Pass-9"}).status_code == 204
    assert login(username, "Initial-Pass-123").status_code == 401
    assert login(username, "Brand-New-Pass-9").status_code == 200

    events = client.get("/api/admin/audit", headers=headers(ADMIN)).json()
    mine = [e for e in events if e["details"].get("username") == username]
    assert [e["action"] for e in mine][:2] == ["PASSWORD_RESET", "USER_CREATED"]
    assert all(e["actor"] == ADMIN for e in mine)
    assert "Brand-New-Pass-9" not in str(events) and "Initial-Pass-123" not in str(events)


def test_disabled_accounts_cannot_be_assigned():
    analyst = new_account(role="SOC_L2")
    client.patch(f"/api/admin/users/{analyst}", headers=headers(ADMIN), json={"disabled": True})
    listed = client.get("/api/users?role=SOC_L2", headers=headers(ADMIN)).json()
    assert analyst not in [u["username"] for u in listed]
