import sqlite3

import bcrypt
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config.settings import FRONTEND_ORIGIN, API_VERSION, DATABASE_PATH, WAZUH_WEBHOOK_TOKEN
from src.api.routers import tickets, alerts, stats, dashboard, system, users, auth

app = FastAPI(
    title="SOC AI Platform API",
    description="API du pipeline d'enrichissement et de qualification des alertes SOC",
    version=API_VERSION
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN, "http://localhost:8501"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Retry-After"],
)

app.include_router(system.router, prefix="/api")
app.include_router(tickets.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(stats.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(auth.router, prefix="/api")


def _security_startup_checks() -> None:
    """Avertit au démarrage des réglages de sécurité dangereux."""
    if not WAZUH_WEBHOOK_TOKEN:
        print("[SECURITY] WAZUH_WEBHOOK_TOKEN is not set: the Wazuh webhook is disabled.")
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        rows = conn.execute("SELECT username, password_hash FROM users").fetchall()
        conn.close()
    except sqlite3.Error:
        return
    weak = [u for u, h in rows if h and bcrypt.checkpw(b"admin123", h.encode("utf-8"))]
    if weak:
        print(
            f"[SECURITY] {len(weak)} account(s) still use the old default password 'admin123': "
            f"{', '.join(weak)}. Change them before any demo outside your machine."
        )


_security_startup_checks()


@app.get("/")
def root():
    return {"status": "ok", "service": "SOC AI Platform API"}