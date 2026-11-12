import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# --- Database ---
DATABASE_PATH = os.getenv("DATABASE_PATH", "database/soc_alerts.db")

# --- API ---
API_VERSION = "1.0.0"
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

# --- LLM ---
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "google/gemini-2.5-flash")
LLM_MAX_TOKENS = 900
LLM_TEMPERATURE = 0

# --- CORS ---
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")
N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL", "http://localhost:5678/webhook/ticket-created")

# --- Security ---
# Shared secret sent by the Wazuh integration in the X-Webhook-Token header.
# If unset, the webhook is disabled (fail closed).
WAZUH_WEBHOOK_TOKEN = os.getenv("WAZUH_WEBHOOK_TOKEN", "")
# Password given to the seeded demo accounts when the users table is created.
# If unset, a random password is generated and printed once at first startup.
SEED_USER_PASSWORD = os.getenv("SEED_USER_PASSWORD", "")
# Login brute-force protection
LOGIN_MAX_FAILURES = int(os.getenv("LOGIN_MAX_FAILURES", "5"))
LOGIN_LOCKOUT_SECONDS = int(os.getenv("LOGIN_LOCKOUT_SECONDS", "900"))