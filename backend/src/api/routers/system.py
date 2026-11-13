from typing import Annotated

import requests
from fastapi import APIRouter, Depends
from datetime import datetime

from config import api_keys, settings
from config.settings import API_VERSION
from src.database.database_manager import DatabaseManager
from src.dependencies import get_current_user
from src.llm.openrouter_client import OpenRouterClient
from src.scoring import scoring_engine
from src.scoring.scoring_rules import ATTACK_SCORES

router = APIRouter(tags=["system"])
db = DatabaseManager()

OLLAMA_TAGS_URL = "http://localhost:11434/api/tags"


@router.get("/health")
def health_check():
    """Vérifie que l'API et la base de données sont accessibles."""
    try:
        db.get_alerts_dataframe()
        db_status = "connected"
    except Exception:
        db_status = "unreachable"

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "database": db_status,
        "timestamp": datetime.now().isoformat()
    }


@router.get("/version")
def version():
    return {"version": API_VERSION}


def _ollama_models() -> list[str] | None:
    """Modèles installés sur Ollama, ou None si Ollama ne répond pas."""
    try:
        response = requests.get(OLLAMA_TAGS_URL, timeout=1.5)
        response.raise_for_status()
        return [m.get("name") for m in response.json().get("models", [])]
    except (requests.RequestException, ValueError):
        return None


@router.get("/system/status")
def system_status(current_user: Annotated[dict, Depends(get_current_user)]):
    """
    État réel de la plateforme et modèle de scoring appliqué.
    Ne renvoie jamais de secret : seulement si chaque clé est configurée ou non.
    """
    health = health_check()
    llm = OpenRouterClient(use_local=True)
    installed = _ollama_models()

    return {
        "version": API_VERSION,
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "database": health["database"],
        "threat_intel": {
            "virustotal_configured": bool(api_keys.VIRUSTOTAL_API_KEY),
            "abuseipdb_configured": bool(api_keys.ABUSEIPDB_API_KEY),
        },
        "llm": {
            "ollama_reachable": installed is not None,
            "local_models": [
                {"name": name, "installed": installed is not None and name in installed}
                for name in llm.local_models
            ],
            "cloud_fallback_configured": llm.remote_client is not None,
            "cloud_models": list(llm.remote_models),
        },
        "wazuh_webhook_enabled": bool(settings.WAZUH_WEBHOOK_TOKEN),
        "scoring": {
            "attack_types": dict(sorted(ATTACK_SCORES.items(), key=lambda kv: -kv[1])),
            "wazuh_frequency_tiers": scoring_engine.WAZUH_FREQUENCY_TIERS,
            "flow_frequency_tiers": scoring_engine.FLOW_FREQUENCY_TIERS,
            "reputation_points": scoring_engine.REPUTATION_POINTS,
            "mitre_points": scoring_engine.MITRE_POINTS,
            "priority_thresholds": scoring_engine.PRIORITY_THRESHOLDS,
        },
    }
