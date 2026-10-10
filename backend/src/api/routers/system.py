from fastapi import APIRouter
from datetime import datetime

from config.settings import API_VERSION
from src.database.database_manager import DatabaseManager

router = APIRouter(tags=["system"])
db = DatabaseManager()


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