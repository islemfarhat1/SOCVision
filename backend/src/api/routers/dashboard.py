from fastapi import APIRouter, Depends
from typing import Annotated

from src.database.database_manager import DatabaseManager
from src.api.models import DashboardSchema, StatisticsSchema
from src.dependencies import get_current_user

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
db = DatabaseManager()

@router.get("", response_model=DashboardSchema)
def get_dashboard(
    current_user: Annotated[dict, Depends(get_current_user)],
    latest_limit: int = 10
):
    """Endpoint agrégé : statistiques (basées sur les alertes) + dernières alertes."""
    df = db.get_alerts_dataframe()

    if df.empty:
        stats = StatisticsSchema(total_alerts=0, critical=0, high=0, medium=0, low=0, by_attack_type={})
        return DashboardSchema(statistics=stats, latest_alerts=[])

    severity_counts = df["severity"].value_counts()
    stats = StatisticsSchema(
        total_alerts=len(df),
        critical=int(severity_counts.get("CRITICAL", 0)),
        high=int(severity_counts.get("HIGH", 0)),
        medium=int(severity_counts.get("MEDIUM", 0)),
        low=int(severity_counts.get("LOW", 0)),
        by_attack_type=df["attack_type"].value_counts().to_dict()
    )

    latest = df.astype(object).where(df.notnull(), None).sort_values("id", ascending=False).head(latest_limit)

    return DashboardSchema(statistics=stats, latest_alerts=latest.to_dict(orient="records"))