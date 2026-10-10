from fastapi import APIRouter, Depends
from typing import Annotated

from src.database.database_manager import DatabaseManager
from src.api.models import StatisticsSchema, TopEntitiesSchema, TopEntitySchema
from src.dependencies import get_current_user

router = APIRouter(prefix="/statistics", tags=["statistics"])
db = DatabaseManager()

@router.get("", response_model=StatisticsSchema)
def get_statistics(current_user: Annotated[dict, Depends(get_current_user)]):
    """Retourne les statistiques globales (basées sur les alertes)."""
    df = db.get_alerts_dataframe()

    if df.empty:
        return StatisticsSchema(
            total_alerts=0, critical=0, high=0, medium=0, low=0, by_attack_type={}
        )

    severity_counts = df["severity"].value_counts()
    attack_counts = df["attack_type"].value_counts().to_dict()

    return StatisticsSchema(
        total_alerts=len(df),
        critical=int(severity_counts.get("CRITICAL", 0)),
        high=int(severity_counts.get("HIGH", 0)),
        medium=int(severity_counts.get("MEDIUM", 0)),
        low=int(severity_counts.get("LOW", 0)),
        by_attack_type=attack_counts
    )

@router.get("/top-entities", response_model=TopEntitiesSchema)
def get_top_entities(
    current_user: Annotated[dict, Depends(get_current_user)],
    limit: int = 5
):
    """Retourne les IP sources et destinations les plus fréquentes dans les alertes."""
    df = db.get_alerts_dataframe()

    if df.empty:
        return TopEntitiesSchema(top_attackers=[], top_victims=[])

    top_attackers = (
        df["source_ip"].value_counts().head(limit)
        .reset_index()
    )
    top_attackers.columns = ["ip", "count"]

    top_victims = (
        df["destination_ip"].value_counts().head(limit)
        .reset_index()
    )
    top_victims.columns = ["ip", "count"]

    return TopEntitiesSchema(
        top_attackers=[TopEntitySchema(**row) for row in top_attackers.to_dict(orient="records")],
        top_victims=[TopEntitySchema(**row) for row in top_victims.to_dict(orient="records")],
    )