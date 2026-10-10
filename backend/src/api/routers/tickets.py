from fastapi import APIRouter, HTTPException, Depends
from typing import Annotated

from src.database.database_manager import DatabaseManager
from src.api.models import TicketSchema, TicketUpdateSchema
from src.dependencies import get_current_user, require_role

router = APIRouter(prefix="/tickets", tags=["tickets"])
db = DatabaseManager()

def _clean(df):
    return df.astype(object).where(df.notnull(), None)

@router.get("", response_model=list[TicketSchema])
def get_tickets(
    current_user: Annotated[dict, Depends(require_role("SOC_L2", "MANAGER", "ADMIN"))]
):
    """Retourne les tickets/incidents confirmés."""
    df = db.get_tickets_dataframe()
    df = _clean(df)
    return df.to_dict(orient="records")

@router.get("/{ticket_id}", response_model=TicketSchema)
def get_ticket(
    ticket_id: str,
    current_user: Annotated[dict, Depends(require_role("SOC_L2", "MANAGER", "ADMIN"))]
):
    df = _clean(db.get_tickets_dataframe())
    row = df[df["ticket_id"] == ticket_id]
    if row.empty:
        raise HTTPException(status_code=404, detail=f"Ticket {ticket_id} introuvable")
    return row.to_dict(orient="records")[0]

@router.patch("/{ticket_id}", response_model=TicketSchema)
def update_ticket(
    ticket_id: str,
    update: TicketUpdateSchema,
    current_user: Annotated[dict, Depends(require_role("SOC_L2", "ADMIN"))]
):
    df = _clean(db.get_tickets_dataframe())
    row = df[df["ticket_id"] == ticket_id]
    if row.empty:
        raise HTTPException(status_code=404, detail=f"Ticket {ticket_id} introuvable")

    current_ticket = row.to_dict(orient="records")[0]

    fields = {}
    if update.status:
        fields["status"] = update.status.upper()
    if update.assigned_to is not None:
        fields["assigned_to"] = update.assigned_to
    if update.comments is not None:
        fields["comments"] = update.comments

    db.update_ticket(ticket_id, fields)

    df_updated = _clean(db.get_tickets_dataframe())
    updated_row = df_updated[df_updated["ticket_id"] == ticket_id]
    return updated_row.to_dict(orient="records")[0]


from src.api.models import IncidentReportSchema
from src.llm.llm_service import LLMService
from datetime import datetime

@router.post("/{ticket_id}/generate-report", response_model=IncidentReportSchema)
def generate_report(
    ticket_id: str,
    current_user: Annotated[dict, Depends(require_role("SOC_L2", "ADMIN"))]
):
    """Génère un rapport d'incident via LLM et le sauvegarde dans l'historique."""
    df_tickets = _clean(db.get_tickets_dataframe())
    row = df_tickets[df_tickets["ticket_id"] == ticket_id]
    if row.empty:
        raise HTTPException(status_code=404, detail="Ticket introuvable")
    
    ticket_data = row.to_dict(orient="records")[0]
    
    # Récupérer l'alerte d'origine complète (le join de get_tickets_dataframe ne contient pas tout)
    alert_id = ticket_data["alert_id"]
    df_alerts = _clean(db.get_alerts_dataframe())
    alert_row = df_alerts[df_alerts["alert_id"] == alert_id]
    alert_data = alert_row.to_dict(orient="records")[0] if not alert_row.empty else {}

    # Générer le rapport via le LLM
    llm = LLMService()
    report_content = llm.generate_incident_report(ticket_data, alert_data)
    
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    generated_by = current_user.get("username", "System")
    
    # Sauvegarder dans la DB
    version = db.insert_incident_report(ticket_id, generated_by, generated_at, report_content)
    
    # Récupérer la ligne insérée
    reports = db.get_incident_reports(ticket_id)
    return reports[0]

@router.get("/{ticket_id}/reports", response_model=list[IncidentReportSchema])
def get_reports(
    ticket_id: str,
    current_user: Annotated[dict, Depends(require_role("SOC_L2", "MANAGER", "ADMIN"))]
):
    """Récupère l'historique des rapports générés pour un ticket donné."""
    reports = db.get_incident_reports(ticket_id)
    return reports