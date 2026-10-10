from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional, Annotated
from datetime import datetime
import sqlite3

from config.settings import DATABASE_PATH
from src.database.database_manager import DatabaseManager
from src.api.models import AlertSchema, AlertUpdateSchema, PromoteAlertSchema
from src.dependencies import get_current_user, require_role
from src.utils.notifier import notify_n8n

router = APIRouter(prefix="/alerts", tags=["alerts"])
db = DatabaseManager()

def _clean(df):
    return df.astype(object).where(df.notnull(), None)

@router.get("", response_model=list[AlertSchema])
def get_alerts(
    current_user: Annotated[dict, Depends(require_role("SOC_L1", "ADMIN"))],
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    status: Optional[str] = None,
    source: Optional[str] = Query(None, description="Filtrer par source : cicids ou wazuh"),
    search: Optional[str] = Query(None, description="Recherche libre sur les IP"),
    sort: str = Query("id", description="Champ de tri: id, score, created_at"),
    order: str = Query("desc", description="asc ou desc"),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
):
    """Retourne la file des alertes SOC."""
    df = db.get_alerts_dataframe()

    if severity:
        df = df[df["severity"] == severity.upper()]
    if attack_type:
        df = df[df["attack_type"].str.contains(attack_type, case=False, na=False)]
    if status:
        df = df[df["status"] == status.upper()]
    if source:
        df = df[df["source"].str.lower() == source.lower()]
    if search:
        df = df[
            df["source_ip"].str.contains(search, na=False)
            | df["destination_ip"].str.contains(search, na=False)
        ]

    if sort in df.columns:
        df = df.sort_values(sort, ascending=(order == "asc"))

    start = (page - 1) * size
    df = df.iloc[start:start + size]

    df = _clean(df)
    return df.to_dict(orient="records")


@router.get("/{alert_id}", response_model=AlertSchema)
def get_alert(alert_id: str, current_user: Annotated[dict, Depends(require_role("SOC_L1", "ADMIN"))]):
    df = _clean(db.get_alerts_dataframe())
    row = df[df["alert_id"] == alert_id]
    if row.empty:
        raise HTTPException(status_code=404, detail=f"Alerte {alert_id} introuvable")
    return row.to_dict(orient="records")[0]


@router.patch("/{alert_id}", response_model=AlertSchema)
def update_alert(
    alert_id: str,
    update: AlertUpdateSchema,
    current_user: Annotated[dict, Depends(require_role("SOC_L1", "ADMIN"))]
):
    """
    Permet à un analyste de changer le statut d'une alerte (ex: DISMISSED, UNDER_REVIEW).
    """
    df = db.get_alerts_dataframe()
    if alert_id not in df["alert_id"].values:
        raise HTTPException(status_code=404, detail="Alerte introuvable")

    fields = {}
    if update.status:
        fields["status"] = update.status.upper()
        if fields["status"] == "DISMISSED":
            fields["reviewed_by"] = current_user.get("username")
            fields["reviewed_at"] = datetime.now().isoformat()
    if update.investigation_notes is not None:
        fields["investigation_notes"] = update.investigation_notes
    if update.classification is not None:
        fields["classification"] = update.classification

    db.update_alert(alert_id, fields)
    
    df = _clean(db.get_alerts_dataframe())
    row = df[df["alert_id"] == alert_id]
    return row.to_dict(orient="records")[0]


@router.post("/{alert_id}/promote")
def promote_alert(
    alert_id: str,
    payload: PromoteAlertSchema,
    current_user: Annotated[dict, Depends(require_role("SOC_L1", "ADMIN"))]
):
    """
    Crée un vrai Ticket à partir de l'alerte et notifie (n8n).
    """
    # 0. Vérifier que l'utilisateur assigné est bien un SOC_L2
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username = ?", (payload.assigned_to,))
    user_row = cursor.fetchone()
    conn.close()
    
    if not user_row:
        raise HTTPException(status_code=400, detail="L'analyste specifie n'existe pas.")
    if user_row[0] != "SOC_L2":
        raise HTTPException(status_code=400, detail="L'analyste assigne doit avoir le role SOC_L2.")

    # 1. Vérifier l'alerte
    df_alerts = _clean(db.get_alerts_dataframe())
    alert_row = df_alerts[df_alerts["alert_id"] == alert_id]
    if alert_row.empty:
        raise HTTPException(status_code=404, detail="Alerte introuvable")
    
    alert_dict = alert_row.to_dict(orient="records")[0]

    if alert_dict["status"] == "ESCALATED":
        raise HTTPException(status_code=400, detail="Alerte déjà promue en incident")

    # 2. Mettre à jour le statut de l'alerte
    db.update_alert(alert_id, {
        "status": "ESCALATED",
        "assigned_to": payload.assigned_to,
        "reviewed_by": current_user.get("username"),
        "reviewed_at": datetime.now().isoformat()
    })

    # 3. Créer le ticket
    import uuid
    ticket_id = f"INC-{uuid.uuid4().hex[:6].upper()}"
    new_ticket = {
        "ticket_id": ticket_id,
        "alert_id": alert_id,
        "status": "IN_PROGRESS",
        "assigned_to": payload.assigned_to
    }
    db.insert_ticket(new_ticket)

    # 4. Envoyer l'email n8n (on passe l'alerte d'origine enrichie du ticket_id)
    alert_dict["ticket_id"] = ticket_id
    alert_dict["assigned_to"] = payload.assigned_to
    try:
        notify_n8n(alert_dict)
    except Exception as e:
        print(f"Erreur notification n8n: {e}")

    return {"message": "Incident créé avec succès", "ticket_id": ticket_id}
from typing import Dict, Any

from typing import Dict, Any
from src.adapters.wazuh_adapter import normalized_to_alert
from src.threat_intelligence.reputation_checker import ReputationChecker
from src.scoring.scoring_engine import ScoringEngine
from src.llm.llm_service import LLMService
from src.ticketing.alert_generator import AlertGenerator
from wazuh_lab.normalize_alerts import normalize, is_noise
import uuid

@router.post('/wazuh/webhook')
def receive_wazuh_webhook(payload: Dict[Any, Any]):
    agent_name = payload.get('agent', {}).get('name', 'unknown')
    rule_id = payload.get('rule', {}).get('id', 'unknown')
    wazuh_event_id = payload.get('id')

    if is_noise(payload):
        print(f"[WEBHOOK] IGNORÉ (bruit agent '{agent_name}', règle {rule_id})")
        return {'status': 'skipped', 'reason': 'noise'}

    if wazuh_event_id and db.check_wazuh_event_exists(wazuh_event_id):
        print(f"[WEBHOOK] IGNORÉ (déjà existant dans la BD, event_id: {wazuh_event_id})")
        return {'status': 'skipped', 'reason': 'duplicate', 'wazuh_event_id': wazuh_event_id}

    print(f"[WEBHOOK] TRAITEMENT D'UNE NOUVELLE ALERTE (event_id: {wazuh_event_id}, rule: {rule_id})...")
    normalized = normalize(payload)
    
    counter = int(uuid.uuid4().hex[:6], 16)
    alert_obj = normalized_to_alert(normalized, counter=counter)

    reputation_checker = ReputationChecker()
    scoring_engine = ScoringEngine()
    llm_service = LLMService()
    alert_generator = AlertGenerator()

    alert_obj.ip_reputation = reputation_checker.check_ip(alert_obj.network_flow.source_ip)
    alert_obj = scoring_engine.evaluate(alert_obj)
    alert_obj = llm_service.analyze(alert_obj)
    
    alert_dict = alert_generator.create_alert(alert_obj)
    db.insert_alert(alert_dict)

    print(f"[WEBHOOK] [OK] NOUVELLE ALERTE INSÉRÉE EN BD: {alert_dict['alert_id']} ({alert_dict['attack_type']}) - Score: {alert_dict['score']}")

    return {
        'status': 'success',
        'alert_id': alert_dict['alert_id'],
        'wazuh_event_id': wazuh_event_id,
        'score': alert_dict['score'],
        'frequency_count': alert_dict['frequency_count']
    }
