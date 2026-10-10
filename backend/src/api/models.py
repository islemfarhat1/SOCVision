from pydantic import BaseModel
from typing import Optional


class AlertSchema(BaseModel):
    id: int
    alert_id: str
    wazuh_event_id: Optional[str] = None
    incident_title: Optional[str] = None
    created_at: str
    severity: str
    attack_type: str
    score: int

    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[int] = None
    frequency_count: Optional[int] = None

    mitre_tactic: Optional[str] = None
    mitre: Optional[str] = None
    ip_reputation: Optional[str] = None

    summary: Optional[str] = None
    reasoning: Optional[str] = None
    ioc_assessment: Optional[str] = None
    mitre_context: Optional[str] = None
    recommended_action: Optional[str] = None
    confidence: Optional[float] = None
    source: Optional[str] = None
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None

    status: str
    assigned_to: Optional[str] = None
    investigation_notes: Optional[str] = None
    classification: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None

    class Config:
        from_attributes = True


class TicketSchema(BaseModel):
    id: int
    ticket_id: str
    alert_id: str
    assigned_to: Optional[str] = None
    status: str
    comments: Optional[str] = None
    ticket_created_at: Optional[str] = None
    # Joined fields from alert
    incident_title: Optional[str] = None
    severity: Optional[str] = None
    attack_type: Optional[str] = None
    score: Optional[int] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[int] = None
    frequency_count: Optional[int] = None
    mitre_tactic: Optional[str] = None
    mitre: Optional[str] = None
    ip_reputation: Optional[str] = None
    summary: Optional[str] = None
    reasoning: Optional[str] = None
    ioc_assessment: Optional[str] = None
    mitre_context: Optional[str] = None
    recommended_action: Optional[str] = None
    confidence: Optional[float] = None
    source: Optional[str] = None
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    investigation_notes: Optional[str] = None
    classification: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None

    class Config:
        from_attributes = True


class AlertUpdateSchema(BaseModel):
    status: Optional[str] = None
    investigation_notes: Optional[str] = None
    classification: Optional[str] = None


class PromoteAlertSchema(BaseModel):
    assigned_to: str


class TicketUpdateSchema(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    comments: Optional[str] = None

class IncidentReportSchema(BaseModel):
    id: int
    ticket_id: str
    generated_by: str
    generated_at: str
    content: str
    version: int

    class Config:
        from_attributes = True

class StatisticsSchema(BaseModel):
    total_alerts: int
    critical: int
    high: int
    medium: int
    low: int
    by_attack_type: dict[str, int]


class DashboardSchema(BaseModel):
    statistics: StatisticsSchema
    latest_alerts: list[AlertSchema]


class TopEntitySchema(BaseModel):
    ip: str
    count: int


class TopEntitiesSchema(BaseModel):
    top_attackers: list[TopEntitySchema]
    top_victims: list[TopEntitySchema]


class UserSchema(BaseModel):
    id: int
    username: str
    full_name: str
    role: str

    class Config:
        from_attributes = True