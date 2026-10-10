from dataclasses import dataclass
from typing import Optional, Dict

from src.models.network_flow import NetworkFlow


@dataclass
class Alert:
    """
    Représente une alerte SOC enrichie.
    """

    # ==========================
    # Alert Identity
    # ==========================

    alert_id: str

    network_flow: NetworkFlow

    # ==========================
    # Classification
    # ==========================

    event_type: str

    wazuh_event_id: Optional[str] = None

    threat_category: Optional[str] = None

    # ==========================
    # SOC Scoring
    # ==========================

    score: Optional[float] = None

    score_details: Optional[Dict] = None

    priority: Optional[str] = None

    frequency_count: Optional[int] = None

    # ==========================
    # Threat Intelligence
    # ==========================

    ip_reputation: Optional[Dict] = None

    virustotal_result: Optional[Dict] = None

    abuseipdb_result: Optional[Dict] = None

    # ==========================
    # MITRE ATT&CK
    # ==========================

    mitre_tactic: Optional[str] = None

    mitre_technique: Optional[str] = None

    # ==========================
    # LLM Analysis
    # ==========================

    summary: Optional[str] = None

    reasoning: Optional[str] = None

    ioc_assessment: Optional[str] = None

    mitre_context: Optional[str] = None

    recommended_action: Optional[str] = None

    confidence: Optional[float] = None

    # ==========================
    # Ticket
    # ==========================

    ticket_id: Optional[str] = None

    status: Optional[str] = None