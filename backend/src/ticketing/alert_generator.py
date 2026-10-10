from datetime import datetime
import uuid

INCIDENT_TITLES = {
    "DDoS": "DDoS Attack Detected",
    "Bot": "Botnet Activity Detected",
    "DoS Hulk": "DoS Hulk Attack Detected",
    "DoS GoldenEye": "DoS GoldenEye Attack Detected",
    "DoS Slowhttptest": "Slow HTTP DoS Attack Detected",
    "DoS slowloris": "Slowloris DoS Attack Detected",
    "FTP-Patator": "FTP Brute Force Attack Detected",
    "SSH-Patator": "SSH Brute Force Attack Detected",
    "Heartbleed": "Heartbleed Vulnerability Exploitation Detected",
    "Infiltration": "Network Infiltration Detected",
    "PortScan": "Port Scan Detected",
    "Web Attack  Brute Force": "Web Application Brute Force Detected",
    "Web Attack  Sql Injection": "SQL Injection Attempt Detected",
    "Web Attack  XSS": "Cross-Site Scripting (XSS) Attempt Detected",
    "Network Scan (Nmap)": "Network Reconnaissance Scan Detected",
    "SSH Bruteforce (Hydra)": "SSH Brute Force Attack Detected",
    "SSH Login Success": "Suspicious SSH Login Detected",
    "PAM Login Session": "PAM Login Session Event",
    "Web Vulnerability Scan (Nikto)": "Web Vulnerability Scan Detected",
    "RDP Bruteforce / Pass-the-Hash": "RDP Brute Force / Pass-the-Hash Attack Detected",
}

def build_incident_title(attack_type: str) -> str:
    return INCIDENT_TITLES.get(attack_type, f"{attack_type} Alert")


class AlertGenerator:
    """
    Génère un dictionnaire Alert à partir d'une alerte enrichie (LLM, MITRE, etc).
    """
    def __init__(self):
        pass

    def create_alert(self, alert_obj):
        flow = alert_obj.network_flow

        alert_id = f"ALRT-{uuid.uuid4().hex[:6].upper()}"

        alert_dict = {
            "alert_id": alert_id,
            "wazuh_event_id": alert_obj.wazuh_event_id,
            "incident_title": build_incident_title(alert_obj.threat_category),
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity": alert_obj.priority,
            "attack_type": alert_obj.threat_category,
            "score": alert_obj.score,
            "source_ip": flow.source_ip,
            "destination_ip": flow.destination_ip,
            "source_port": flow.source_port,
            "destination_port": flow.destination_port,
            "protocol": flow.protocol,
            "frequency_count": alert_obj.frequency_count,
            "mitre_tactic": alert_obj.mitre_tactic,
            "mitre": alert_obj.mitre_technique,
            "ip_reputation": str(alert_obj.ip_reputation) if alert_obj.ip_reputation else None,
            "summary": alert_obj.summary,
            "reasoning": alert_obj.reasoning,
            "ioc_assessment": alert_obj.ioc_assessment,
            "mitre_context": alert_obj.mitre_context,
            "recommended_action": alert_obj.recommended_action,
            "confidence": alert_obj.confidence,
            "source": "wazuh" if alert_obj.event_type == "wazuh" else "cicids",
            "llm_provider": "ollama",
            "llm_model": "qwen2.5:7b",
            "status": "NEW",
            "assigned_to": None,
        }

        return alert_dict
