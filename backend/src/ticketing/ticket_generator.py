from datetime import datetime

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


class TicketGenerator:
    """
    Génère un incident SOC à partir d'une alerte enrichie.
    """
    def __init__(self):
        self.counter = 1

    def create_ticket(self, alert):
        flow = alert.network_flow

        ticket = {
            "ticket_id": f"INC-{self.counter:05d}",
            "incident_title": build_incident_title(alert.threat_category),
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity": alert.priority,
            "attack_type": alert.threat_category,
            "score": alert.score,
            "source_ip": flow.source_ip,
            "destination_ip": flow.destination_ip,
            "source_port": flow.source_port,
            "destination_port": flow.destination_port,
            "protocol": flow.protocol,
            "frequency_count": alert.frequency_count,
            "mitre_tactic": alert.mitre_tactic,
            "mitre": alert.mitre_technique,
            "ip_reputation": str(alert.ip_reputation) if alert.ip_reputation else None,
            "summary": alert.summary,
            "reasoning": alert.reasoning,
            "ioc_assessment": alert.ioc_assessment,
            "mitre_context": alert.mitre_context,
            "recommended_action": alert.recommended_action,
            "confidence": alert.confidence,
            "source": "wazuh" if alert.event_type == "wazuh" else "cicids",
            "llm_provider": "ollama",
            "llm_model": "qwen2.5:7b",
            "status": "NEW",
            "assigned_to": None,
        }

        self.counter += 1
        return ticket