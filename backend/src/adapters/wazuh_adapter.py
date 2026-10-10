"""
Adapter Wazuh -> Alert.
Transforme une alerte normalisée (format standard produit par
normalize_alerts.py) en objet Alert identique à celui produit par
AlertBuilder pour CICIDS, afin que le reste du pipeline (scoring, TI,
LLM, ticketing) reste inchangé, quelle que soit la source.
"""

import json
from pathlib import Path

from src.models.network_flow import NetworkFlow
from src.models.alert import Alert


def load_normalized_alerts(normalized_dir: str) -> list[dict]:
    """Charge toutes les alertes normalisées depuis le dossier."""
    all_alerts = []
    for file in Path(normalized_dir).glob("*.json"):
        with open(file, "r", encoding="utf-8") as f:
            all_alerts.extend(json.load(f))
    return all_alerts


def normalized_to_alert(normalized: dict, counter: int) -> Alert:
    """Convertit une alerte normalisée Wazuh en objet Alert du pipeline."""
    mitre = normalized.get("mitre", {})
    mitre_ids = mitre.get("id", [])
    mitre_tactics = mitre.get("tactic", [])

    flow = NetworkFlow(
        flow_id=f"WAZUH-{normalized.get('rule_id', counter)}-{counter}",
        source_ip=normalized.get("src_ip", "unknown"),
        destination_ip=normalized.get("dst_ip", "unknown"),
        source_port=int(normalized.get("src_port", 0) or 0),
        destination_port=int(normalized.get("dst_port", 0) or 0),
        protocol=6,
        timestamp=normalized.get("timestamp", ""),
        flow_duration=0,
        total_fwd_packets=0,
        total_backward_packets=0,
        flow_bytes_per_second=0.0,
        flow_packets_per_second=0.0,
        label=normalized.get("attack", "Unknown"),
        raw_features=normalized,
    )

    attack_name = normalized.get("attack", "Unknown")
    
    if "SSH" in attack_name and ("Bruteforce" in attack_name or "Patator" in attack_name):
        mitre_ids = ["T1110.001", "T1021.004"]
        mitre_tactics = ["Credential Access", "Lateral Movement"]
    elif "FTP" in attack_name and "Patator" in attack_name:
        mitre_ids = ["T1110.001"]
        mitre_tactics = ["Credential Access"]
    elif "RDP" in attack_name and "Bruteforce" in attack_name:
        mitre_ids = ["T1110.001", "T1021.001"]
        mitre_tactics = ["Credential Access", "Lateral Movement"]
    elif "Nmap" in attack_name or "PortScan" in attack_name or "Network Scan" in attack_name:
        mitre_ids = ["T1046"]
        mitre_tactics = ["Discovery"]

    alert = Alert(
        alert_id=f"WAZUH-ALERT-{counter:04d}",
        wazuh_event_id=normalized.get("id"),
        network_flow=flow,
        event_type="wazuh",
        threat_category=attack_name,
        frequency_count=normalized.get("frequency_count", 1),  # rule_level != frequency_count : rule_level est un niveau de sévérité Wazuh (0-15), pas un compteur d'occurrences. Si Wazuh ne fournit pas frequency_count, on initialise à 1 (événement unique). Une future agrégation par règle + IP source + fenêtre temporelle permettra de calculer une vraie fréquence.
        mitre_technique=", ".join(mitre_ids) if mitre_ids else None,
        mitre_tactic=", ".join(mitre_tactics) if mitre_tactics else None,
    )

    return alert