"""
Normalise les alertes Wazuh brutes (Linux + Windows) vers un format
standard unique, prêt à être consommé par le pipeline SOC AI Platform.
"""

import re
import json
from pathlib import Path

INPUT_DIR = Path("wazuh_lab/alerts_dataset")
OUTPUT_DIR = Path("wazuh_lab/normalized")

# Association fichier source -> nom d'attaque lisible
ATTACK_NAME_BY_FILE = {
    "nmap_scan.json": "Network Scan (Nmap)",
    "ssh_bruteforce.json": "SSH Bruteforce (Hydra)",
    "ssh_success.json": "SSH Login Success",
    "pam_login.json": "PAM Login Session",
    "web_scan_correlated.json": "Web Vulnerability Scan (Nikto)",
    "rdp_bruteforce.json": "RDP Bruteforce / Pass-the-Hash",
}


def extract_src_ip(alert: dict) -> str:
    """L'IP source varie selon le format (Linux plat vs Windows imbriqué)."""
    data = alert.get("data", {})

    if "srcip" in data:
        return data["srcip"]

    win_eventdata = data.get("win", {}).get("eventdata", {})
    ip = win_eventdata.get("ipAddress")
    if ip and ip not in ("-", "127.0.0.1"):
        return ip

    return "unknown"


def extract_src_port(alert: dict) -> int:
    """Extrait le port source depuis les logs Linux ou Windows."""
    data = alert.get("data", {})

    # 1. Format Linux / Syslog / SSH / Web classique
    if "srcport" in data:
        try:
            return int(data["srcport"])
        except (ValueError, TypeError):
            pass

    # 2. Format Windows EventChannel (Event 4624/4625, etc.)
    win_port = data.get("win", {}).get("eventdata", {}).get("ipPort")
    if win_port and win_port not in ("-", "0"):
        try:
            return int(win_port)
        except (ValueError, TypeError):
            pass

    # 3. Fallback regex sur le log brut (ex: "port 49190")
    full_log = alert.get("full_log", "")
    match = re.search(r"port\s+(\d+)", full_log, re.IGNORECASE)
    if match:
        try:
            return int(match.group(1))
        except (ValueError, TypeError):
            pass

    return 0


def extract_dst_port(alert: dict, attack_name: str = "") -> int:
    """Extrait ou déduit le port de destination selon le service/protocole."""
    data = alert.get("data", {})

    # 1. Si présent directement dans le log
    if "dstport" in data:
        try:
            return int(data["dstport"])
        except (ValueError, TypeError):
            pass

    # 2. Déduction selon la règle, le décodeur ou le type d'attaque
    description = (alert.get("rule", {}).get("description", "") + " " + (attack_name or "")).lower()
    decoder = alert.get("decoder", {}).get("name", "").lower()
    full_log = alert.get("full_log", "").lower()

    if "ssh" in description or "ssh" in decoder or "sshd" in full_log:
        return 22
    elif "rdp" in description or "pass-the-hash" in description or "3389" in description:
        return 3389
    elif "web" in description or "nikto" in description or "apache" in decoder or "nginx" in decoder or "http" in full_log:
        return 80
    elif "ftp" in description:
        return 21
    elif "smb" in description or "445" in description:
        return 445

    return 0


def extract_dst_user(alert: dict) -> str:
    data = alert.get("data", {})

    if "dstuser" in data:
        return data["dstuser"]

    win_eventdata = data.get("win", {}).get("eventdata", {})
    return win_eventdata.get("targetUserName", "unknown")


# Configuration du filtrage des agents (Décision documentée)
# Si MONITORED_AGENTS = None, on accepte tout sauf l'agent "wazuh" (le serveur lui-même qui génère du bruit interne).
MONITORED_AGENTS = None

def is_noise(alert: dict) -> bool:
    """
    Filtre les alertes qui concernent le serveur Wazuh lui-même,
    pas les machines cibles du labo (victime, DESKTOP-M36GQTK).
    """
    agent_name = alert.get("agent", {}).get("name", "")
    if MONITORED_AGENTS:
        return agent_name not in MONITORED_AGENTS
    return agent_name == "wazuh"


def normalize(alert: dict, attack_name: str = None) -> dict:
    rule = alert.get("rule", {})
    mitre = rule.get("mitre", {})
    
    if not attack_name:
        attack_name = rule.get("description", "Unknown Attack")

    return {
        "id": alert.get("id"),
        "attack": attack_name,
        "timestamp": alert.get("timestamp"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "frequency_count": 1,
        "description": rule.get("description"),
        "src_ip": extract_src_ip(alert),
        "dst_ip": alert.get("agent", {}).get("ip", "unknown"),
        "src_port": extract_src_port(alert),
        "dst_port": extract_dst_port(alert, attack_name),
        "dst_user": extract_dst_user(alert),
        "agent_name": alert.get("agent", {}).get("name"),
        "mitre": {
            "id": mitre.get("id", []),
            "tactic": mitre.get("tactic", []),
            "technique": mitre.get("technique", []),
        },
        "raw_log": alert.get("full_log", ""),
    }


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for file in INPUT_DIR.glob("*.json"):
        attack_name = ATTACK_NAME_BY_FILE.get(file.name, file.stem)

        with open(file, "r", encoding="utf-8") as f:
            alerts = json.load(f)

        normalized = []
        skipped = 0
        for alert in alerts:
            if is_noise(alert):
                skipped += 1
                continue
            normalized.append(normalize(alert, attack_name))

        out_path = OUTPUT_DIR / file.name
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(normalized, f, indent=2, ensure_ascii=False)

        print(f"{file.name}: {len(normalized)} conservees, {skipped} ignorees (bruit wazuh) -> {out_path}")


if __name__ == "__main__":
    main()