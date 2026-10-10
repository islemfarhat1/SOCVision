# Scores associés aux catégories d'attaques
# Ces valeurs pourront évoluer selon la politique SOC






PRIORITY_LEVELS = {
    "LOW": 20,
    "MEDIUM": 40,
    "HIGH": 70,
    "CRITICAL": 90
}

FREQUENCY_SCORES = {
    "LOW": 0,
    "MEDIUM": 5,
    "HIGH": 10,
    "VERY_HIGH": 20
}
ATTACK_SCORES = {

    # ===== CICIDS =====

    "BENIGN": 0,
    "PortScan": 20,

    "DoS Hulk": 40,
    "DoS GoldenEye": 40,
    "DoS Slowloris": 40,
    "DoS Slowhttptest": 40,
    "DDoS": 45,

    "FTP-Patator": 30,
    "SSH-Patator": 30,

    "Bot": 50,
    "Infiltration": 60,

    "Web Attack": 35,

    "Heartbleed": 70,

    # ===== WAZUH =====

    "Network Scan (Nmap)": 40,
    "SSH Bruteforce (Hydra)": 55,
    "SSH Login Success": 20,
    "PAM Login Session": 10,
    "Web Vulnerability Scan (Nikto)": 60,
    "RDP Bruteforce / Pass-the-Hash": 70,
}