"""
Configuration pytest.

Les fichiers ci-dessous sont des scripts de vérification manuelle : ils appellent
les vraies API (VirusTotal, AbuseIPDB, Ollama/OpenRouter) ou ont besoin du dataset
CICIDS2017, et s'exécutent à l'import. Ils ne sont donc pas collectés par pytest
(ni en CI). Pour en lancer un : python tests/<fichier>.py depuis backend/.
"""

import os

# Clé de test : src.security exige JWT_SECRET_KEY à l'import.
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret")

collect_ignore = [
    "test_abuseipdb.py",
    "test_alert.py",
    "test_alert_builder.py",
    "test_database.py",
    "test_frequency.py",
    "test_llm.py",
    "test_mitre.py",
    "test_network_flow.py",
    "test_openrouter.py",
    "test_prompt_builder.py",
    "test_scoring.py",
    "test_simulator.py",
    "test_ticketing.py",
    "test_virustotal.py",
    "test_wazuh_scoring.py",
]
