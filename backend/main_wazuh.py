from src.adapters.wazuh_adapter import load_normalized_alerts, normalized_to_alert
from src.threat_intelligence.reputation_checker import ReputationChecker
from src.scoring.scoring_engine import ScoringEngine
from src.llm.llm_service import LLMService
from src.ticketing.alert_generator import AlertGenerator
from src.database.database_manager import DatabaseManager


NORMALIZED_DIR = "wazuh_lab/normalized"


def main():
    print("MAIN_WAZUH LANCE")
    print("=" * 70)
    print("SOC AI PLATFORM — SOURCE WAZUH")
    print("=" * 70)

    alerts_raw = load_normalized_alerts(NORMALIZED_DIR)
    print(f"[OK] {len(alerts_raw)} alertes normalisees chargees")

    reputation_checker = ReputationChecker()
    scoring_engine = ScoringEngine()
    llm_service = LLMService()
    database = DatabaseManager()
    alert_generator = AlertGenerator()

    print("[OK] Services initialises")

    processed = 0
    total = len(alerts_raw)

    for i, raw in enumerate(alerts_raw):
        print(f"\nProcessing Alert {i + 1}/{total}")

        alert = normalized_to_alert(raw, i + 1)

        # Threat Intelligence — même service que CICIDS, appliqué sur l'IP source
        alert.ip_reputation = reputation_checker.check_ip(alert.network_flow.source_ip)

        # MITRE : déjà fourni nativement par Wazuh via l'adapter
        # (alert.mitre_technique / alert.mitre_tactic sont déjà remplis,
        # on ne les écrase pas avec le MitreMapper CICIDS)

        alert = scoring_engine.evaluate(alert)
        alert = llm_service.analyze(alert)
        alert_dict = alert_generator.create_alert(alert)
        database.insert_alert(alert_dict)


        processed += 1

        print(
            f"✓ {alert_dict['alert_id']} | "
            f"{alert_dict['attack_type']} | "
            f"{alert_dict['severity']} | "
            f"Score={alert_dict['score']}"
        )

    print("\n")
    print("=" * 70)
    print("SIMULATION WAZUH TERMINEE")
    print("=" * 70)
    print(f"Alertes traitees : {processed}")


if __name__ == "__main__":
    main() 