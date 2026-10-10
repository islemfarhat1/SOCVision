from src.simulator.cicids_simulator import CICIDSSimulator
from src.analysis.frequency_analyzer import FrequencyAnalyzer
from src.threat_intelligence.reputation_checker import ReputationChecker
from src.mitre.mitre_mapping import MitreMapper
from src.utils.alert_builder import AlertBuilder
from src.scoring.scoring_engine import ScoringEngine
from src.llm.llm_service import LLMService
from src.ticketing.alert_generator import AlertGenerator
from src.database.database_manager import DatabaseManager


DATASET = "data/raw"          # ← dossier entier maintenant, plus un seul fichier
PER_LABEL = 2                  # ← nombre d'alertes max par type d'attaque

def main():

    print("=" * 70)
    print("SOC AI PLATFORM")
    print("=" * 70)

    # ==========================================================
    # Chargement Dataset (multi-fichiers)
    # ==========================================================

    simulator = CICIDSSimulator(DATASET)
    simulator.load_dataset()

    print("[OK] Dataset loaded")
    simulator.show_info()

    # ==========================================================
    # Échantillonnage stratifié (remplace le "20 premières lignes")
    # ==========================================================

    sample_indexes = simulator.stratified_sample(per_label=PER_LABEL)

    # ==========================================================
    # Initialisation des services (UNE seule fois)
    # ==========================================================

    frequency_analyzer = FrequencyAnalyzer(simulator.data)
    reputation_checker = ReputationChecker()
    mitre_mapper = MitreMapper()

    alert_builder = AlertBuilder(
        frequency_analyzer=frequency_analyzer,
        reputation_checker=reputation_checker,
        mitre_mapper=mitre_mapper
    )

    scoring_engine = ScoringEngine()
    llm_service = LLMService()
    database = DatabaseManager()
    alert_generator = AlertGenerator()

    database.clear_alerts()

    print("[OK] Services initialized")

    # ==========================================================
    # Traitement des attaques (échantillon diversifié)
    # ==========================================================

    processed = 0
    total = len(sample_indexes)

    for index in sample_indexes:

        print(f"\nProcessing Alert {processed + 1}/{total}")

        flow = simulator.create_network_flow(index)
        alert = alert_builder.create_alert(flow)
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

    # ==========================================================
    # Résumé
    # ==========================================================

    print("\n")
    print("=" * 70)
    print("SIMULATION FINISHED")
    print("=" * 70)
    print(f"Processed alerts : {processed}")
    print("Alerts stored successfully.")
    print("SQLite database updated.")
    print("Dashboard ready.")


if __name__ == "__main__":
    main()