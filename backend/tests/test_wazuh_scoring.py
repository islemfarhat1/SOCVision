from src.adapters.wazuh_adapter import (
    load_normalized_alerts,
    normalized_to_alert
)

from src.scoring.scoring_engine import ScoringEngine

alerts = load_normalized_alerts("wazuh_lab/normalized")

alert = normalized_to_alert(alerts[0], 1)

engine = ScoringEngine()

engine.evaluate(alert)

print("=" * 40)
print("Attack :", alert.threat_category)
print("Score :", alert.score)
print("Priority :", alert.priority)
print("Details :", alert.score_details)