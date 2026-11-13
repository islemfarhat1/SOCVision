from src.scoring.scoring_rules import ATTACK_SCORES

# Points per factor. Exposed by GET /api/system/status so the UI shows the real model.
# (minimum count, points), checked from the highest tier down
WAZUH_FREQUENCY_TIERS = [(12, 20), (8, 15), (5, 10), (3, 5)]
# (count strictly above, points) for the CICIDS2017 flows
FLOW_FREQUENCY_TIERS = [(100000, 20), (10000, 10), (1000, 5)]
REPUTATION_POINTS = {"malicious": 20, "suspicious": 10}
MITRE_POINTS = 15
# (minimum score, priority), checked from the highest down
PRIORITY_THRESHOLDS = [(70, "CRITICAL"), (40, "HIGH"), (20, "MEDIUM"), (0, "LOW")]


class ScoringEngine:
    """
    Moteur de scoring déterministe.
    Analyse une alerte et calcule sa criticité.
    """


    def evaluate(self, alert):

        attack_type = alert.threat_category


        # 1) Score type d'attaque
        attack_score = ATTACK_SCORES.get(
            attack_type,
            0
        )


        # 2) Score fréquence
        frequency_score = self.calculate_frequency_score(
            alert.frequency_count,
            event_type=alert.event_type
        )


        # 3) Score réputation IP
        reputation_score = self.calculate_reputation_score(
            alert.ip_reputation
        )
        # 4) Score MITRE
        mitre_score = self.calculate_mitre_score(
            alert.mitre_technique
        )


        # Score total
        alert.score = (
            attack_score
            + frequency_score
            + reputation_score
            + mitre_score
        )


        # Détails pour expliquer le score
        alert.score_details = {
            "attack_type": attack_score,
            "frequency": frequency_score,
            "ip_reputation": reputation_score,
            "mitre": mitre_score
        }


        # Priorité SOC
        alert.priority = self.calculate_priority(
            alert.score
        )


        return alert
    def calculate_frequency_score(self, frequency, event_type=None):

        if frequency is None:
            return 0

        if event_type == "wazuh":
            for minimum, points in WAZUH_FREQUENCY_TIERS:
                if frequency >= minimum:
                    return points
            return 0

        for above, points in FLOW_FREQUENCY_TIERS:
            if frequency > above:
                return points
        return 0

    def calculate_reputation_score(self, reputation):
        """
        Transforme le résultat Threat Intelligence en points de criticité SOC.
        "clean", "not_checked" (TI indisponible) et IP privée : aucun point.
        Un lookup en échec n'ajoute rien, mais n'est jamais traité comme "clean"
        ailleurs dans le pipeline (prompt LLM, affichage).
        """
        if reputation is None:
            return 0
        return REPUTATION_POINTS.get(reputation.get("reputation"), 0)

    def calculate_priority(self, score):
        for minimum, priority in PRIORITY_THRESHOLDS:
            if score >= minimum:
                return priority
        return "LOW"

    def calculate_mitre_score(self, mitre_technique):
        return MITRE_POINTS if mitre_technique else 0
