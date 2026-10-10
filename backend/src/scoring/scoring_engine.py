from src.scoring.scoring_rules import ATTACK_SCORES


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
            if frequency >= 12:
                return 20
            elif frequency >= 8:
                return 15
            elif frequency >= 5:
                return 10
            elif frequency >= 3:
                return 5
            else:
                return 0

        if frequency > 100000:
            return 20

        elif frequency > 10000:
            return 10

        elif frequency > 1000:
            return 5

        else:
            return 0



    
            



    def calculate_reputation_score(self, reputation):

        """
        Transforme le résultat Threat Intelligence
        en points de criticité SOC.
        """

        if reputation is None:
            return 0


        reputation_value = reputation.get(
            "reputation"
        )


        if reputation_value == "malicious":
            return 20

        elif reputation_value == "suspicious":
            return 10

        else:
            return 0



    def calculate_priority(self, score):

        if score >= 70:
            return "CRITICAL"

        elif score >= 40:
            return "HIGH"

        elif score >= 20:
            return "MEDIUM"

        else:
            return "LOW"
        
    def calculate_mitre_score(self, mitre_technique):


        if mitre_technique:
         return 15

        return 0