from src.models.network_flow import NetworkFlow
from src.models.alert import Alert


class AlertBuilder:
    """
    Transforme un événement réseau (NetworkFlow)
    en alerte SOC.
    """

    def __init__(
        self,
        frequency_analyzer=None,
        reputation_checker=None,
        mitre_mapper=None
    ):
        self.counter = 0
        self.frequency_analyzer = frequency_analyzer
        self.reputation_checker = reputation_checker
        self.mitre_mapper = mitre_mapper


    def create_alert(self, flow: NetworkFlow) -> Alert:

        self.counter += 1

        if flow.label != "BENIGN":
            event_type = "Network Attack"
            threat_category = flow.label

        else:
            event_type = "Normal Traffic"
            threat_category = None


        alert = Alert(
            alert_id=f"ALT-{self.counter:05d}",
            network_flow=flow,
            event_type=event_type,
            threat_category=threat_category
        )


        # Enrichissement Threat Intelligence
        if self.reputation_checker:

            alert.ip_reputation = self.reputation_checker.check_ip(
                flow.source_ip
            )


        # Enrichissement fréquence
        if self.frequency_analyzer and threat_category:

            alert.frequency_count = self.frequency_analyzer.get_frequency(
                flow.source_ip,
                threat_category
            )


        # Enrichissement MITRE
        if self.mitre_mapper and threat_category:

            mitre_info = self.mitre_mapper.get_mapping(
                threat_category
            )

            if mitre_info:

                alert.mitre_tactic = mitre_info["tactic"]

                alert.mitre_technique = (
                    f'{mitre_info["technique_id"]} - '
                    f'{mitre_info["technique_name"]}'
                )


        return alert