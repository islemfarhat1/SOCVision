class MitreMapper:
    """
    Mappe un type d'attaque vers MITRE ATT&CK.
    """

    def __init__(self):

        self.mapping = {

            "DDoS": {
                "technique_id": "T1498",
                "technique_name": "Network Denial of Service",
                "tactic": "Impact"
            },

            "DoS": {
                "technique_id": "T1498",
                "technique_name": "Network Denial of Service",
                "tactic": "Impact"
            },

            "PortScan": {
                "technique_id": "T1046",
                "technique_name": "Network Service Scanning",
                "tactic": "Discovery"
            }
        }


    def get_mapping(self, attack_type):

        return self.mapping.get(
            attack_type,
            None
        )