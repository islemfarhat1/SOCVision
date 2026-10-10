from src.threat_intelligence.virustotal_client import VirusTotalClient
from src.threat_intelligence.abuseipdb_client import AbuseIPDBClient


class ReputationChecker:
    """
    Agrège les résultats de plusieurs sources
    de Threat Intelligence.
    """

    def __init__(self):

        self.virustotal = VirusTotalClient()

        self.abuseipdb = AbuseIPDBClient()


    def check_ip(self, ip):
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return {
                    "reputation": "Internal / Private IP",
                    "score": 0,
                    "sources": {
                        "External reputation": "Not applicable"
                    }
                }
        except ValueError:
            pass

        vt = self.virustotal.check_ip(ip)
        abuse = self.abuseipdb.check_ip(ip)

        reputation = self.calculate_reputation(vt, abuse)

        return {
            "reputation": reputation["reputation"],
            "score": reputation["score"],
            "sources": {
                "VirusTotal": vt,
                "AbuseIPDB": abuse
            }
        }


    def calculate_reputation(self, vt, abuse):

        score = 0


        # ----------------------------
        # VirusTotal
        # ----------------------------

        if vt:

            score += min(
                vt["malicious"] * 10 +
                vt["suspicious"] * 5,
                60
            )


        # ----------------------------
        # AbuseIPDB
        # ----------------------------

        if abuse:

            score += abuse["abuseConfidenceScore"] * 0.4


        score = min(
            int(score),
            100
        )


        # ----------------------------
        # Niveau de réputation
        # ----------------------------

        if score >= 70:

            reputation = "malicious"

        elif score >= 30:

            reputation = "suspicious"

        else:

            reputation = "clean"


        return {

            "reputation": reputation,

            "score": score

        }