import ipaddress
from datetime import datetime, timezone

from src.threat_intelligence.virustotal_client import VirusTotalClient
from src.threat_intelligence.abuseipdb_client import AbuseIPDBClient


# Statuts d'évaluation (champ "assessment_status")
NOT_APPLICABLE = "not_applicable"  # IP privée : aucune requête externe
COMPLETE = "complete"              # toutes les sources ont répondu
PARTIAL = "partial"                # au moins une source a échoué
NOT_CHECKED = "not_checked"        # aucune source n'a répondu

# Statuts par source
SOURCE_OK = "ok"
SOURCE_NOT_CHECKED = "not_checked"


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ReputationChecker:
    """
    Agrège les résultats de plusieurs sources de Threat Intelligence.

    Règle importante : une source qui n'a pas répondu (timeout, quota,
    clé absente...) est marquée "not_checked" et n'est JAMAIS interprétée
    comme un résultat "clean". Chaque source garde l'heure de sa requête.
    """

    def __init__(self):
        self.virustotal = VirusTotalClient()
        self.abuseipdb = AbuseIPDBClient()

    def check_ip(self, ip):
        checked_at = _now_utc()

        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return {
                    "reputation": "Internal / Private IP",
                    "score": 0,
                    "assessment_status": NOT_APPLICABLE,
                    "checked_at": checked_at,
                    "sources": {
                        "External reputation": "Not applicable"
                    }
                }
        except ValueError:
            pass

        sources = {
            "VirusTotal": self._lookup("VirusTotal", self.virustotal, ip),
            "AbuseIPDB": self._lookup("AbuseIPDB", self.abuseipdb, ip),
        }

        ok_count = sum(1 for s in sources.values() if s["status"] == SOURCE_OK)

        if ok_count == 0:
            return {
                "reputation": NOT_CHECKED,
                "score": None,
                "assessment_status": NOT_CHECKED,
                "checked_at": checked_at,
                "sources": sources,
            }

        vt = sources["VirusTotal"] if sources["VirusTotal"]["status"] == SOURCE_OK else None
        abuse = sources["AbuseIPDB"] if sources["AbuseIPDB"]["status"] == SOURCE_OK else None
        reputation = self.calculate_reputation(vt, abuse)

        return {
            "reputation": reputation["reputation"],
            "score": reputation["score"],
            "assessment_status": COMPLETE if ok_count == len(sources) else PARTIAL,
            "checked_at": checked_at,
            "sources": sources,
        }

    @staticmethod
    def _lookup(engine: str, client, ip) -> dict:
        """Interroge une source et renvoie toujours un dict avec statut + heure."""
        checked_at = _now_utc()
        try:
            result = client.check_ip(ip)
            error = getattr(client, "last_error", None)
        except Exception as e:  # filet de sécurité : un client ne doit pas casser le pipeline
            result, error = None, f"{type(e).__name__}: {e}"

        if result is None:
            return {
                "engine": engine,
                "status": SOURCE_NOT_CHECKED,
                "checked_at": checked_at,
                "error": error or "No response",
            }

        return {**result, "engine": engine, "status": SOURCE_OK, "checked_at": checked_at}

    def calculate_reputation(self, vt, abuse):
        """
        Calcule le score à partir des sources qui ont répondu uniquement.
        Les sources absentes (None) ne contribuent pas au score.
        """
        score = 0

        if vt:
            score += min(vt["malicious"] * 10 + vt["suspicious"] * 5, 60)

        if abuse:
            score += abuse["abuseConfidenceScore"] * 0.4

        score = min(int(score), 100)

        if score >= 70:
            reputation = "malicious"
        elif score >= 30:
            reputation = "suspicious"
        else:
            reputation = "clean"

        return {"reputation": reputation, "score": score}
