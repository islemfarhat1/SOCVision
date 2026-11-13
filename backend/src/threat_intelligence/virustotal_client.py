import requests

from config.api_keys import VIRUSTOTAL_API_KEY


class VirusTotalClient:
    """
    Client permettant d'interroger l'API VirusTotal.
    """

    BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"


    def check_ip(self, ip):
        """Retourne les données, ou None en cas d'échec (raison dans self.last_error)."""
        self.last_error = None

        if not VIRUSTOTAL_API_KEY:
            self.last_error = "API key not configured"
            return None

        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }

        url = f"{self.BASE_URL}/{ip}"

        try:

            response = requests.get(
                url,
                headers=headers,
                timeout=10
            )

            if response.status_code != 200:

                self.last_error = f"HTTP {response.status_code}"

                return None

            data = response.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]

            return {

                "engine": "VirusTotal",

                "malicious": stats["malicious"],

                "suspicious": stats["suspicious"],

                "harmless": stats["harmless"],

                "undetected": stats["undetected"]

            }

        except Exception as e:

            self.last_error = f"{type(e).__name__}: {e}"

            return None