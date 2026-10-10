import requests

from config.api_keys import VIRUSTOTAL_API_KEY


class VirusTotalClient:
    """
    Client permettant d'interroger l'API VirusTotal.
    """

    BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"


    def check_ip(self, ip):

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

            print("VirusTotal Error :", e)

            return None