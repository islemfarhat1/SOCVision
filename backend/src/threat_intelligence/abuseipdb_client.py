import requests

from config.api_keys import ABUSEIPDB_API_KEY


class AbuseIPDBClient:
    """
    Client permettant d'interroger l'API AbuseIPDB.
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def check_ip(self, ip):
        """Retourne les données, ou None en cas d'échec (raison dans self.last_error)."""
        self.last_error = None

        if not ABUSEIPDB_API_KEY:
            self.last_error = "API key not configured"
            return None

        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }

        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }

        try:

            response = requests.get(
                self.BASE_URL,
                headers=headers,
                params=params,
                timeout=10
            )

            if response.status_code != 200:
                self.last_error = f"HTTP {response.status_code}"
                return None

            data = response.json()["data"]

            return {

                "engine": "AbuseIPDB",

                "abuseConfidenceScore":
                    data["abuseConfidenceScore"],

                "country":
                    data["countryCode"],

                "isp":
                    data["isp"],

                "domain":
                    data["domain"],

                "totalReports":
                    data["totalReports"]

            }

        except Exception as e:

            self.last_error = f"{type(e).__name__}: {e}"

            return None