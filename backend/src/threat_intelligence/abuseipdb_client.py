import requests

from config.api_keys import ABUSEIPDB_API_KEY


class AbuseIPDBClient:
    """
    Client permettant d'interroger l'API AbuseIPDB.
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def check_ip(self, ip):

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
                print("AbuseIPDB Error:", response.status_code)
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

            print("AbuseIPDB Exception:", e)

            return None