import json


class ResponseParser:
    """
    Parse et valide la réponse JSON du LLM.
    """

    MIN_SUMMARY_LENGTH = 30

    def parse(self, response):

        if response is None:
            return None

        # Suppression des éventuels blocs Markdown
        response = (
            response
            .replace("```json", "")
            .replace("```", "")
            .strip()
        )

        # Premier essai
        try:
            return json.loads(response)

        except json.JSONDecodeError as e:

            print("JSON Parsing Error:", e)

        # -----------------------------
        # Tentative de réparation
        # -----------------------------

        repaired = response.rstrip()

        # guillemet manquant
        if repaired.count('"') % 2 != 0:
            repaired += '"'

        # accolades manquantes
        missing = repaired.count("{") - repaired.count("}")

        if missing > 0:
            repaired += "}" * missing

        try:

            result = json.loads(repaired)

        except Exception:

            print("\nImpossible de réparer le JSON.\n")

            print(response)

            return None

        # -----------------------------
        # Validation minimale
        # -----------------------------

        summary = result.get("summary", "")

        if len(summary) < self.MIN_SUMMARY_LENGTH:

            print(
                f"Repair rejected (summary too short: {len(summary)} chars)"
            )

            return None

        # Champs obligatoires

        defaults = {

            "summary": "",

            "reasoning": "",

            "ioc_assessment": "",

            "mitre_context": "",

            "recommended_action": "",

            "confidence": 0.0

        }

        for key, value in defaults.items():

            result.setdefault(key, value)

        print("JSON repaired successfully.")

        return result