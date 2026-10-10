import re

from src.llm.prompt_builder import PromptBuilder
from src.llm.openrouter_client import OpenRouterClient
from src.llm.response_parser import ResponseParser

MITRE_PATTERN = re.compile(r"T\d{4}(\.\d{3})?")


class LLMService:
    """
    Orchestration complète du pipeline LLM.
    """

    LLM_PROVIDER = "ollama"
    LLM_MODEL = "qwen2.5:7b"

    def __init__(self):
        self.prompt_builder = PromptBuilder()
        self.client = OpenRouterClient(use_local=True)
        self.parser = ResponseParser()

    def _validate(self, result: dict, alert) -> dict:
        """
        Vérifie et corrige les sorties du LLM avant de les publier.
        Filet de sécurité contre les hallucinations, indépendant du modèle utilisé.
        """
        summary = (result.get("summary") or "Résumé non fourni par le modèle.").strip()
        reasoning = result.get("reasoning") or ""
        ioc_assessment = result.get("ioc_assessment") or ""
        mitre_context = (result.get("mitre_context") or "").strip()
        recommended_action = result.get("recommended_action") or "Aucune recommandation générée - vérification manuelle conseillée."

        confidence = result.get("confidence")
        if not isinstance(confidence, (int, float)) or not (0 <= confidence <= 1):
            confidence = 0.5

        # --- Validation MITRE ---
        print("\n========== VALIDATOR DEBUG ==========")
        print("ENGINE MITRE TECHNIQUE:", repr(alert.mitre_technique))
        print("ENGINE MITRE TACTIC:", repr(alert.mitre_tactic))
        print("LLM MITRE CONTEXT:", repr(mitre_context))
        print("MITRE PATTERN MATCH:", MITRE_PATTERN.search(mitre_context))
        print("=====================================\n")

        if alert.mitre_technique:
            if not mitre_context:
                mitre_context = (
                    f"This alert is mapped to MITRE ATT&CK technique "
                    f"{alert.mitre_technique}."
                )
            elif alert.mitre_technique not in mitre_context:
                mitre_context = f"{alert.mitre_technique}: " + mitre_context
        else:
            if MITRE_PATTERN.search(mitre_context) or "NONE MAPPED" in mitre_context or "do not invent" in mitre_context or not mitre_context:
                mitre_context = "Aucune technique MITRE ATT&CK n'a été mappée par le moteur pour cette alerte."

        # --- Validation recommended_action ---
        forbidden_action_phrases = [
            "no action is recommended",
            "no action required",
            "no action is needed",
            "nothing needs to be done",
            "host is compromised",
            "host may be compromised",
            "ensure that the host is not compromised",
        ]
        if any(phrase in recommended_action.lower() for phrase in forbidden_action_phrases):
            recommended_action = (
                "Review the authentication event and verify whether the "
                "activity is expected for the monitored host."
            )

        # --- Validation summary vs priorité ---
        low_priority_phrases = ["low risk", "likely benign", "false positive", "not a concern"]
        if alert.priority in ("CRITICAL", "HIGH"):
            if any(phrase in summary.lower() for phrase in low_priority_phrases):
                prefix = "Critical alert detected. " if alert.priority == "CRITICAL" else "High-priority alert detected. "
                summary = prefix + summary

        print("FINAL MITRE CONTEXT:", repr(mitre_context))
        print("=====================================\n")

        return {
            "summary": summary,
            "reasoning": reasoning,
            "ioc_assessment": ioc_assessment,
            "mitre_context": mitre_context,
            "recommended_action": recommended_action,
            "confidence": confidence,
        }

    def analyze(self, alert):

        prompt = self.prompt_builder.build(alert)
        response = self.client.generate(prompt)

        print("\n========== RAW RESPONSE ==========")
        print(response)
        print("==================================\n")

        result = self.parser.parse(response)

        if result is None:
            alert.summary = "SOC AI analysis unavailable for this alert."
            alert.reasoning = ""
            alert.ioc_assessment = ""
            alert.mitre_context = ""
            alert.recommended_action = "Manual review required."
            alert.confidence = 0.0
            return alert

        validated = self._validate(result, alert)

        alert.summary = validated["summary"]
        alert.reasoning = validated["reasoning"]
        alert.ioc_assessment = validated["ioc_assessment"]
        alert.mitre_context = validated["mitre_context"]
        alert.recommended_action = validated["recommended_action"]
        alert.confidence = validated["confidence"]

        return alert

    def generate_incident_report(self, ticket: dict, alert: dict) -> str:
        prompt = self.prompt_builder.build_incident_report_prompt(ticket, alert)
        response = self.client.generate(prompt)

        print("\n========== GENERATED REPORT ==========")
        print(response)
        print("======================================\n")

        return response