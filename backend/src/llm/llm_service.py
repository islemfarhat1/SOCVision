import re

from src.llm.prompt_builder import PromptBuilder
from src.llm.openrouter_client import OpenRouterClient

REPORT_SYSTEM_PROMPT = (
    "You are a senior SOC analyst writing an incident report. "
    "Answer in Markdown, following exactly the section structure requested. "
    "Never answer in JSON. Use only the evidence provided."
)
REPORT_MAX_TOKENS = 2500
from src.llm.response_parser import ResponseParser

_FENCE = re.compile(r"^\s*```[a-zA-Z]*[ \t]*\n(.*?)\n?```\s*$", re.DOTALL)
_OPEN_FENCE = re.compile(r"^\s*```(?:markdown|md)?[ \t]*\n", re.IGNORECASE)


def strip_code_fence(text: str | None) -> str | None:
    """
    Les modèles entourent souvent le rapport de ```markdown ... ```, ce qui le
    ferait afficher comme un bloc de code. On retire cette enveloppe (même si
    la fermeture manque parce que la réponse a été tronquée).
    """
    if not text:
        return text
    match = _FENCE.match(text)
    if match:
        return match.group(1).strip()
    return _OPEN_FENCE.sub("", text, count=1).strip()

MITRE_PATTERN = re.compile(r"T\d{4}(\.\d{3})?")


class LLMService:
    """
    Orchestration complète du pipeline LLM.
    """

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

        # --- Validation ioc_assessment vs private/internal IP ---
        source_ip = None
        if hasattr(alert, "network_flow") and alert.network_flow:
            source_ip = getattr(alert.network_flow, "source_ip", None)

        is_private_ip = False
        if source_ip:
            import ipaddress
            try:
                ip_obj = ipaddress.ip_address(source_ip)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                    is_private_ip = True
            except ValueError:
                pass

        rep = getattr(alert, "ip_reputation", None) or {}
        sources = rep.get("sources", {})
        rep_status = self.prompt_builder._get_assessment_status(rep or None)
        clean_claims = ["clean", "safe", "benign", "no malicious", "not malicious", "good reputation"]

        if rep_status == "NOT_CHECKED" and not is_private_ip:
            # Lookup TI en échec : le LLM ne doit pas conclure que l'IP est propre.
            if not ioc_assessment or any(p in ioc_assessment.lower() for p in clean_claims):
                ioc_assessment = (
                    "The reputation of the source IP could not be verified: the external "
                    "threat-intelligence services (VirusTotal, AbuseIPDB) did not answer. "
                    "The IP must not be considered clean; re-check its reputation manually."
                )
        elif is_private_ip or sources.get("External reputation") == "Not applicable":
            hallucination_phrases = ["clean according to", "clean on virustotal", "clean in abuseipdb", "virustotal and abuseipdb", "reputation is clean"]
            if any(p in ioc_assessment.lower() for p in hallucination_phrases) or not ioc_assessment:
                ioc_assessment = (
                    "The source IP belongs to a private network and was not evaluated by external "
                    "reputation services. The alert remains critical based on the detected attack "
                    "activity, frequency, and other available security indicators."
                )

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
        alert.llm_provider = self.client.last_provider
        alert.llm_model = self.client.last_model

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

    def generate_incident_report(self, ticket: dict, alert: dict) -> str | None:
        """Retourne le rapport Markdown, ou None si aucun modèle n'a répondu."""
        prompt = self.prompt_builder.build_incident_report_prompt(ticket, alert)
        response = self.client.generate(
            prompt, system_prompt=REPORT_SYSTEM_PROMPT, max_tokens=REPORT_MAX_TOKENS
        )

        print("\n========== GENERATED REPORT ==========")
        print(response)
        print("======================================\n")

        return strip_code_fence(response)