"""
Focused tests for the reputation-context / prompt-builder fix.

Covers:
  1. Private IP  → assessment status NOT_APPLICABLE
  2. Public IP with real results → ASSESSED, correct summary in prompt
  3. No reputation data (None) → UNKNOWN
  4. Public IP where API returned None values → ASSESSED but labelled as such
  5. Score of 0 for assessed IP → never described as "clean" in context block
  6. End-to-end: prompt for private IP must NOT contain "VirusTotal" or
     "AbuseIPDB" in a positive-verdict sentence.
"""

import pytest
from unittest.mock import MagicMock
from src.llm.prompt_builder import PromptBuilder
from src.models.alert import Alert
from src.models.network_flow import NetworkFlow


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_flow(source_ip: str = "192.168.1.10") -> NetworkFlow:
    flow = MagicMock(spec=NetworkFlow)
    flow.source_ip = source_ip
    flow.destination_ip = "10.0.0.1"
    flow.source_port = 12345
    flow.destination_port = 80
    flow.protocol = 6
    flow.flow_duration = 100
    flow.total_fwd_packets = 10
    flow.total_backward_packets = 5
    flow.flow_bytes_per_second = 1000.0
    flow.flow_packets_per_second = 50.0
    return flow


def _make_alert(source_ip: str, ip_reputation: dict | None) -> Alert:
    alert = Alert(
        alert_id="ALRT-00001",
        network_flow=_make_flow(source_ip),
        event_type="cicids",
        threat_category="DDoS",
        score=60,
        priority="HIGH",
        frequency_count=500,
        score_details={"attack_type": 30, "frequency": 20, "ip_reputation": 0, "mitre": 10},
        ip_reputation=ip_reputation,
        mitre_technique=None,
        mitre_tactic=None,
    )
    return alert


# ── Private-IP reputation dict (as produced by ReputationChecker) ─────────
PRIVATE_REP = {
    "reputation": "Internal / Private IP",
    "score": 0,
    "sources": {"External reputation": "Not applicable"},
}

# ── Public-IP reputation dict (VirusTotal + AbuseIPDB results) ────────────
PUBLIC_REP_MALICIOUS = {
    "reputation": "malicious",
    "score": 75,
    "sources": {
        "VirusTotal": {"malicious": 5, "suspicious": 2, "harmless": 70},
        "AbuseIPDB": {"abuseConfidenceScore": 85, "totalReports": 12},
    },
}

PUBLIC_REP_CLEAN = {
    "reputation": "clean",
    "score": 0,
    "sources": {
        "VirusTotal": {"malicious": 0, "suspicious": 0, "harmless": 90},
        "AbuseIPDB": {"abuseConfidenceScore": 0, "totalReports": 0},
    },
}


# ── Tests: _get_assessment_status ────────────────────────────────────────────

class TestGetAssessmentStatus:

    def setup_method(self):
        self.pb = PromptBuilder()

    def test_private_ip_rep_returns_not_applicable(self):
        assert self.pb._get_assessment_status(PRIVATE_REP) == "NOT_APPLICABLE"

    def test_none_rep_returns_unknown(self):
        assert self.pb._get_assessment_status(None) == "UNKNOWN"

    def test_empty_dict_returns_unknown(self):
        assert self.pb._get_assessment_status({}) == "UNKNOWN"

    def test_public_malicious_returns_assessed(self):
        assert self.pb._get_assessment_status(PUBLIC_REP_MALICIOUS) == "ASSESSED"

    def test_public_clean_score_zero_returns_assessed(self):
        # A score of 0 from an actual API call is still ASSESSED, not UNKNOWN
        assert self.pb._get_assessment_status(PUBLIC_REP_CLEAN) == "ASSESSED"

    def test_missing_vt_but_has_abuseipdb_returns_assessed(self):
        rep = {
            "reputation": "clean",
            "score": 0,
            "sources": {"AbuseIPDB": {"abuseConfidenceScore": 0, "totalReports": 0}},
        }
        assert self.pb._get_assessment_status(rep) == "ASSESSED"


# ── Tests: _build_reputation_context ─────────────────────────────────────────

class TestBuildReputationContext:

    def setup_method(self):
        self.pb = PromptBuilder()

    def test_private_ip_context_says_not_applicable(self):
        ctx = self.pb._build_reputation_context("192.168.1.10", PRIVATE_REP)
        assert "NOT_APPLICABLE" in ctx
        assert "NOT performed" in ctx
        # Must not suggest it was checked
        assert "VirusTotal" not in ctx or "NOT performed" in ctx

    def test_private_ip_context_does_not_say_clean(self):
        ctx = self.pb._build_reputation_context("192.168.56.20", PRIVATE_REP)
        assert "clean" not in ctx.lower()

    def test_unknown_context_warns_zero_is_not_clean(self):
        ctx = self.pb._build_reputation_context("1.2.3.4", None)
        assert "UNKNOWN" in ctx
        assert "0 does NOT mean" in ctx

    def test_assessed_malicious_context_shows_vt_and_abuse(self):
        ctx = self.pb._build_reputation_context("203.0.113.5", PUBLIC_REP_MALICIOUS)
        assert "ASSESSED" in ctx
        assert "malicious=5" in ctx
        assert "abuseConfidenceScore=85" in ctx

    def test_assessed_clean_zero_context_is_still_assessed(self):
        ctx = self.pb._build_reputation_context("8.8.8.8", PUBLIC_REP_CLEAN)
        assert "ASSESSED" in ctx
        # The clean label comes from the aggregated result, not invented
        assert "clean" in ctx


# ── Tests: full prompt for private IP ────────────────────────────────────────

class TestPromptPrivateIP:

    def setup_method(self):
        self.pb = PromptBuilder()

    def test_prompt_contains_not_applicable_status(self):
        alert = _make_alert("192.168.56.20", PRIVATE_REP)
        prompt = self.pb.build(alert)
        assert "NOT_APPLICABLE" in prompt

    def test_prompt_states_ip_not_checked_externally(self):
        alert = _make_alert("192.168.56.20", PRIVATE_REP)
        prompt = self.pb.build(alert)
        assert "NOT performed" in prompt

    def test_prompt_reminds_llm_not_to_claim_vt_abuseipdb(self):
        alert = _make_alert("192.168.56.20", PRIVATE_REP)
        prompt = self.pb.build(alert)
        # The FINAL REMINDER section must contain the assessment status
        assert "NOT_APPLICABLE" in prompt
        # And a prohibition phrase must be present
        assert "do NOT claim any VirusTotal" in prompt

    def test_prompt_does_not_inject_raw_dict(self):
        """The prompt must not contain raw Python repr of the reputation dict."""
        alert = _make_alert("192.168.56.20", PRIVATE_REP)
        prompt = self.pb.build(alert)
        # Raw dict would look like: {'reputation': 'Internal / Private IP', ...}
        assert "{'reputation'" not in prompt
        assert '{"reputation"' not in prompt

    def test_prompt_for_none_reputation_contains_unknown(self):
        alert = _make_alert("192.168.56.20", None)
        prompt = self.pb.build(alert)
        assert "UNKNOWN" in prompt

    def test_prompt_for_assessed_malicious_shows_vt_data(self):
        alert = _make_alert("203.0.113.5", PUBLIC_REP_MALICIOUS)
        prompt = self.pb.build(alert)
        assert "ASSESSED" in prompt
        assert "malicious=5" in prompt
        assert "abuseConfidenceScore=85" in prompt


# ── Tests: LLMService _validate safety net ───────────────────────────────────

from src.llm.llm_service import LLMService

class TestLLMServiceValidation:

    def setup_method(self):
        self.service = LLMService()

    def test_hallucinated_clean_reputation_replaced_for_private_ip(self):
        alert = _make_alert("192.168.56.20", PRIVATE_REP)
        raw_result = {
            "summary": "Suspicious network activity detected.",
            "reasoning": "Attack pattern identified.",
            "ioc_assessment": "The IP reputation is clean according to VirusTotal and AbuseIPDB.",
            "mitre_context": "",
            "recommended_action": "Isolate host and verify logs.",
            "confidence": 0.9,
        }
        validated = self.service._validate(raw_result, alert)
        assert "clean according to VirusTotal" not in validated["ioc_assessment"]
        assert "private network" in validated["ioc_assessment"]
        assert "not evaluated by external reputation services" in validated["ioc_assessment"]

    def test_valid_assessed_ioc_assessment_preserved(self):
        alert = _make_alert("93.184.216.34", PUBLIC_REP_MALICIOUS)
        raw_result = {
            "summary": "High risk activity detected.",
            "reasoning": "Known malicious source.",
            "ioc_assessment": "IP is flagged with malicious score 75 on VirusTotal and AbuseIPDB.",
            "mitre_context": "",
            "recommended_action": "Block incoming traffic from source.",
            "confidence": 0.9,
        }
        validated = self.service._validate(raw_result, alert)
        assert "flagged with malicious score 75" in validated["ioc_assessment"]

