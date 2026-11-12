"""
Tests unitaires du ReputationChecker (sans appel réseau).

Règle vérifiée : une source de Threat Intelligence qui ne répond pas
reste "not_checked" et n'est jamais transformée en résultat "clean".
"""

from src.threat_intelligence.reputation_checker import ReputationChecker
from src.scoring.scoring_engine import ScoringEngine
from src.llm.prompt_builder import PromptBuilder


class FakeClient:
    def __init__(self, result=None, error=None, raises=False):
        self.result = result
        self.error = error
        self.raises = raises
        self.last_error = None

    def check_ip(self, ip):
        if self.raises:
            raise RuntimeError("boom")
        self.last_error = self.error
        return self.result


VT_CLEAN = {"engine": "VirusTotal", "malicious": 0, "suspicious": 0, "harmless": 80, "undetected": 10}
VT_MALICIOUS = {"engine": "VirusTotal", "malicious": 6, "suspicious": 1, "harmless": 10, "undetected": 5}
ABUSE_CLEAN = {"engine": "AbuseIPDB", "abuseConfidenceScore": 0, "country": "US",
               "isp": "x", "domain": "x", "totalReports": 0}

PUBLIC_IP = "8.8.8.8"


def make_checker(vt, abuse):
    checker = ReputationChecker.__new__(ReputationChecker)
    checker.virustotal = vt
    checker.abuseipdb = abuse
    return checker


def test_private_ip_is_not_applicable():
    checker = make_checker(FakeClient(VT_CLEAN), FakeClient(ABUSE_CLEAN))
    rep = checker.check_ip("192.168.1.10")
    assert rep["assessment_status"] == "not_applicable"
    assert rep["sources"] == {"External reputation": "Not applicable"}


def test_all_sources_failed_is_not_checked_not_clean():
    checker = make_checker(FakeClient(None, error="HTTP 429"), FakeClient(None, error="Timeout"))
    rep = checker.check_ip(PUBLIC_IP)

    assert rep["assessment_status"] == "not_checked"
    assert rep["reputation"] == "not_checked"
    assert rep["reputation"] != "clean"
    assert rep["score"] is None
    assert rep["sources"]["VirusTotal"]["status"] == "not_checked"
    assert rep["sources"]["VirusTotal"]["error"] == "HTTP 429"
    assert rep["sources"]["AbuseIPDB"]["error"] == "Timeout"


def test_client_exception_is_not_checked():
    checker = make_checker(FakeClient(raises=True), FakeClient(raises=True))
    rep = checker.check_ip(PUBLIC_IP)
    assert rep["assessment_status"] == "not_checked"
    assert "RuntimeError" in rep["sources"]["VirusTotal"]["error"]


def test_partial_failure_keeps_failed_source_marked():
    checker = make_checker(FakeClient(VT_MALICIOUS), FakeClient(None, error="HTTP 500"))
    rep = checker.check_ip(PUBLIC_IP)

    assert rep["assessment_status"] == "partial"
    assert rep["sources"]["VirusTotal"]["status"] == "ok"
    assert rep["sources"]["AbuseIPDB"]["status"] == "not_checked"
    # score calculé uniquement avec VirusTotal : 6*10 + 1*5 plafonné à 60
    assert rep["score"] == 60


def test_complete_assessment_has_lookup_times():
    checker = make_checker(FakeClient(VT_CLEAN), FakeClient(ABUSE_CLEAN))
    rep = checker.check_ip(PUBLIC_IP)

    assert rep["assessment_status"] == "complete"
    assert rep["reputation"] == "clean"
    assert rep["checked_at"]
    for source in rep["sources"].values():
        assert source["status"] == "ok"
        assert source["checked_at"]


def test_not_checked_adds_no_reputation_points():
    assert ScoringEngine().calculate_reputation_score({"reputation": "not_checked"}) == 0


# ── Prompt LLM ───────────────────────────────────────────────────────────────

def test_prompt_status_for_failed_lookups():
    checker = make_checker(FakeClient(None, error="HTTP 429"), FakeClient(None, error="Timeout"))
    rep = checker.check_ip(PUBLIC_IP)
    pb = PromptBuilder()

    assert pb._get_assessment_status(rep) == "NOT_CHECKED"
    ctx = pb._build_reputation_context(PUBLIC_IP, rep)
    assert "NOT_CHECKED" in ctx
    assert "Aggregated Reputation: clean" not in ctx


def test_prompt_status_for_legacy_record_with_none_sources():
    """Anciens enregistrements : {"VirusTotal": None, "AbuseIPDB": None} avec 'clean'."""
    legacy = {"reputation": "clean", "score": 0, "sources": {"VirusTotal": None, "AbuseIPDB": None}}
    assert PromptBuilder()._get_assessment_status(legacy) == "NOT_CHECKED"


def test_prompt_partial_marks_missing_source():
    checker = make_checker(FakeClient(VT_CLEAN), FakeClient(None, error="HTTP 500"))
    rep = checker.check_ip(PUBLIC_IP)
    ctx = PromptBuilder()._build_reputation_context(PUBLIC_IP, rep)

    assert "ASSESSED" in ctx
    assert "PARTIAL" in ctx
    assert "AbuseIPDB: NOT CHECKED" in ctx
