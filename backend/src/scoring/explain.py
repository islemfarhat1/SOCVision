"""
Explication déterministe du score d'une alerte (principes : explainability +
scoring déterministe). Tout vient du moteur de règles, jamais du LLM.

- Alertes récentes : le détail calculé au moment du scoring est stocké
  (colonne score_details) et fait foi.
- Alertes plus anciennes : le détail est recalculé avec les règles actuelles.
  Si le total ne correspond pas au score enregistré, c'est signalé : l'alerte
  a été notée avec une version antérieure des règles.
"""

import ast
import json

from src.scoring import scoring_engine
from src.scoring.scoring_engine import ScoringEngine
from src.scoring.scoring_rules import ATTACK_SCORES

_engine = ScoringEngine()

NO_MITRE = (None, "", "None", "Not identified")


def _parse(raw):
    """ip_reputation / score_details are stored as JSON (older rows: Python repr)."""
    if raw is None or isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        try:
            value = ast.literal_eval(raw)
            return value if isinstance(value, dict) else None
        except (ValueError, SyntaxError):
            return None


def _frequency_rule(count, is_wazuh: bool) -> str:
    if count is None:
        return "no frequency information"
    if is_wazuh:
        for minimum, points in scoring_engine.WAZUH_FREQUENCY_TIERS:
            if count >= minimum:
                return f"{count:,} similar events (≥ {minimum} → +{points})"
        lowest = scoring_engine.WAZUH_FREQUENCY_TIERS[-1][0]
        return f"{count:,} similar event{'s' if count != 1 else ''} (fewer than {lowest} → +0)"
    for above, points in scoring_engine.FLOW_FREQUENCY_TIERS:
        if count > above:
            return f"{count:,} flows of this type (> {above:,} → +{points})"
    lowest = scoring_engine.FLOW_FREQUENCY_TIERS[-1][0]
    return f"{count:,} flows of this type (≤ {lowest:,} → +0)"


def _reputation_detail(rep) -> str:
    if not rep:
        return "no reputation data"
    status = rep.get("assessment_status")
    sources = rep.get("sources") or {}
    if (
        status == "not_applicable"
        or sources.get("External reputation") == "Not applicable"
        or "private" in str(rep.get("reputation", "")).lower()  # older records
    ):
        return "private / internal IP — not checked externally"
    if status == "not_checked" or rep.get("reputation") == "not_checked":
        return "lookup failed — not checked (adds nothing, not treated as clean)"
    label = rep.get("reputation", "unknown")
    partial = " (partial: one source answered)" if status == "partial" else ""
    return f"{label}{partial}"


def explain_score(alert: dict) -> dict:
    """Décomposition du score d'une alerte (dict issu de la base)."""
    attack_type = alert.get("attack_type")
    is_wazuh = (alert.get("source") or "").lower() == "wazuh"
    rep = _parse(alert.get("ip_reputation"))
    mitre = alert.get("mitre")
    has_mitre = mitre not in NO_MITRE
    covered = attack_type in ATTACK_SCORES

    current = {
        "attack_type": ATTACK_SCORES.get(attack_type, 0),
        "frequency": _engine.calculate_frequency_score(alert.get("frequency_count"), event_type="wazuh" if is_wazuh else None),
        "ip_reputation": _engine.calculate_reputation_score(rep),
        "mitre": _engine.calculate_mitre_score(mitre if has_mitre else None),
    }

    stored_details = _parse(alert.get("score_details"))
    if isinstance(stored_details, dict) and all(k in stored_details for k in current):
        points = {k: int(stored_details[k]) for k in current}
        origin = "stored"
    else:
        points = current
        origin = "recomputed"

    total = sum(points.values())
    stored_score = alert.get("score")
    priority = _engine.calculate_priority(total)

    thresholds = scoring_engine.PRIORITY_THRESHOLDS  # highest first
    reached = next(t for t in thresholds if total >= t[0])
    higher = [t for t in thresholds if t[0] > total]
    next_threshold = higher[-1] if higher else None

    factors = [
        {
            "key": "attack_type",
            "label": "Attack type",
            "points": points["attack_type"],
            "detail": attack_type if covered else f"{attack_type} — not covered by the scoring rules",
            "covered": covered,
        },
        {
            "key": "frequency",
            "label": "Frequency",
            "points": points["frequency"],
            "detail": _frequency_rule(alert.get("frequency_count"), is_wazuh),
        },
        {
            "key": "ip_reputation",
            "label": "IP reputation",
            "points": points["ip_reputation"],
            "detail": _reputation_detail(rep),
        },
        {
            "key": "mitre",
            "label": "MITRE ATT&CK",
            "points": points["mitre"],
            "detail": f"technique mapped ({mitre})" if has_mitre else "no technique mapped",
        },
    ]

    return {
        "origin": origin,
        "factors": factors,
        "total": total,
        "priority": priority,
        "threshold": {"priority": reached[1], "min": reached[0]},
        "next_threshold": {"priority": next_threshold[1], "min": next_threshold[0]} if next_threshold else None,
        # All priority boundaries, lowest first, for the scale under the score bar
        "scale": sorted(minimum for minimum, _ in thresholds if minimum > 0),
        "stored_score": stored_score,
        "matches_stored_score": stored_score is None or int(stored_score) == total,
    }
