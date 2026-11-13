"""Tests du moteur de scoring : points par facteur et seuils de priorité (valeurs limites)."""

import pytest

from src.scoring.scoring_engine import ScoringEngine

engine = ScoringEngine()


@pytest.mark.parametrize("count, points", [
    (None, 0), (0, 0), (2, 0), (3, 5), (4, 5), (5, 10), (7, 10), (8, 15), (11, 15), (12, 20), (50, 20),
])
def test_wazuh_frequency_tiers(count, points):
    assert engine.calculate_frequency_score(count, event_type="wazuh") == points


@pytest.mark.parametrize("count, points", [
    (0, 0), (1000, 0), (1001, 5), (10000, 5), (10001, 10), (100000, 10), (100001, 20),
])
def test_flow_frequency_tiers(count, points):
    assert engine.calculate_frequency_score(count) == points


@pytest.mark.parametrize("reputation, points", [
    (None, 0),
    ({"reputation": "malicious"}, 20),
    ({"reputation": "suspicious"}, 10),
    ({"reputation": "clean"}, 0),
    ({"reputation": "not_checked"}, 0),
])
def test_reputation_points(reputation, points):
    assert engine.calculate_reputation_score(reputation) == points


@pytest.mark.parametrize("score, priority", [
    (0, "LOW"), (19, "LOW"), (20, "MEDIUM"), (39, "MEDIUM"), (40, "HIGH"), (69, "HIGH"), (70, "CRITICAL"), (100, "CRITICAL"),
])
def test_priority_thresholds(score, priority):
    assert engine.calculate_priority(score) == priority


def test_mitre_points():
    assert engine.calculate_mitre_score("T1110.001") == 15
    assert engine.calculate_mitre_score(None) == 0
