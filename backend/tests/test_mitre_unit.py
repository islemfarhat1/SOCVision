from src.mitre.mitre_mapping import MitreMapper


def test_mitre_mapping_ddos():
    mapper = MitreMapper()

    result = mapper.get_mapping("DDoS")

    assert result["technique_id"] == "T1498"
    assert result["technique_name"] == "Network Denial of Service"
    assert result["tactic"] == "Impact"
