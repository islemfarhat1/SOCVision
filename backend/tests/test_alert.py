from src.models.network_flow import NetworkFlow
from src.models.alert import Alert


# Création d'un flux réseau simulé
flow = NetworkFlow(
    flow_id="001",
    source_ip="192.168.10.5",
    destination_ip="8.8.8.8",
    source_port=50000,
    destination_port=443,
    protocol=6,
    timestamp="07/07/2017 03:30",
    flow_duration=1000,
    total_fwd_packets=20,
    total_backward_packets=10,
    flow_bytes_per_second=5000,
    flow_packets_per_second=200,
    label="BENIGN"
)


# Création d'une alerte SOC
alert = Alert(
    alert_id="ALT-001",
    network_flow=flow,
    event_type="Network Traffic Event",
    threat_category="DDoS",
    score=80,
    score_details={
        "attack_type": 40,
        "ioc_reputation": 20,
        "mitre_context": 20
    },
    priority="HIGH"
)


print(alert)