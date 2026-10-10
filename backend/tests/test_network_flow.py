from src.models.network_flow import NetworkFlow


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


print(flow)