from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class NetworkFlow:
    """
    Représente un flux réseau extrait depuis une source
    comme CICIDS2017/2018 ou un outil de monitoring.
    """

    flow_id: str
    source_ip: str
    destination_ip: str

    source_port: int
    destination_port: int

    protocol: int

    timestamp: str

    flow_duration: int

    total_fwd_packets: int
    total_backward_packets: int

    flow_bytes_per_second: float
    flow_packets_per_second: float

    label: Optional[str] = None

    raw_features: Optional[Dict] = field(default=None, repr=False)