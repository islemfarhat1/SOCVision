from src.simulator.cicids_simulator import CICIDSSimulator
from src.analysis.frequency_analyzer import FrequencyAnalyzer


dataset_path = "data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"


simulator = CICIDSSimulator(dataset_path)

simulator.load_dataset()


analyzer = FrequencyAnalyzer(
    simulator.data
)


frequency = analyzer.get_frequency(
    "172.16.0.1",
    "DDoS"
)


print("Fréquence trouvée :", frequency)