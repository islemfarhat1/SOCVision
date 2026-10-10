from src.simulator.cicids_simulator import CICIDSSimulator
from src.utils.alert_builder import AlertBuilder
from src.analysis.frequency_analyzer import FrequencyAnalyzer
from src.threat_intelligence.reputation_checker import ReputationChecker
from src.mitre.mitre_mapping import MitreMapper

dataset_path = "data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"


# Charger dataset
simulator = CICIDSSimulator(dataset_path)
mitre_mapper = MitreMapper()

simulator.load_dataset()
reputation_checker = ReputationChecker()


# Chercher une attaque
attack_index = None

for index, row in simulator.data.iterrows():

    if row[" Label"] != "BENIGN":
        attack_index = index
        break


# Créer NetworkFlow
flow = simulator.create_network_flow(
    attack_index
)


# Créer FrequencyAnalyzer
frequency_analyzer = FrequencyAnalyzer(
    simulator.data
)


# Créer AlertBuilder avec l'analyseur
builder = AlertBuilder(
    frequency_analyzer,
    reputation_checker,
    mitre_mapper
)


# Générer l'alerte
alert = builder.create_alert(flow)


print("Alert générée :")
print(alert)