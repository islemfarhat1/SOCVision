from src.simulator.cicids_simulator import CICIDSSimulator
from src.analysis.frequency_analyzer import FrequencyAnalyzer
from src.threat_intelligence.reputation_checker import ReputationChecker
from src.mitre.mitre_mapping import MitreMapper
from src.utils.alert_builder import AlertBuilder
from src.scoring.scoring_engine import ScoringEngine
from src.llm.prompt_builder import PromptBuilder

dataset = "data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

# Charger le dataset
simulator = CICIDSSimulator(dataset)
simulator.load_dataset()

# Chercher la première attaque
attack_index = None

for index, row in simulator.data.iterrows():
    if row[" Label"] != "BENIGN":
        attack_index = index
        break

# Créer le NetworkFlow
flow = simulator.create_network_flow(attack_index)

# Services
frequency_analyzer = FrequencyAnalyzer(simulator.data)
reputation_checker = ReputationChecker()
mitre_mapper = MitreMapper()

# Construire l'alerte
builder = AlertBuilder(
    frequency_analyzer=frequency_analyzer,
    reputation_checker=reputation_checker,
    mitre_mapper=mitre_mapper
)

alert = builder.create_alert(flow)

# Calcul du score
scoring = ScoringEngine()
alert = scoring.evaluate(alert)

# Génération du prompt
prompt_builder = PromptBuilder()

prompt = prompt_builder.build_alert_prompt(alert)
response = llm.analyze(prompt)

alert.explanation = response["explanation"]
alert.recommended_action = response["recommended_action"]
alert.confidence = response["confidence"]

print(prompt)