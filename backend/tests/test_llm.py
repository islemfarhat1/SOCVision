from src.simulator.cicids_simulator import CICIDSSimulator
from src.utils.alert_builder import AlertBuilder
from src.scoring.scoring_engine import ScoringEngine
from src.analysis.frequency_analyzer import FrequencyAnalyzer
from src.threat_intelligence.reputation_checker import ReputationChecker
from src.mitre.mitre_mapping import MitreMapper
from src.llm.llm_service import LLMService


dataset = "data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"


# Charger dataset
simulator = CICIDSSimulator(dataset)
simulator.load_dataset()


# Chercher une attaque
attack_index = None

for index, row in simulator.data.iterrows():

    if row[" Label"] != "BENIGN":
        attack_index = index
        break


# NetworkFlow
flow = simulator.create_network_flow(
    attack_index
)


# Services
frequency_analyzer = FrequencyAnalyzer(
    simulator.data
)

reputation_checker = ReputationChecker()

mitre_mapper = MitreMapper()


# AlertBuilder
builder = AlertBuilder(
    frequency_analyzer=frequency_analyzer,
    reputation_checker=reputation_checker,
    mitre_mapper=mitre_mapper
)


alert = builder.create_alert(flow)


# Scoring
scoring_engine = ScoringEngine()

alert = scoring_engine.evaluate(alert)



# Analyse IA avec OpenRouter

llm_service = LLMService()

alert = llm_service.analyze(alert)



print(alert)