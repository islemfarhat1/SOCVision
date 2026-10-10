from src.simulator.cicids_simulator import CICIDSSimulator
from src.utils.alert_builder import AlertBuilder
from src.scoring.scoring_engine import ScoringEngine
from src.analysis.frequency_analyzer import FrequencyAnalyzer
from src.threat_intelligence.reputation_checker import ReputationChecker
from src.mitre.mitre_mapping import MitreMapper
from src.llm.prompt_builder import PromptBuilder
from src.llm.llm_client import LLMClient
from src.ticketing.ticket_generator import TicketGenerator


dataset = "data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"


# ==========================
# 1) Charger le dataset
# ==========================

simulator = CICIDSSimulator(dataset)

simulator.load_dataset()


# Chercher une attaque
attack_index = None

for index, row in simulator.data.iterrows():

    if row[" Label"] != "BENIGN":
        attack_index = index
        break


# ==========================
# 2) Network Flow
# ==========================

flow = simulator.create_network_flow(
    attack_index
)


# ==========================
# 3) Création Alert
# ==========================

frequency_analyzer = FrequencyAnalyzer(
    simulator.data
)

reputation_checker = ReputationChecker()

mitre_mapper = MitreMapper()


alert_builder = AlertBuilder(
    frequency_analyzer=frequency_analyzer,
    reputation_checker=reputation_checker,
    mitre_mapper=mitre_mapper
)


alert = alert_builder.create_alert(flow)



# ==========================
# 4) Scoring
# ==========================

scoring_engine = ScoringEngine()

alert = scoring_engine.evaluate(alert)



# ==========================
# 5) Analyse LLM
# ==========================

prompt_builder = PromptBuilder()

prompt = prompt_builder.build_alert_prompt(alert)


llm_client = LLMClient()

response = llm_client.analyze(prompt)



alert.explanation = response["explanation"]

alert.recommended_action = response["recommended_action"]

alert.confidence = response["confidence"]



# ==========================
# 6) Génération Ticket
# ==========================

ticket_generator = TicketGenerator()

ticket = ticket_generator.create_ticket(alert)



# ==========================
# Affichage
# ==========================

print("===== ALERT =====")
print(alert)


print("\n===== TICKET SOC =====")

for key, value in ticket.items():
    print(f"{key}: {value}")