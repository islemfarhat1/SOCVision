from src.simulator.cicids_simulator import CICIDSSimulator


dataset = "data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"


simulator = CICIDSSimulator(dataset)

simulator.load_dataset()

simulator.show_info()
flow = simulator.create_network_flow(0)

print("\nNetwork Flow créé :")
print(flow)