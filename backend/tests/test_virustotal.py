from src.threat_intelligence.virustotal_client import VirusTotalClient

client = VirusTotalClient()

result = client.check_ip("8.8.8.8")

print(result)