from src.threat_intelligence.abuseipdb_client import AbuseIPDBClient

client = AbuseIPDBClient()

result = client.check_ip("8.8.8.8")

print(result)