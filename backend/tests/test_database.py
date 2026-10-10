from src.database.database_manager import DatabaseManager



db = DatabaseManager()



ticket = {

    "ticket_id": "INC-00001",
    "created_at": "2026-07-19 21:00:00",
    "severity": "CRITICAL",
    "attack_type": "DDoS",
    "score": 100,
    "source_ip": "172.16.0.1",
    "destination_ip": "192.168.10.50",
    "mitre": "T1498 - Network Denial of Service",
    "explanation": "DDoS attack detected",
    "recommended_action": "Investigate source IP",
    "status": "OPEN"

}


db.insert_ticket(ticket)



tickets = db.get_all_tickets()


print("Tickets enregistrés :")


for t in tickets:
    print(t)