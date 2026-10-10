import requests
from config.settings import N8N_WEBHOOK_URL


def notify_n8n(ticket: dict):
    """Envoie le ticket à n8n si sa sévérité justifie une notification."""
    if ticket.get("severity") not in ("CRITICAL", "HIGH"):
        return

    try:
        payload = {
            "ticket_id": ticket["ticket_id"],
            "incident_title": ticket["incident_title"],
            "severity": ticket["severity"],
            "attack_type": ticket["attack_type"],
            "score": ticket["score"],
            "source_ip": ticket["source_ip"],
            "destination_ip": ticket["destination_ip"],
            "summary": ticket.get("summary"),
            "recommended_action": ticket.get("recommended_action"),
            "source": ticket.get("source"),
            "assigned_to": ticket.get("assigned_to"),
            "investigation_notes": ticket.get("investigation_notes"),
        }
        response = requests.post(N8N_WEBHOOK_URL, json=payload, timeout=5)
        print(f"[n8n] Notification envoyee pour {ticket['ticket_id']} : {response.status_code}")
    except requests.RequestException as e:
        print(f"[n8n] Echec de notification pour {ticket['ticket_id']} : {e}")