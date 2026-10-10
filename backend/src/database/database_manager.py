import sqlite3
import pandas as pd
from datetime import datetime


class DatabaseManager:
    """
    Gestionnaire SQLite pour le SOC (Alertes et Tickets).
    """

    def __init__(self, db_path="database/soc_alerts.db"):
        self.db_path = db_path
        self.create_tables()

    def create_tables(self):
        connection = sqlite3.connect(self.db_path)
        cursor = connection.cursor()

        # Table des alertes (anciennement tickets)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT,
            incident_title TEXT,
            created_at TEXT,
            severity TEXT,
            attack_type TEXT,
            score INTEGER,
            source_ip TEXT,
            destination_ip TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            protocol INTEGER,
            frequency_count INTEGER,
            mitre_tactic TEXT,
            mitre TEXT,
            ip_reputation TEXT,
            summary TEXT,
            reasoning TEXT,
            ioc_assessment TEXT,
            mitre_context TEXT,
            recommended_action TEXT,
            confidence REAL,
            source TEXT,
            llm_provider TEXT,
            llm_model TEXT,
            status TEXT,
            assigned_to TEXT,
            investigation_notes TEXT,
            classification TEXT,
            reviewed_by TEXT,
            reviewed_at TEXT
        )
        """)

        # Add wazuh_event_id dynamically if it doesn't exist
        cursor.execute("PRAGMA table_info(alerts)")
        columns = [info[1] for info in cursor.fetchall()]
        if "wazuh_event_id" not in columns:
            cursor.execute("ALTER TABLE alerts ADD COLUMN wazuh_event_id TEXT")

        # Nouvelle table des tickets
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id TEXT UNIQUE NOT NULL,
            alert_id TEXT NOT NULL,
            assigned_to TEXT,
            status TEXT DEFAULT 'OPEN',
            comments TEXT,
            created_at TEXT
        )
        """)

        # Nouvelle table des rapports d'incident (audit et versioning)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id TEXT NOT NULL,
            generated_by TEXT NOT NULL,
            generated_at TEXT NOT NULL,
            content TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1
        )
        """)

        # Table des utilisateurs SOC
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL,
            password_hash TEXT
        )
        """)

        # Seed users
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            import bcrypt
            hashed = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode("utf-8")
            default_users = [
                ("ahmed.salem",    "Ahmed Salem",      "SOC_L1",  hashed),
                ("sarra.bannour",  "Sarra Bannour",    "SOC_L1",  hashed),
                ("ala.mabrouk",    "Ala Mabrouk",      "SOC_L2",  hashed),
                ("ahlem.benahmed", "Ahlem Ben Ahmed",  "SOC_L2",  hashed),
                ("youssef.gharbi", "Youssef Gharbi",   "SOC_L3",  hashed),
                ("mariem.trabelsi","Mariem Trabelsi",  "MANAGER", hashed),
                ("karim.bouazizi", "Karim Bouazizi",   "ADMIN",   hashed),
            ]
            cursor.executemany(
                "INSERT INTO users (username, full_name, role, password_hash) VALUES (?, ?, ?, ?)",
                default_users
            )

        connection.commit()
        connection.close()


    def check_wazuh_event_exists(self, wazuh_event_id: str) -> bool:
        if not wazuh_event_id:
            return False
        connection = sqlite3.connect(self.db_path)
        cursor = connection.cursor()
        cursor.execute("SELECT 1 FROM alerts WHERE wazuh_event_id = ?", (wazuh_event_id,))
        exists = cursor.fetchone() is not None
        connection.close()
        return exists

    # ------------------ ALERTS ------------------

    def insert_alert(self, alert):
        connection = sqlite3.connect(self.db_path)
        cursor = connection.cursor()

        cursor.execute("""
        INSERT INTO alerts (
            wazuh_event_id, alert_id, incident_title, created_at, severity, attack_type, score,
            source_ip, destination_ip, source_port, destination_port,
            protocol, frequency_count,
            mitre_tactic, mitre, ip_reputation,
            summary, reasoning, ioc_assessment, mitre_context,
            recommended_action, confidence, source,
            llm_provider, llm_model, status, assigned_to, investigation_notes,
            classification, reviewed_by, reviewed_at
        )
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            alert.get("wazuh_event_id"),
            alert["alert_id"],
            alert.get("incident_title"),
            alert["created_at"],
            alert["severity"],
            alert["attack_type"],
            alert["score"],
            alert["source_ip"],
            alert["destination_ip"],
            alert.get("source_port"),
            alert.get("destination_port"),
            alert.get("protocol"),
            alert.get("frequency_count"),
            alert.get("mitre_tactic"),
            alert.get("mitre"),
            alert.get("ip_reputation"),
            alert.get("summary"),
            alert.get("reasoning"),
            alert.get("ioc_assessment"),
            alert.get("mitre_context"),
            alert.get("recommended_action"),
            alert.get("confidence"),
            alert.get("source"),
            alert.get("llm_provider"),
            alert.get("llm_model"),
            alert.get("status", "NEW"),
            alert.get("assigned_to"),
            alert.get("investigation_notes"),
            alert.get("classification"),
            alert.get("reviewed_by"),
            alert.get("reviewed_at")
        ))

        connection.commit()
        connection.close()

    def update_alert(self, alert_id: str, fields: dict):
        if not fields:
            return 0
        connection = sqlite3.connect(self.db_path)
        cursor = connection.cursor()
        set_clause = ", ".join(f"{key} = ?" for key in fields.keys())
        values = list(fields.values()) + [alert_id]
        cursor.execute(f"UPDATE alerts SET {set_clause} WHERE alert_id = ?", values)
        connection.commit()
        rows = cursor.rowcount
        connection.close()
        return rows

    def get_alerts_dataframe(self):
        connection = sqlite3.connect(self.db_path)
        dataframe = pd.read_sql_query("SELECT * FROM alerts", connection)
        connection.close()
        if "attack_type" in dataframe.columns:
            dataframe["attack_type"] = (
                dataframe["attack_type"]
                .str.replace(r"\s+", " ", regex=True)
                .str.replace("Â–", "-", regex=False)
                .str.strip()
            )
        return dataframe

    def clear_alerts(self):
        connection = sqlite3.connect(self.db_path)
        cursor = connection.cursor()
        cursor.execute("DELETE FROM alerts")
        connection.commit()
        connection.close()


    # ------------------ TICKETS ------------------

    def insert_ticket(self, ticket):
        connection = sqlite3.connect(self.db_path)
        cursor = connection.cursor()
        cursor.execute("""
        INSERT INTO tickets (ticket_id, alert_id, assigned_to, status, comments, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            ticket["ticket_id"],
            ticket["alert_id"],
            ticket.get("assigned_to"),
            ticket.get("status", "OPEN"),
            ticket.get("comments"),
            ticket.get("created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        ))
        connection.commit()
        connection.close()

    def update_ticket(self, ticket_id: str, fields: dict):
        if not fields:
            return 0
        connection = sqlite3.connect(self.db_path)
        cursor = connection.cursor()
        set_clause = ", ".join(f"{key} = ?" for key in fields.keys())
        values = list(fields.values()) + [ticket_id]
        cursor.execute(f"UPDATE tickets SET {set_clause} WHERE ticket_id = ?", values)
        connection.commit()
        rows = cursor.rowcount
        connection.close()
        return rows

    def get_tickets_dataframe(self):
        connection = sqlite3.connect(self.db_path)
        query = """
        SELECT t.id, t.ticket_id, t.status, t.assigned_to, t.comments, t.created_at as ticket_created_at,
               a.id as alert_db_id, a.alert_id, a.incident_title, a.created_at, a.severity, a.attack_type, a.score,
               a.source_ip, a.destination_ip, a.source_port, a.destination_port,
               a.protocol, a.frequency_count, a.mitre_tactic, a.mitre, a.ip_reputation,
               a.summary, a.reasoning, a.ioc_assessment, a.mitre_context,
               a.recommended_action, a.confidence, a.source, a.llm_provider, a.llm_model,
               a.investigation_notes, a.classification, a.reviewed_by, a.reviewed_at
        FROM tickets t
        JOIN alerts a ON t.alert_id = a.alert_id
        """
        dataframe = pd.read_sql_query(query, connection)
        connection.close()
        return dataframe

    # ------------------ INCIDENT REPORTS ------------------

    def insert_incident_report(self, ticket_id: str, generated_by: str, generated_at: str, content: str):
        connection = sqlite3.connect(self.db_path)
        cursor = connection.cursor()
        
        # Obtenir la dernière version
        cursor.execute("SELECT MAX(version) FROM incident_reports WHERE ticket_id = ?", (ticket_id,))
        max_v = cursor.fetchone()[0]
        version = (max_v + 1) if max_v else 1

        cursor.execute("""
        INSERT INTO incident_reports (ticket_id, generated_by, generated_at, content, version)
        VALUES (?, ?, ?, ?, ?)
        """, (ticket_id, generated_by, generated_at, content, version))
        
        connection.commit()
        connection.close()
        return version

    def get_incident_reports(self, ticket_id: str):
        connection = sqlite3.connect(self.db_path)
        cursor = connection.cursor()
        cursor.execute("""
        SELECT id, ticket_id, generated_by, generated_at, content, version 
        FROM incident_reports 
        WHERE ticket_id = ? 
        ORDER BY version DESC
        """, (ticket_id,))
        rows = cursor.fetchall()
        connection.close()
        
        return [
            {
                "id": r[0],
                "ticket_id": r[1],
                "generated_by": r[2],
                "generated_at": r[3],
                "content": r[4],
                "version": r[5]
            } for r in rows
        ]
