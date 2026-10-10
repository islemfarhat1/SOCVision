# 🛡️ SOCVision — AI-Assisted Security Operations Platform

**From security events to actionable intelligence: threat detection, enrichment, prioritization, and human-led incident response.**

SOCVision is an AI-assisted Security Operations Center (SOC) platform developed to support security analysts throughout the incident management lifecycle.

It combines **security monitoring, threat intelligence, MITRE ATT&CK mapping, risk-based prioritization, LLM-assisted investigation, and incident ticketing** within a unified web application.

The platform uses two complementary security data sources: **Wazuh laboratory alerts** and the **CICIDS2017 dataset**.

> **Status:** Functional cybersecurity engineering prototype developed for educational and controlled laboratory use.

---

## 1. Project Objectives

Security Operations Centers must process large volumes of alerts, identify suspicious activities, assess their severity, and coordinate incident investigations.

SOCVision aims to:

- Centralize security alerts from different sources.
- Normalize and enrich security events.
- Prioritize alerts using contextual risk scoring.
- Map suspicious activities to MITRE ATT&CK techniques.
- Support analysts with AI-generated explanations and recommendations.
- Facilitate escalation from SOC Level 1 to SOC Level 2.
- Manage incident tickets and investigation reports.
- Provide SOC managers with operational visibility.

**SOCVision is designed to assist analysts, not replace their judgment.**

---

## 2. Security Data Sources

SOCVision combines two sources of cybersecurity data.

### Wazuh Security Laboratory

A virtualized security laboratory generates security events that can be collected and analyzed through Wazuh.

Laboratory components include:

- **Kali Linux:** Controlled attack simulation and security testing.
- **Ubuntu:** Linux target environment.
- **Windows 10 and Sysmon:** Windows endpoint event monitoring.
- **Wazuh Server:** Centralized security monitoring and alert collection.

Example security scenarios include SSH brute-force attempts, web vulnerability scanning, suspicious network activity, and authentication-related incidents.

### CICIDS2017 Dataset

The CICIDS2017 dataset provides network traffic data representing benign activity and different attack scenarios.

It complements laboratory-generated alerts by providing additional experimental security data.

**Why use both?**

| Wazuh Lab | CICIDS2017 |
|---|---|
| Laboratory-generated security events | Dataset-based network traffic |
| Endpoint and network monitoring context | Multiple attack scenarios |
| Practical SOC investigation exercises | Repeatable experimentation |
| Security alert analysis | Additional data for security analytics |

Together, these sources support experimentation with alert normalization, prioritization, and investigation workflows.

---

## 3. System Architecture

SOCVision follows a modular architecture connecting security data sources, backend processing, threat intelligence, AI assistance, persistent storage, and analyst dashboards.

### Processing Pipeline

```text
                SECURITY DATA SOURCES
           +-----------------------------+
           | Wazuh Security Laboratory   |
           | CICIDS2017 Dataset          |
           +--------------+--------------+
                          |
                          v
                 INGESTION LAYER
                 FastAPI / Webhooks
                          |
                          v
                EVENT NORMALIZATION
                          |
              +-----------+-----------+
              |           |           |
              v           v           v
          RISK        THREAT        MITRE
         SCORING    INTELLIGENCE   ATT&CK
              |           |           |
              +-----------+-----------+
                          |
                          v
                 AI-ASSISTED ANALYSIS
                    Ollama / LLM
                          |
                          v
                    SQLite Storage
                          |
                          v
                SOCVision Dashboard
                 Next.js / React
                          |
                          v
                SOC L1 / SOC L2 /
                  SOC Manager
```

### Main Components

**Backend — FastAPI**

- Security event ingestion and processing.
- Alert normalization and management.
- Threat intelligence enrichment.
- Risk scoring.
- MITRE ATT&CK mapping.
- Incident ticket management.
- AI-assisted reporting.
- Authentication and role-aware workflows.

**Frontend — Next.js**

- Role-based SOC dashboards.
- Alert triage and investigation interfaces.
- Incident management.
- Security visualizations and KPIs.
- Investigation notes and reports.

**Database — SQLite**

Stores application data, alerts, incidents, and investigation-related information for the prototype.

**AI — Ollama**

Provides local LLM inference for security explanations, recommendations, and incident report generation.

---

## 4. Core Features

### Alert Ingestion and Normalization

Security data from Wazuh and CICIDS2017 is processed into a structure suitable for investigation and prioritization.

This helps present events from different sources through a consistent analyst interface.

### Threat Intelligence Enrichment

SOCVision integrates:

- **VirusTotal:** Threat intelligence and reputation context.
- **AbuseIPDB:** IP reputation and abuse-related intelligence.

The application also distinguishes private/internal IP addresses from public IP addresses.

**An unavailable external reputation score does not imply that an internal IP address is safe.**

### Risk-Based Prioritization

A contextual scoring mechanism evaluates security alerts using indicators such as:

- Alert characteristics.
- Threat intelligence information.
- Event frequency.
- MITRE ATT&CK context.

The resulting score helps analysts prioritize investigation activities.

### MITRE ATT&CK Mapping

Security alerts are associated with relevant adversary tactics and techniques.

Examples include:

- **T1498:** Network Denial of Service.
- **T1110.001:** Password Guessing.
- **T1021.004:** SSH.

MITRE ATT&CK provides a standardized vocabulary for understanding and communicating adversary behavior.

### AI-Assisted Investigation

SOCVision integrates a local LLM through Ollama, including experimentation with Qwen models.

AI assistance supports:

- Security alert summaries.
- Contextual explanations.
- Investigation guidance.
- Recommended mitigation actions.
- Incident report generation.

**Human-in-the-Loop:** AI-generated outputs must be reviewed by SOC analysts before operational decisions or report distribution.

### Incident Ticketing

SOCVision supports an investigation workflow involving:

- Alert qualification.
- Incident escalation.
- Ticket creation.
- Analyst assignment.
- Investigation status tracking.
- Analyst comments.
- Incident reporting.

### Workflow Automation

The backend includes integration hooks for n8n, enabling experimentation with notifications and downstream security automation.

---

## 5. Role-Based SOC Workflows

SOCVision provides distinct interfaces for different security operations responsibilities.

### SOC Level 1 — Alert Triage

The SOC L1 dashboard provides:

- Alerts awaiting processing.
- Critical and high-severity alert indicators.
- Priority queues.
- Alert details and contextual intelligence.
- Risk scores and MITRE ATT&CK information.
- Investigation notes.
- Escalation to SOC L2.

**Objective:** Identify, qualify, and prioritize suspicious events.

### SOC Level 2 — Incident Investigation

The SOC L2 dashboard provides:

- Assigned incidents.
- Incident status tracking.
- Detailed investigation records.
- Threat intelligence context.
- MITRE ATT&CK mapping.
- AI-assisted analysis.
- Investigation comments.
- Incident reporting.

**Objective:** Conduct deeper investigations and coordinate incident handling.

### SOC Manager — Operational Supervision

The SOC Manager dashboard provides:

- Alert and incident statistics.
- Severity distribution.
- Active and resolved incident indicators.
- Recent incident reports.
- Operational oversight.

**Objective:** Monitor SOC activities and incident management progress.

### Administrator

The application also includes an administrative role for system and user-management functions.

Authentication and role-aware functionality are part of the prototype. Comprehensive endpoint-level authorization testing remains a future security-hardening activity.

---

## 6. Incident Investigation Lifecycle

SOCVision models a structured investigation workflow:

```text
Security Event
      |
      v
Alert Ingestion
      |
      v
Normalization & Enrichment
      |
      v
Risk Scoring & MITRE Mapping
      |
      v
SOC L1 — Initial Triage
      |
      v
Escalation / Incident Ticket
      |
      v
SOC L2 — Investigation
      |
      v
AI-Assisted Report
      |
      v
Human Review
      |
      v
Incident Tracking & Supervision
```

This workflow demonstrates how automation and AI can support analysts while preserving human oversight.

---

## 7. Technology Stack

| Category | Technologies |
|---|---|
| Backend | Python, FastAPI |
| Frontend | Next.js 16, React 19, TypeScript |
| Styling and UI | Tailwind CSS, shadcn/ui components |
| Data Visualization | Recharts |
| Database | SQLite |
| Security Monitoring | Wazuh, Sysmon |
| Security Dataset | CICIDS2017 |
| Threat Intelligence | VirusTotal, AbuseIPDB |
| Threat Framework | MITRE ATT&CK |
| Local AI | Ollama, Qwen |
| Automation | n8n |
| Version Control | Git, GitHub |
| CI | GitHub Actions |
| Security Analysis | Semgrep, Gitleaks, Trivy |
| Backend Testing | Pytest |

---

## 8. DevSecOps & Continuous Integration

SOCVision includes an automated GitHub Actions workflow for selected backend tests and security checks.

**Workflow:** `.github/workflows/ci.yml`

| CI Job | Tool | Objective |
|---|---|---|
| Backend Unit Tests | Pytest | Validate selected backend functionality, including MITRE mapping |
| Secret Scanning | Gitleaks | Detect potentially exposed credentials |
| Static Security Analysis | Semgrep | Identify potentially insecure source-code patterns |
| Dependency Scanning | Trivy | Detect known dependency vulnerabilities |

### Current CI Implementation

The four GitHub Actions jobs have been executed successfully.

**Security limitations:**

- The backend test job currently runs a targeted unit test rather than a comprehensive test suite.
- Trivy runs in informational mode, so vulnerability findings do not automatically fail the workflow.
- Frontend linting and automated frontend tests are not currently enforced by CI.
- A successful pipeline does not guarantee that the application is vulnerability-free.

### Dependency Maintenance

Following frontend dependency updates, the production dependency audit reported:

**0 vulnerabilities detected by `npm audit --omit=dev` at the time of verification.**

Development dependency findings and other security issues require separate assessment.

---

## 9. Installation and Local Development

### Prerequisites

- Git
- Python 3.12 or a compatible version
- Node.js compatible with Next.js 16
- npm
- Ollama, if local AI assistance is required
- Optional VirusTotal and AbuseIPDB API credentials

### Clone the Repository

```bash
git clone https://github.com/islemfarhat1/SOCVision.git
cd SOCVision
```

### Backend Setup

```bash
cd backend
python -m venv .venv
```

Activate the environment.

**Windows PowerShell:**

```powershell
.\.venv\Scripts\Activate.ps1
```

**Linux/macOS:**

```bash
source .venv/bin/activate
```

Install dependencies using the backend dependency specification.

If using `requirements.txt`:

```bash
pip install -r requirements.txt
```

### Environment Variables

The repository provides an example configuration at:

`backend/.env.example`

Example environment variables:

```dotenv
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OPENROUTER_API_KEY=
N8N_WEBHOOK_URL=
JWT_SECRET_KEY=
```

Provide the required variables through the application's supported environment-loading mechanism.

**Never commit real credentials or JWT secrets.**

The backend must be launched using its configured FastAPI application entry point.

### Frontend Setup

From the repository root:

```bash
cd frontend
npm ci
npm run dev
```

The Next.js development server normally starts at:

`http://localhost:3000`

The backend API address must be configured according to the frontend API client implementation.

### Verify the Frontend Build

```bash
npm run build
```

### Run a Production Dependency Audit

```bash
npm audit --omit=dev
```

---

## 10. Repository Structure

```text
SOCVision/
|
+-- .github/
|   +-- workflows/
|       +-- ci.yml
|
+-- backend/
|   +-- config/
|   +-- src/
|   +-- tests/
|   +-- .env.example
|
+-- frontend/
|   +-- src/
|   +-- package.json
|   +-- package-lock.json
|
+-- .gitignore
+-- README.md
```

Local databases, datasets, credentials, and generated artifacts are excluded from the public repository where applicable.

---

## 11. Screenshots & Demonstration

The application includes the following interfaces:

**SOC L1 — Triage Dashboard**

Priority queues, security KPIs, alert severity, and initial investigation.

**SOC L1 — Alert Investigation**

Technical alert details, MITRE ATT&CK mapping, reputation context, analyst notes, and escalation.

**SOC L2 — Investigation Dashboard**

Assigned incidents, investigation progress, and ticket management.

**SOC L2 — Incident Details**

Threat intelligence, investigation comments, AI-assisted summaries, and recommended actions.

**Incident Reports**

Structured incident reports with classification, investigation details, and human-review requirements.

**SOC Manager — Supervision Dashboard**

Global alert and incident statistics, severity distributions, and recent reports.

Screenshots should use sanitized demonstration data before publication.

---

## 12. Future Improvements

Potential development directions include:

- Broader automated backend and frontend test coverage.
- Stronger authorization and endpoint security testing.
- Remediation of outstanding lint and dependency findings.
- More advanced alert correlation and detection.
- Additional threat intelligence integrations.
- Explainable AI-assisted prioritization.
- Evaluation of LLM-generated investigation recommendations.
- Improved security automation with human approval.
- Production-grade storage and deployment architecture.
- Risk-based CI security gates.

These are planned or potential improvements, not completed functionality.

---

## 13. Author

**Islem Farhat**

Computer Engineering Student  
École Nationale d'Ingénieurs de Carthage (ENICarthage), Tunisia.

**Interests:** Cybersecurity, AI-Assisted Security Operations, Threat Detection, Security Automation, and DevSecOps.

**GitHub:** https://github.com/islemfarhat1

**Portfolio:** https://islem-farhat-portfolio.vercel.app/

---

## Disclaimer

SOCVision is an educational and research-oriented cybersecurity prototype.

All security testing must be performed in authorized environments.

AI-generated security analyses and recommendations require human review before operational use.