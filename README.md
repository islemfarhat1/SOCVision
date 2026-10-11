# SOCVision — AI-Assisted Security Operations Platform

**SOCVision** is a Security Operations Center (SOC) prototype designed to support security analysts in alert triage, threat investigation, incident management, and AI-assisted decision-making.

The platform combines security telemetry, threat intelligence, risk scoring, MITRE ATT&CK mapping, and local LLM assistance within a role-based SOC interface.

## Key Features

- **Security Event Processing:** Ingestion and normalization of alerts from a Wazuh-based security lab and the CICIDS2017 dataset.
- **Risk-Based Prioritization:** Alert scoring based on attack characteristics, reputation, frequency, and threat context.
- **Threat Intelligence:** Integration with VirusTotal and AbuseIPDB for IP reputation enrichment.
- **MITRE ATT&CK:** Mapping of supported attack scenarios to tactics and techniques.
- **AI-Assisted Analysis:** Local LLM-generated explanations, investigation recommendations, and incident reports using Ollama and Qwen.
- **Incident Management:** Alert qualification, escalation, investigation notes, ticket tracking, and reporting.
- **Role-Based Dashboards:** Dedicated interfaces for SOC L1, SOC L2, and SOC Manager.
- **Human-in-the-Loop:** AI-generated findings support analysts rather than replacing human judgment.

## Architecture

SOCVision follows a modular architecture:

```text
Wazuh Security Lab ──┐
                     ├──> FastAPI Backend
CICIDS2017 Dataset ──┘          |
                                v
                      Alert Normalization
                                |
                                v
                        Risk Scoring
                                |
                   +------------+------------+
                   |            |            |
              Threat Intel  MITRE ATT&CK  Ollama/Qwen
                   |            |            |
                   +------------+------------+
                                |
                                v
                       SQLite Database
                                |
                                v
                       Next.js Frontend
                                |
                    +-----------+-----------+
                    |           |           |
                  SOC L1      SOC L2     SOC Manager
```

The prototype also includes n8n automation integrations and a GitHub Actions CI workflow.

## SOC Workflow

1. **Detection:** Security alerts are collected from the laboratory or dataset.
2. **Triage (SOC L1):** Alerts are prioritized, analyzed, and classified.
3. **Escalation:** Relevant alerts are converted into investigation tickets.
4. **Investigation (SOC L2):** Analysts review technical evidence, threat intelligence, MITRE mappings, and AI recommendations.
5. **Reporting:** Incident reports are generated with LLM assistance and remain subject to human review.
6. **Supervision:** SOC managers monitor alert severity, incident status, and operational indicators.

## Technology Stack

| Category | Technologies |
|---|---|
| Backend | Python, FastAPI |
| Frontend | Next.js 16, React 19, TypeScript |
| UI & Visualization | Tailwind CSS, shadcn/ui, Recharts |
| Database | SQLite |
| Security Monitoring | Wazuh, Sysmon |
| Dataset | CICIDS2017 |
| Threat Intelligence | VirusTotal, AbuseIPDB |
| Threat Framework | MITRE ATT&CK |
| AI | Ollama, Qwen |
| Automation | n8n |
| CI & Security Scanning | GitHub Actions, Semgrep, Gitleaks, Trivy |
| Testing | Pytest |

## CI and Security Checks

The GitHub Actions workflow includes:

- Backend unit testing with Pytest.
- Secret detection with Gitleaks.
- Static application security testing with Semgrep.
- Dependency vulnerability scanning with Trivy.

These checks provide automated security feedback. They do not constitute a complete security assessment or production certification.

## Local Setup

**Backend**

```bash
cd backend
python -m pip install -r requirements.txt
```

Configure the required environment variables listed in `backend/.env.example`, including `JWT_SECRET_KEY`, before starting the API.

```bash
python -m uvicorn src.api.main:app --reload
```

**Frontend**

```bash
cd frontend
npm install
npm run dev
```

Frontend: `http://localhost:3000`  
API documentation: `http://127.0.0.1:8000/docs`

Local databases, security datasets, credentials, and generated files are not included in the public repository.

## Project Scope

SOCVision is an educational and experimental SOC prototype developed using controlled laboratory scenarios and security datasets. It is not intended to replace production SIEM/SOAR platforms or autonomous security analysts.

## Author

**Islem Farhat**  
Computer Engineering Student — École Nationale d'Ingénieurs de Carthage (ENICarthage), Tunisia  
Interests: Cybersecurity, AI-Assisted Security Operations, Security Automation

- **GitHub:** https://github.com/islemfarhat1
- **Portfolio:** https://islem-farhat-portfolio.vercel.app/
- **LinkedIn:** https://www.linkedin.com/in/islem-farhat/
