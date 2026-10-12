# SecureShip — Automated DevSecOps Platform

**SecureShip** is an end-to-end DevSecOps platform designed for continuous vulnerability detection, automated dependency management, policy-driven quality gating, and secure multi-cloud / container deployment.

---

## 1. System Architecture & Workflow

```
+---------------------------------------------------------------------------------------------------+
|                                      1. Developer Git Commit                                      |
|                               (Python / FastAPI App, Branching)                                    |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                                  2. Multi-CI/CD Orchestration                                     |
|           GitHub Actions   ·   Jenkins Pipeline   ·   GitLab CI/CD   ·   Azure Pipelines           |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                                    3. Automated Code & API Tests                                  |
|                            Pytest Unit Tests   ·   Newman Postman API Tests                       |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                                    4. DevSecOps Security Checks                                   |
|               Gitleaks (Secrets)  ·  Semgrep (SAST)  ·  Trivy / pip-audit (Dependencies)          |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                                                  v
                                     [ Policy Evaluation Gating ]
                                    /                            \
                     [ Critical / High Found ]            [ Clean / Approved ]
                                |                                  |
                                v                                  v
                       Block Deployment               5. Build & Scan Container Image
                     Report to Dashboard                   (Docker / Versioning)
                                                                   |
                                                                   v
                                                      6. Multi-Target Deployment
                                                    Docker Compose / Helm & K8s
                                                                   |
                                                                   v
                                                      7. Telemetry & Continuous Update
                                                    Prometheus · Grafana · Renovate
```

---

## 2. CI/CD Engines Comparison

| CI/CD Tool | Configuration | Execution Model | SecureShip Role |
| :--- | :--- | :--- | :--- |
| **GitHub Actions** | `.github/workflows/ci.yml` | Cloud / Hosted Runner | Primary PR checks, automated gating, security scanning |
| **Jenkins** | `Jenkinsfile` | Declarative Pipeline (Self-hosted) | Local cluster CI execution, artifact retention |
| **GitLab CI/CD** | `.gitlab-ci.yml` | Staged container jobs | Multi-stage image validation and security reports |
| **Azure Pipelines** | `azure-pipelines.yml` | Microsoft Azure DevOps Hosted | Enterprise cloud CI/CD compliance workflow |

---

## 3. Directory Layout

```
secureship/
├── .github/workflows/          # GitHub Actions CI definitions
├── .gitlab-ci.yml              # GitLab CI/CD pipeline
├── Jenkinsfile                 # Jenkins declarative pipeline
├── azure-pipelines.yml         # Azure Pipelines configuration
├── backend/
│   ├── app/
│   │   ├── main.py             # FastAPI entrypoint & Prometheus instrumentator
│   │   ├── database.py         # SQLAlchemy engine & session factory
│   │   ├── models.py           # Applications, Pipelines, Scans, Findings, Deployments
│   │   └── schemas.py          # Pydantic validation schemas
│   ├── tests/
│   │   └── test_main.py        # Pytest test suite with StaticPool isolation
│   ├── Dockerfile              # Backend container definition
│   └── requirements.txt        # Python dependency manifest
├── frontend/
│   ├── src/
│   │   ├── App.jsx             # React DevSecOps 7-section Dashboard
│   │   └── index.css           # Modern theme & component styling
│   ├── Dockerfile              # Multi-stage production container build
│   └── package.json            # React & Lucide icons manifest
├── security/
│   ├── policies/
│   │   ├── README.md           # Security gating thresholds & policies
│   │   └── security_policy.json# Machine-readable evaluation rules
│   └── scripts/
│       └── run_scans.py        # SAST, secret, and vuln scanner orchestrator
├── infra/
│   ├── terraform/              # Infrastructure as Code (Local & Azure)
│   ├── ansible/                # Configuration management & Vault encryption
│   └── packer/                 # Reusable machine image build automation
├── k8s/                        # Kubernetes Deployments, Services, ConfigMaps
├── helm/secureship/            # Helm packaging chart
├── monitoring/
│   ├── prometheus/             # Prometheus scraping configuration
│   └── grafana/                # Pre-built DevSecOps telemetry dashboard
├── tests/
│   ├── postman/                # Postman API test collection
│   ├── reports/                # Standardized JSON scan outputs
│   └── run_scenarios.py        # 6 DevSecOps acceptance scenarios suite
└── renovate.json               # Renovate automated dependency update bot config
```

---

## 4. Quickstart Guide (Local Execution)

### 1. Run the Backend (FastAPI)
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
- API Docs: `http://localhost:8000/docs`
- Health Endpoint: `http://localhost:8000/health`
- Prometheus Metrics: `http://localhost:8000/metrics`

### 2. Run the React Dashboard
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` to explore the dashboard.

### 3. Run Automated Tests
```bash
cd backend
pytest -v
```

### 4. Run the DevSecOps Security Scanner
```bash
python3 security/scripts/run_scans.py
```

### 5. Run All 6 Acceptance Scenarios
```bash
python3 tests/run_scenarios.py
```

---

## 5. Acceptance Checklist Status

- [x] **Healthy Application**: Passes health endpoints and active deployment validation.
- [x] **Failing Unit Test**: Pipeline rejects broken code and aborts promotion.
- [x] **Detected Test Secret**: Gitleaks detection blocks commit with Critical violation.
- [x] **Vulnerable Dependency**: Trivy / pip-audit identifies CVE and blocks release.
- [x] **Dependency Update**: Renovate proposes automated package upgrades for verification.
- [x] **Unhealthy Deployment**: Automated probe flags failing pod and displays on dashboard.
