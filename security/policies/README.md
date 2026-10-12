# SecureShip Security Policies & Evaluation Gating

SecureShip integrates automated security checks into the software delivery pipeline to ensure security is continuous and non-negotiable.

## 1. Gating & Enforcement Thresholds

| Finding Type | Severity / Tool | Action | Policy Enforcement |
| :--- | :--- | :--- | :--- |
| **Committed Secrets** | Gitleaks / Any | **BLOCK** | Immediate pipeline failure; PR cannot be merged. Secret rotation required. |
| **Critical Vulnerability** | Trivy / pip-audit (CVSS 9.0+) | **BLOCK** | Deployment blocked; build rejected unless formal signed exception exists. |
| **High Vulnerability** | Trivy / pip-audit (CVSS 7.0-8.9) | **GATE** | Block deployment if fix is available in upstream registry. |
| **SAST High / Critical** | Semgrep (injection, RCE, auth) | **BLOCK** | Pipeline fails; code review required. |
| **Medium / Low SAST** | Semgrep (code smell, deprecation) | **WARN** | Recorded in SecureShip Dashboard for sprint remediation. |
| **Failed Unit / API Tests** | Pytest / Newman | **BLOCK** | Immediate pipeline stop before packaging or container build. |

## 2. Policy Gating Workflow

1. **Scanner Execution**: Scanners execute locally or in CI/CD runners (`Gitleaks`, `Semgrep`, `Trivy`, `pip-audit`).
2. **Artifact Generation**: Standard JSON reports are written to `tests/reports/`.
3. **Policy Evaluation**: `security/scripts/run_scans.py` ingests all scanner outputs and evaluates them against `security/policies/security_policy.json`.
4. **Backend Publication**: Findings are dispatched to the SecureShip FastAPI backend via `POST /api/scans` and `POST /api/findings`.
5. **Dashboard Visualization**: The SecureShip web dashboard reflects active findings, severity levels, and deployment promotion health.
