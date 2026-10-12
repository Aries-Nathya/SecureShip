# SecureShip

SecureShip is a small DevSecOps dashboard for running Python dependency, source-code, and secret scans; evaluating their results against a policy; and recording pipelines, scans, findings, and deployment data in a FastAPI service.

## Architecture

- **Frontend:** React/Vite application, served by the frontend container on `http://localhost:5173`.
- **API:** FastAPI and SQLAlchemy, served on `http://127.0.0.1:8000`; interactive docs are at `/docs` and health is at `/health`.
- **Database:** SQLite. Docker Compose mounts the external named volume `secureship_data` at `/app/data`, with the database at `/app/data/secureship.db`.
- **Scanner orchestrator:** `security/scripts/run_scans.py` executes scanners, normalizes findings, evaluates policy, publishes records to the API, then records a terminal pipeline state.
- **CI:** `.github/workflows/ci.yml` installs `backend/requirements.txt` on a fresh GitHub-hosted Python 3.12 runner and runs backend pytest on pushes and pull requests to `main`.

The API permits the local frontend origins `http://localhost:5173` and `http://127.0.0.1:5173` by default. Set `SECURESHIP_CORS_ORIGINS` to a comma-separated allowlist when using different frontend origins.

## Security policy and scanner scope

The policy is in [`security_policy.json`](security/policies/security_policy.json). It blocks detected secrets, critical/high dependency findings, critical/high SAST findings, and any unknown finding severity. The maximum allowed critical and high finding counts are both zero. Medium, low, and informational findings are recorded but do not currently fail the policy. Scanner execution failures or unavailable required scanners fail the overall run.

The current orchestrator scans these targets:

| Scanner | Target and scope |
| --- | --- |
| pip-audit | Dependencies declared by `backend/requirements.txt` (not every package installed in an arbitrary environment) |
| Gitleaks | The working tree directory; this does not scan Git history |
| Semgrep | `backend/app/` using the `p/default` ruleset |

Reports contain normalized findings. The orchestrator avoids writing raw Gitleaks matches or Semgrep source snippets, which could contain secrets. Scanner results cover only the configured targets and rules; zero findings do **not** prove the whole application is secure.

## Local development

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Frontend

In another terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The frontend defaults to the API at `http://127.0.0.1:8000`.

## Docker Compose

The Compose file expects the named volume to exist because it is declared external. Create it once on a fresh Docker host, then start the services:

```bash
docker volume create secureship_data
docker compose up --build -d
docker compose ps
```

Back up the database before replacing containers or changing storage configuration. The named volume persists the database across backend container recreation; it is not a substitute for an external backup.

## Backend checks

```bash
cd backend
python -m pip install -r requirements.txt
python -m pip check
python -m pytest -v
```

At the final verification snapshot on 2026-10-12, all 11 backend tests passed and `pip check` reported no broken requirements. One existing Starlette deprecation warning was reported. The GitHub Actions workflow is configured as described above; this local result alone does not establish the status of a particular hosted Actions run.

## Security scans

The scanner requires `pip-audit`, `gitleaks`, and `semgrep` to be available. In the verified development setup, Semgrep was isolated from the backend virtual environment. Run the scanner only when `SECURESHIP_API_URL` points to the database intended to receive the records. The default is the live local API at `http://127.0.0.1:8000`.

For a safe isolated run, follow [`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md), which starts a temporary API/database and directs reports to `/tmp`. Do not use the default API target for a demonstration unless you intend to add records to the dashboard database.

## Verification snapshot and known data

On 2026-10-12, a full scanner run against an isolated SQLite database completed successfully: pip-audit audited 54 declared dependencies, Gitleaks completed, and Semgrep completed against `backend/app/`; none reported findings in those configured scopes, and the policy passed. An earlier Semgrep run identified a medium-severity wildcard CORS issue; the CORS configuration was then restricted and the scoped check no longer reported that issue. These results describe that snapshot, not a guarantee about later source or dependency changes.

The restored live dashboard database contains historical records: 1 application, 9 pipeline runs, 13 scan runs, 4 findings, 2 dependency updates, and 4 deployments. The 9 historical pipelines include 6 marked failed and 3 still marked running, with no completion timestamps. They predate the terminal-status implementation and were left intact rather than rewritten. The isolated successful scan is separate from these dashboard records.

For the reproducible demonstration flow, including a clearly labeled synthetic policy failure that writes only to the isolated database, see [`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md). For a research/project report structure and draft abstract, see [`docs/PROJECT_REPORT_OUTLINE.md`](docs/PROJECT_REPORT_OUTLINE.md).

## Repository areas

```text
backend/                   FastAPI app, SQLAlchemy models, and backend tests
frontend/                  React dashboard
security/policies/         Machine-readable security policy and policy notes
security/scripts/           Scanner orchestration
.github/workflows/          GitHub Actions backend CI
infra/, k8s/, helm/,        Infrastructure and deployment configurations
monitoring/                  Monitoring configurations
docs/                        Demonstration and project-report documentation
```

Infrastructure and CI configuration files outside the verified local Compose/backend workflow are project artifacts; their presence alone should not be described as proof of a working integration.
