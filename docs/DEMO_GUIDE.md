# SecureShip demonstration guide

This flow keeps demo records and reports in a fresh temporary SQLite database. It demonstrates a real scanner pass and a separate, explicitly synthetic policy failure. Neither is written to the live dashboard database.

## Prerequisites

- Python and the backend requirements are installed in `backend/.venv`.
- `pip-audit` is installed in `backend/.venv`.
- `gitleaks` and `semgrep` are installed and available.
- For the verified macOS setup, Semgrep is in `/tmp/secureship-security-tools/bin/semgrep`. If using another path, update the environment variable below.

## 1. Start a clean isolated API

In Terminal A, from the repository root:

```bash
command -v lsof >/dev/null || { echo "lsof is required for the port preflight."; exit 1; }
if lsof -nP -iTCP:8002 -sTCP:LISTEN; then
  echo "Port 8002 is occupied. Stop and identify that service; do not continue."
  exit 1
fi
DEMO_DB="$(mktemp /tmp/secureship-demo.XXXXXX)"
echo "Demo database: $DEMO_DB"
export DATABASE_URL="sqlite:///$DEMO_DB"
cd backend
../backend/.venv/bin/python -m uvicorn app.main:app --app-dir . --host 127.0.0.1 --port 8002
```

The commands stop if a process already owns port 8002. If occupied, identify it before continuing; do not send demo requests to it. Keep the new server running and confirm its startup log says it is listening on `127.0.0.1:8002`. Save the `DEMO_DB` path printed by `echo "$DEMO_DB"` in Terminal A before starting Uvicorn; use that exact path for cleanup. In Terminal B, verify the isolated API:

```bash
curl -fsS http://127.0.0.1:8002/health
curl -fsS http://127.0.0.1:8002/api/overview
curl -fsS http://127.0.0.1:8002/api/pipelines
curl -fsS http://127.0.0.1:8002/api/scans
curl -fsS http://127.0.0.1:8002/api/findings
```

The new SQLite database is initialized on startup. Confirm `/health` is healthy, the overview has `total_pipelines: 0` and `total_findings: 0`, and the pipelines, scans, and findings routes each return an empty list. Stop if any check fails or the data is unexpected. This initial state confirms the scanner target is the fresh database, beyond just a successful health response.

## 2. Run the real scanner pipeline against the isolated API

In Terminal B, from the repository root, configure the API target and report directory explicitly. Preserve any certificate environment needed by your local Semgrep installation.

```bash
export SECURESHIP_API_URL=http://127.0.0.1:8002
export SECURESHIP_REPORTS_DIR=/tmp/secureship-demo-reports
export SECURESHIP_SEMGREP_BIN=/tmp/secureship-security-tools/bin/semgrep
export SEMGREP_ENABLE_VERSION_CHECK=0
export SEMGREP_SEND_METRICS=off
export OCAML_EXTRA_CA_CERTS="$PWD/backend/.venv/lib/python3.12/site-packages/certifi/cacert.pem"
backend/.venv/bin/python security/scripts/run_scans.py
```

Expected demonstration evidence is scanner statuses, policy status, and a terminal pipeline status in `/tmp/secureship-demo-reports/security-scan-summary.json`, plus the pipeline/scans/findings retrieved from the API. Results can change as dependencies, source, rules, or tools change. Do not present zero findings as proof that the application is completely secure.

Retrieve the isolated records:

```bash
curl -fsS http://127.0.0.1:8002/api/pipelines
curl -fsS http://127.0.0.1:8002/api/scans
curl -fsS http://127.0.0.1:8002/api/findings
```

If the scanner fails or a required tool is unavailable, preserve the report and show the failed result. Do not describe an unavailable scan as a pass.

## 3. Demonstrate a policy failure with a synthetic finding

After the successful run, create a separate, clearly labeled synthetic high-severity SAST finding in the same isolated database:

```bash
export SECURESHIP_API_URL=http://127.0.0.1:8002
backend/.venv/bin/python docs/demo_policy_failure.py
```

The script creates a new pipeline and scan, posts a synthetic finding titled `DEMO ONLY: synthetic high-severity SAST finding`, evaluates the checked-in policy, and marks that pipeline failed. This is test data, not a discovered issue. Use the API GET routes above to show that the finding and failed terminal status persisted.

The script refuses to run unless the API URL is explicitly set to `http://127.0.0.1:8002`; do not remove that guard or point it at the live dashboard.

## 4. Cleanup

Stop the temporary API with Ctrl-C in Terminal A. Once you have saved any desired demo output, remove the temporary database and report directory using the exact paths created for this demo. Verify those paths before removing them; do not use wildcard cleanup commands. The live Docker database and `secureship_data` volume are not part of this demo.

## Suggested 3-minute presentation

1. Show the dashboard and explain the API, scanner orchestrator, policy, and persistent database.
2. Run the real scan against the isolated API; show scanner execution status and normalized reports.
3. Retrieve the successful pipeline, scan records, and findings from the API.
4. Run the synthetic policy-failure demonstration; show the high-severity test record and failed terminal pipeline.
5. State the scanner scope and limitation: a passing result only means these tools found no blocking issue in the configured targets at that point in time.
