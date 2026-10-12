# SecureShip security policy

The machine-readable policy is [`security_policy.json`](security_policy.json). The scanner orchestrator in `security/scripts/run_scans.py` evaluates normalized results and records the resulting pipeline status through the API.

## Current rules

| Finding | Current action |
| --- | --- |
| Any secret finding | Fail the policy |
| Critical or high dependency finding | Fail the policy |
| Critical or high SAST finding | Fail the policy |
| Critical or high finding count above configured maximum | Fail the policy; both current maxima are zero |
| Finding with unknown severity | Fail the policy because severity cannot be established |
| Medium, low, or informational finding | Record it; it does not currently fail policy |
| Scanner unavailable, scanner error, or invalid report | Fail the overall run |

`allowed_exceptions` is empty in the current policy. Do not treat it as an approval workflow: this project does not currently implement signed exceptions, expiry dates, or an approval process.

## Execution and reporting

The orchestrator runs pip-audit against `backend/requirements.txt`, Gitleaks against the working tree directory, and Semgrep against `backend/app/` with the `p/default` ruleset. These scopes do not cover every possible dependency source, Git history, or every application layer. Reports contain normalized findings; raw secret matches and source snippets are not included.

The API run flow creates a pipeline, records each scanner run, submits findings, then patches the pipeline to `success` or `failed`. API write or final-status update errors are surfaced as failures. The scanner's exit status is also non-zero when policy or required execution fails.

This is a project policy configuration, not a certification or proof that a passing build is secure. Review scope, rule coverage, scanner versions, and findings whenever source or dependencies change.
