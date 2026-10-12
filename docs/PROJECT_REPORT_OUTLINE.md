# SecureShip project / research report outline

## Working title

**SecureShip: A Policy-Gated DevSecOps Dashboard for Python Application Security Scanning**

## Draft abstract

SecureShip is a prototype DevSecOps platform that combines a FastAPI service, a React dashboard, SQLite persistence, and a scanner orchestration script. It executes dependency auditing, static application security testing, and secret scanning; normalizes results into a common finding model; evaluates them against a configurable policy; and records scanner and pipeline outcomes through an API. The implementation was evaluated with backend regression tests, API persistence checks, Docker database-persistence checks, and a full scanner run against an isolated database. At the 2026-10-12 verification snapshot, 11 backend tests passed, the backend dependency environment passed `pip check`, and the isolated run completed pip-audit over 54 declared dependencies, Gitleaks over the working tree, and Semgrep over `backend/app/`, with no findings in those configured scopes. A prior Semgrep result exposed a medium-severity wildcard CORS issue, which was followed by a CORS restriction and a scoped rescan. The evaluation demonstrates integration and policy-gating behavior, but it does not establish complete security: scanner coverage is bounded by selected targets and rules, Gitleaks was run on the working tree rather than Git history, and a zero-finding result cannot prove the absence of vulnerabilities.

## 1. Introduction

- Explain how security checks can be integrated into software delivery workflows.
- State the project problem: scan results, policy decisions, and pipeline outcomes are often separated across tools.
- State the project objective: build a prototype that aggregates selected security scans and records policy decisions in an API-backed dashboard.
- Research question: *Can a lightweight DevSecOps application execute selected scanners, normalize and persist their findings, and block a pipeline when configured policy conditions are met?*

## 2. Background and related work

Describe continuous integration, dependency vulnerability auditing, static analysis, secret detection, and policy gates. Introduce the role of the selected tools without implying that one tool covers all threats.

- `pip-audit` checks Python dependency advisories using the declared dependency manifest in this implementation.
- Semgrep applies static analysis rules to source code.
- Gitleaks detects likely secrets in the scanned directory; the demonstrated configuration does not inspect Git history.
- GitHub Actions runs the backend test suite on pushes and pull requests to `main`.

Primary references to consult and cite in the final paper:

- [pip-audit project documentation](https://github.com/pypa/pip-audit)
- [Semgrep Community Edition](https://semgrep.dev/products/community-edition/)
- [Gitleaks documentation](https://github.com/gitleaks/gitleaks)
- [FastAPI CORS documentation](https://fastapi.tiangolo.com/tutorial/cors/)
- [Docker volume documentation](https://docs.docker.com/engine/storage/volumes/)

## 3. Requirements and scope

### Functional requirements

1. Execute dependency, SAST, and secret scanners.
2. Parse scanner output into normalized findings.
3. Record pipelines, scans, findings, and terminal status through the API.
4. Apply blocking policy conditions and return a non-zero scanner process status on failure.
5. Preserve database records when the backend container is recreated.

### Non-functional requirements

- Report missing or failed tools honestly.
- Avoid persisting raw secret values or source snippets in normalized reports.
- Keep scanner dependencies separate from the pinned backend environment.
- Support isolated verification without changing the live dashboard database.

### Scope limits

List the exact scanner targets and policy thresholds from the README. State that this project does not establish coverage of Git history, frontend source, container images, infrastructure plans, or every CI provider unless those are separately implemented and measured.

## 4. System design

Include a system diagram showing:

```text
Developer / CI runner
       |
       +--> pytest
       +--> pip-audit ----+
       +--> Gitleaks -----+--> run_scans.py --> policy decision
       +--> Semgrep ------+          |
                                     +--> FastAPI API --> SQLite volume
                                                        |
                                                        +--> React dashboard
```

Describe the React/Vite frontend, FastAPI routes and schemas, SQLAlchemy persistence, named Docker volume, scanner parsers, and pipeline state updates. Explain finding idempotency key behavior at a high level: repeated records for the same scan run, rule, location, and line are treated idempotently by the API. A new scan run still has its own records.

## 5. Implementation

- API models and routes for applications, pipelines, scans, findings, dependencies, and deployments.
- Terminal pipeline status update (`success` / `failed`) with completion timestamp.
- Scanner orchestration and normalized report generation.
- Policy rules: secrets blocked; critical/high dependency and SAST blocked; zero allowed critical/high count; unknown severity blocked; medium/low/info recorded but currently permitted.
- CORS: local frontend origins allowed by default, with environment-based configuration.
- Docker Compose persistence using the external `secureship_data` volume.
- GitHub Actions backend workflow and its actual verification status (record the hosted run URL/date only after checking it).

## 6. Evaluation method

Describe reproducible checks and distinguish them from assumptions:

1. Run backend tests against their isolated test database.
2. Check backend dependency consistency with `pip check`.
3. Run the scanner against an isolated API and SQLite database.
4. Verify pipeline, scan, and finding records through GET API routes.
5. Run a synthetic high-severity policy demonstration against the isolated API and verify the failed terminal status.
6. Recreate the backend container and verify persistent database integrity and record counts.
7. Perform HTTP health/frontend smoke checks.

Do not describe the synthetic record as a real vulnerability or count it among scan findings.

## 7. Results

Use this verified snapshot, adding exact report filenames or run identifiers if preserving the artifacts:

| Measure | Result at 2026-10-12 |
| --- | --- |
| Backend tests | 11 passed; one existing Starlette deprecation warning |
| Backend dependency consistency | `pip check` passed |
| Declared Python dependencies audited | 54 |
| pip-audit findings in isolated final run | 0 |
| Gitleaks findings in isolated final run | 0 |
| Semgrep findings in isolated final run | 0 |
| Isolated final policy decision | Passed |
| Historical live dashboard | 1 application, 9 pipelines, 13 scans, 4 findings, 2 dependency updates, 4 deployments |
| Historical pipeline status | 6 failed and 3 running; none of these nine had a completion timestamp at the time checked |

Explain that the historical dashboard records are distinct from the isolated successful run. The historical pipeline states were preserved rather than retroactively rewritten. The policy-failure presentation uses a separate synthetic record and must not be conflated with measured scanner findings.

Also document the earlier medium-severity wildcard CORS Semgrep finding, the subsequent origin restriction, and the scoped rescan. Include the report outputs as an appendix only after reviewing them for sensitive data.

## 8. Discussion

Discuss what the evaluation establishes: tool invocation, status handling, parsing, API persistence, policy failure, terminal state recording, and Docker persistence were demonstrated in isolated or deployed checks. Distinguish implementation correctness from assurance of overall application security.

## 9. Limitations and threats to validity

- Findings are constrained by scanner versions, rulesets, network/advisory data, and the snapshot date.
- Dependency audit is based on `backend/requirements.txt`; it is not an audit of every installed or transitive runtime environment in use.
- Gitleaks scans the working directory in this configuration, not Git history.
- Semgrep covers `backend/app/`, not the frontend or infrastructure directories.
- The passing final scan is one point-in-time observation and does not prove absence of vulnerabilities.
- The historical live database contains old unfinished pipeline records; these are not evidence of behavior from the new scanner run.
- A local GitHub Actions workflow file is not proof of a hosted Actions run; cite an actual successful run if that is part of the claim.
- Testing on a single developer machine and a small project is not a broad performance or reliability study.

## 10. Conclusion and future work

Conclude narrowly that the prototype demonstrated an integrated scan-to-policy-to-persistence flow for the tested configuration. Future work can include Git-history secret scans, frontend and container scanning, richer severity normalization, authenticated multi-user access, formal exception handling, CI run evidence, broader test coverage, and evaluation against a larger benchmark. Present these as future work unless implemented and tested.

## Suggested appendices

- Security policy JSON and scanner versions.
- Sanitized isolated-run summary and API responses.
- Test summary and Docker persistence verification.
- Demo steps from [`DEMO_GUIDE.md`](DEMO_GUIDE.md).
