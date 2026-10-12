#!/usr/bin/env python3
"""Create a synthetic policy-failure record on the isolated demo API only."""

from __future__ import annotations

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCANNER_SCRIPTS = ROOT / "security" / "scripts"
sys.path.insert(0, str(SCANNER_SCRIPTS))

from run_scans import (  # noqa: E402
    evaluate_policy,
    load_policy,
    make_finding,
    patch_json,
    post_json,
)


EXPECTED_API = "http://127.0.0.1:8002"


def main() -> int:
    configured_api = os.getenv("SECURESHIP_API_URL", "").rstrip("/")
    if configured_api != EXPECTED_API:
        print(
            f"Refusing to create demo data: set SECURESHIP_API_URL={EXPECTED_API}",
            file=sys.stderr,
        )
        return 2

    application_id = int(os.getenv("SECURESHIP_APPLICATION_ID", "1"))
    finding = make_finding(
        category="sast",
        rule_id="SECURESHIP-DEMO-SYNTHETIC-HIGH",
        severity="high",
        title="DEMO ONLY: synthetic high-severity SAST finding",
        description="Synthetic record used only to demonstrate policy enforcement.",
        file_or_package="demo-only.py",
        remediation="No remediation required; this is not a real vulnerability.",
    )
    scan = {
        "scanner": "synthetic-policy-demo",
        "status": "success",
        "findings": [finding],
    }
    violations = evaluate_policy(load_policy(), [scan])
    if not violations:
        print("Expected the current policy to block the synthetic high finding.", file=sys.stderr)
        return 2

    pipeline = post_json("/api/pipelines", {
        "application_id": application_id,
        "provider": "synthetic-policy-demo",
        "commit_id": "demo-only",
        "branch": "demo",
        "status": "running",
    })
    pipeline_id = pipeline.get("id")
    if not pipeline_id:
        raise RuntimeError("Demo API did not return a pipeline id")

    scan_record = post_json("/api/scans", {
        "pipeline_run_id": pipeline_id,
        "scanner": scan["scanner"],
        "status": "success",
        "findings_count": 0,
        "report_location": "synthetic demo record; no scanner report",
    })
    scan_id = scan_record.get("id")
    if not scan_id:
        raise RuntimeError("Demo API did not return a scan id")

    payload = dict(finding["api"], scan_run_id=scan_id)
    posted_finding = post_json("/api/findings", payload)
    if not posted_finding.get("id"):
        raise RuntimeError("Demo API did not return a finding id")

    completed = patch_json(f"/api/pipelines/{pipeline_id}", {"status": "failed"})
    if completed.get("status") != "failed" or not completed.get("completed_at"):
        raise RuntimeError("Demo API did not persist the failed terminal state")

    print("Synthetic policy demonstration complete (isolated API only).")
    print(f"Pipeline: {pipeline_id} ({completed['status']})")
    print(f"Scan: {scan_id}; finding: {posted_finding['id']}")
    print("Policy violations: " + "; ".join(violations))
    print("This synthetic finding is not a real vulnerability.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
