#!/usr/bin/env python3
"""Run SecureShip security scanners, publish their results, and enforce policy."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REPORTS_DIR = Path(os.getenv("SECURESHIP_REPORTS_DIR", ROOT / "tests" / "reports")).expanduser()
POLICY_FILE = ROOT / "security" / "policies" / "security_policy.json"
BACKEND_URL = os.getenv("SECURESHIP_API_URL", "http://127.0.0.1:8000").rstrip("/")
APP_ID = int(os.getenv("SECURESHIP_APPLICATION_ID", "1"))


class ApiError(RuntimeError):
    """A safe-to-log API failure that does not include response bodies."""


def load_policy() -> dict[str, Any]:
    with POLICY_FILE.open(encoding="utf-8") as policy_file:
        policy = json.load(policy_file)
    rules = policy.get("rules")
    if not isinstance(rules, dict):
        raise ValueError("Security policy must contain a rules object")
    return rules


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def report_location(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def request_json(method: str, endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{BACKEND_URL}{endpoint}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raise ApiError(f"{method} {endpoint} returned HTTP {error.code}") from None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        reason = "connection or response error"
        if isinstance(error, urllib.error.URLError) and isinstance(error.reason, TimeoutError):
            reason = "request timed out"
        raise ApiError(f"{method} {endpoint} failed: {reason}") from None
    if not isinstance(result, dict):
        raise ApiError(f"{method} {endpoint} returned an invalid response")
    return result


def post_json(endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
    return request_json("POST", endpoint, payload)


def patch_json(endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
    return request_json("PATCH", endpoint, payload)


def normalize_severity(value: Any) -> str:
    """Normalize scanner severity or CVSS data without inventing a rating."""
    if isinstance(value, dict):
        explicit = value.get("severity") or value.get("level")
        if explicit:
            return normalize_severity(explicit)
        value = value.get("score")
    if isinstance(value, (int, float)):
        if value >= 9.0:
            return "critical"
        if value >= 7.0:
            return "high"
        if value >= 4.0:
            return "medium"
        if value > 0:
            return "low"
        return "info"
    if isinstance(value, str):
        label = value.strip().lower()
        if label in {"critical", "high", "medium", "low", "info"}:
            return label
        if label in {"error", "warning", "note"}:
            return {"error": "high", "warning": "medium", "note": "info"}[label]
    return "unknown"


def make_finding(
    *,
    category: str,
    rule_id: Any,
    severity: Any,
    title: Any,
    file_or_package: Any,
    description: Any = None,
    line_number: Any = None,
    remediation: Any = None,
) -> dict[str, Any]:
    """Build a schema-compatible finding and retain its policy category."""
    try:
        line = int(line_number) if line_number is not None else None
    except (TypeError, ValueError):
        line = None
    return {
        "category": category,
        "api": {
            "rule_id": str(rule_id or "UNKNOWN")[:100],
            "severity": normalize_severity(severity),
            "title": str(title or "Security finding")[:200],
            "description": str(description) if description else None,
            "file_or_package": str(file_or_package or "unknown")[:255],
            "line_number": line,
            "remediation": str(remediation) if remediation else None,
            "status": "open",
        },
    }


def parse_pip_audit(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get("dependencies"), list):
        raise ValueError("pip-audit JSON has no dependencies list")
    findings: list[dict[str, Any]] = []
    for dependency in data["dependencies"]:
        if not isinstance(dependency, dict):
            raise ValueError("pip-audit JSON contains an invalid dependency")
        name = str(dependency.get("name") or "unknown-package")
        version = str(dependency.get("version") or "unknown-version")
        vulnerabilities = dependency.get("vulns", [])
        if not isinstance(vulnerabilities, list):
            raise ValueError("pip-audit vulnerability list is invalid")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError("pip-audit JSON contains an invalid vulnerability")
            fixes = vulnerability.get("fix_versions") or []
            if not isinstance(fixes, list):
                fixes = [str(fixes)]
            vuln_id = vulnerability.get("id") or "PIP-AUDIT-UNKNOWN"
            findings.append(make_finding(
                category="dependency",
                rule_id=vuln_id,
                severity=vulnerability.get("severity") or vulnerability.get("cvss"),
                title=f"Vulnerability in {name}",
                description=vulnerability.get("description") or "Vulnerable dependency detected.",
                file_or_package=f"{name}@{version}",
                remediation=(f"Upgrade to: {', '.join(map(str, fixes))}" if fixes else
                             "Review the advisory and upgrade to a fixed version."),
            ))
    return findings


def parse_semgrep(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError("Semgrep JSON has no results list")
    findings: list[dict[str, Any]] = []
    for result in data["results"]:
        if not isinstance(result, dict):
            raise ValueError("Semgrep JSON contains an invalid result")
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        start = result.get("start") if isinstance(result.get("start"), dict) else {}
        severity = extra.get("severity") or metadata.get("severity")
        # Do not publish source snippets or interpolated messages that might contain secrets.
        rule_id = result.get("check_id") or "SEMGREP-UNKNOWN"
        findings.append(make_finding(
            category="sast",
            rule_id=rule_id,
            severity=severity,
            title=f"Semgrep finding: {str(rule_id).split('.')[-1]}",
            description=f"Semgrep reported a {normalize_severity(severity)} finding.",
            file_or_package=result.get("path") or "unknown",
            line_number=start.get("line"),
            remediation=metadata.get("fix") or "Review the Semgrep rule and remediate the finding.",
        ))
    errors = data.get("errors", [])
    if errors:
        raise ValueError("Semgrep returned scanner errors")
    return findings


def parse_gitleaks(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, list):
        raise ValueError("Gitleaks JSON must be an array")
    findings: list[dict[str, Any]] = []
    for leak in data:
        if not isinstance(leak, dict):
            raise ValueError("Gitleaks JSON contains an invalid result")
        findings.append(make_finding(
            category="secret",
            rule_id=leak.get("RuleID") or leak.get("ruleID") or "SECRET_LEAK",
            severity="critical",
            title=leak.get("Description") or "Potential secret detected",
            # Never copy Secret, Match, or source text into a report or API payload.
            description="A potential secret was detected. Review the location and rotate it if valid.",
            file_or_package=leak.get("File") or leak.get("file") or "unknown",
            line_number=leak.get("StartLine") or leak.get("startLine"),
            remediation="Revoke and rotate the credential, then remove it from source history.",
        ))
    return findings


def find_tool(name: str) -> str | None:
    if name == "pip-audit":
        venv_tool = ROOT / "backend" / ".venv" / "bin" / "pip-audit"
        if venv_tool.is_file() and os.access(venv_tool, os.X_OK):
            return str(venv_tool)
    if name == "semgrep":
        configured_tool = os.getenv("SECURESHIP_SEMGREP_BIN")
        if configured_tool:
            path = Path(configured_tool).expanduser()
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
            return None
    return shutil.which(name)


def run_scanner(
    name: str,
    command_args: list[str],
    parser,
    report_path: Path,
    *,
    accepted_exit_codes: set[int] = {0},
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    # Replace any previous report, including when the scanner is unavailable.
    report_path.unlink(missing_ok=True)
    executable = find_tool(name)
    if not executable:
        result = {
            "scanner": name,
            "status": "unavailable",
            "returncode": None,
            "findings": [],
            "error": "scanner executable not found",
            "report_path": report_path,
        }
        write_json(report_path, {k: v for k, v in result.items() if k != "report_path"})
        return result

    try:
        environment = None
        if name == "semgrep":
            environment = os.environ.copy()
            # Avoid an outbound version-check request during every local or CI scan.
            environment["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
        process = subprocess.run(
            [executable, *command_args], cwd=ROOT, capture_output=True, text=True,
            check=False, env=environment, timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        result = {
            "scanner": name,
            "status": "failed",
            "returncode": None,
            "findings": [],
            "error": f"scanner timed out after {timeout_seconds} seconds",
            "report_path": report_path,
        }
        write_json(report_path, {k: v for k, v in result.items() if k != "report_path"})
        return result
    except OSError:
        result = {
            "scanner": name,
            "status": "failed",
            "returncode": None,
            "findings": [],
            "error": "scanner could not be started",
            "report_path": report_path,
        }
        write_json(report_path, {k: v for k, v in result.items() if k != "report_path"})
        return result

    try:
        scanner_data = json.loads(process.stdout)
        findings = parser(scanner_data)
        if process.returncode not in accepted_exit_codes:
            raise ValueError(f"scanner exited with code {process.returncode}")
        status = "success"
        error = None
    except (json.JSONDecodeError, ValueError, TypeError):
        scanner_data = None
        findings = []
        status = "failed"
        error = "scanner returned invalid output or a failing exit code"

    result = {
        "scanner": name,
        "status": status,
        "returncode": process.returncode,
        "findings": findings,
        "error": error,
        "report_path": report_path,
    }
    # Reports contain normalized findings only. In particular, raw Gitleaks and
    # Semgrep output is never saved because it can contain credentials or snippets.
    report = {
        "scanner": name,
        "status": status,
        "returncode": process.returncode,
        "findings_count": len(findings),
        "findings": [finding["api"] for finding in findings],
    }
    if error:
        report["error"] = error
    if name == "pip-audit" and isinstance(scanner_data, dict):
        report["dependency_count"] = len(scanner_data.get("dependencies", []))
    write_json(report_path, report)
    return result


def run_pip_audit() -> dict[str, Any]:
    return run_scanner(
        "pip-audit", ["-r", "backend/requirements.txt", "-f", "json"], parse_pip_audit,
        REPORTS_DIR / "pip-audit-results.json", accepted_exit_codes={0, 1},
    )


def run_gitleaks() -> dict[str, Any]:
    return run_scanner(
        "gitleaks", [
            "dir", str(ROOT), "--report-format", "json", "--report-path", "-", "--redact", "100",
        ], parse_gitleaks,
        REPORTS_DIR / "gitleaks-results.json", accepted_exit_codes={0, 1},
    )


def run_semgrep() -> dict[str, Any]:
    return run_scanner(
        "semgrep", [
            "scan", "--quiet", "--disable-version-check", "--config", "p/default", "--json", "backend/app/",
        ], parse_semgrep,
        REPORTS_DIR / "semgrep-results.json", accepted_exit_codes={0},
    )


def policy_exceptions(policy: dict[str, Any]) -> set[str]:
    exceptions = policy.get("allowed_exceptions", [])
    if not isinstance(exceptions, list):
        return set()
    values: set[str] = set()
    for exception in exceptions:
        if isinstance(exception, str):
            values.add(exception)
        elif isinstance(exception, dict):
            rule_id = exception.get("rule_id") or exception.get("id")
            if rule_id:
                values.add(str(rule_id))
    return values


def evaluate_policy(policy: dict[str, Any], scans: list[dict[str, Any]]) -> list[str]:
    violations: list[str] = []
    for scan in scans:
        if scan["status"] != "success":
            violations.append(f"{scan['scanner']} scan is {scan['status']}")

    exceptions = policy_exceptions(policy)
    findings = [
        finding for scan in scans for finding in scan["findings"]
        if finding["api"]["rule_id"] not in exceptions
    ]
    critical = sum(f["api"]["severity"] == "critical" for f in findings)
    high = sum(f["api"]["severity"] == "high" for f in findings)

    if policy.get("block_on_secrets", True) and any(f["category"] == "secret" for f in findings):
        violations.append("secret findings are blocked by policy")
    if policy.get("block_on_critical_vulnerabilities", True) and any(
        f["category"] == "dependency" and f["api"]["severity"] == "critical" for f in findings
    ):
        violations.append("critical dependency vulnerabilities are blocked by policy")
    if policy.get("block_on_high_vulnerabilities", True) and any(
        f["category"] == "dependency" and f["api"]["severity"] == "high" for f in findings
    ):
        violations.append("high dependency vulnerabilities are blocked by policy")
    if policy.get("block_on_sast_critical", True) and any(
        f["category"] == "sast" and f["api"]["severity"] == "critical" for f in findings
    ):
        violations.append("critical SAST findings are blocked by policy")
    if policy.get("block_on_sast_high", True) and any(
        f["category"] == "sast" and f["api"]["severity"] == "high" for f in findings
    ):
        violations.append("high SAST findings are blocked by policy")
    if critical > int(policy.get("max_allowed_critical_findings", 0)):
        violations.append("maximum critical finding count exceeded")
    if high > int(policy.get("max_allowed_high_findings", 0)):
        violations.append("maximum high finding count exceeded")
    if any(f["category"] == "dependency" and f["api"]["severity"] == "unknown" for f in findings):
        violations.append("dependency finding has unknown severity")
    if any(f["api"]["severity"] == "unknown" for f in findings):
        violations.append("finding severity could not be established")
    return violations


def main() -> int:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        policy = load_policy()
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"[!] Cannot load security policy: {error}", file=sys.stderr)
        return 2

    scans = [run_pip_audit(), run_gitleaks(), run_semgrep()]
    violations = evaluate_policy(policy, scans)
    api_failures: list[str] = []
    pipeline_id = None
    pipeline_status = "not_created"

    try:
        pipeline = post_json("/api/pipelines", {
            "application_id": APP_ID,
            "provider": os.getenv("CI_PROVIDER", "local-cli"),
            "commit_id": os.getenv("COMMIT_SHA", "dev-local"),
            "branch": os.getenv("GIT_BRANCH", "main"),
            "status": "running",
        })
        pipeline_id = pipeline.get("id")
        if not pipeline_id:
            raise ApiError("POST /api/pipelines returned no pipeline id")
        pipeline_status = "running"
    except (ApiError, ValueError, TypeError) as error:
        api_failures.append(str(error))

    for scan in scans:
        print(f"[{scan['status'].upper()}] {scan['scanner']}: "
              f"{len(scan['findings'])} findings; report {report_location(scan['report_path'])}")
        if scan.get("error"):
            print(f"  {scan['error']}")
        scan_id = None
        if pipeline_id:
            try:
                scan_record = post_json("/api/scans", {
                    "pipeline_run_id": pipeline_id,
                    "scanner": scan["scanner"],
                    "status": scan["status"],
                    # The API increments this counter as each finding is inserted.
                    "findings_count": 0,
                    "report_location": report_location(scan["report_path"]),
                })
                scan_id = scan_record.get("id")
                if not scan_id:
                    raise ApiError("POST /api/scans returned no scan id")
            except (ApiError, ValueError, TypeError) as error:
                api_failures.append(str(error))
        for finding in scan["findings"]:
            if not scan_id:
                continue
            payload = dict(finding["api"], scan_run_id=scan_id)
            try:
                post_json("/api/findings", payload)
            except (ApiError, ValueError, TypeError) as error:
                api_failures.append(str(error))

    if api_failures:
        violations.append("one or more API writes failed")
        for error in api_failures:
            print(f"[API ERROR] {error}", file=sys.stderr)

    if pipeline_id:
        final_status = "failed" if violations else "success"
        try:
            updated_pipeline = patch_json(
                f"/api/pipelines/{pipeline_id}", {"status": final_status}
            )
            if updated_pipeline.get("status") != final_status or not updated_pipeline.get("completed_at"):
                raise ApiError("PATCH /api/pipelines returned an incomplete status update")
            pipeline_status = final_status
        except (ApiError, ValueError, TypeError) as error:
            api_failures.append(str(error))
            violations.append("pipeline final status update failed")
            pipeline_status = "running"
            print(f"[API ERROR] {error}", file=sys.stderr)

    summary = {
        "pipeline_id": pipeline_id,
        "pipeline_status": pipeline_status,
        "policy_status": "failed" if violations else "passed",
        "violations": violations,
        "scanners": [
            {"scanner": scan["scanner"], "status": scan["status"],
             "findings_count": len(scan["findings"])} for scan in scans
        ],
        "api_write_failures": len(api_failures),
    }
    write_json(REPORTS_DIR / "security-scan-summary.json", summary)

    print("\nSECURESHIP SECURITY SUMMARY")
    print(f"Policy: {summary['policy_status'].upper()}")
    for violation in violations:
        print(f"[POLICY FAILURE] {violation}")
    if pipeline_id:
        print(f"Pipeline status: {pipeline_status}")
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
