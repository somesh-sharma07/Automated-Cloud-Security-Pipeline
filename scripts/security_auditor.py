import html
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple


def find_checkov_json() -> Path:
    """Locate the Checkov JSON report regardless of output path layout."""
    candidates = [
        Path("checkov-results/results_json.json"),
        Path("checkov-results"),
        Path("results_json.json"),
    ]
    for path in candidates:
        if path.is_file():
            return path
        if path.is_dir():
            for file in sorted(path.rglob("*.json")):
                if file.is_file():
                    return file
    raise FileNotFoundError("Could not locate Checkov JSON report (results_json.json).")


def parse_checkov_report(report_path: Path) -> Dict[str, List[Dict[str, Any]]]:
    """Normalize Checkov JSON (dict or list of framework reports) into check lists."""
    raw = json.loads(report_path.read_text(encoding="utf-8"))
    blocks = raw if isinstance(raw, list) else [raw]

    passed, failed, skipped = [], [], []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        results = block.get("results", {})
        passed.extend(results.get("passed_checks", []))
        failed.extend(results.get("failed_checks", []))
        skipped.extend(results.get("skipped_checks", []))

    return {"passed": passed, "failed": failed, "skipped": skipped}


def calculate_metrics(checks: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    passed = checks["passed"]
    failed = checks["failed"]
    skipped = checks["skipped"]

    total_evaluated = len(passed) + len(failed)
    score = round((len(passed) / total_evaluated) * 100, 1) if total_evaluated > 0 else 100.0

    custom_passed = [c for c in passed if str(c.get("check_id", "")).startswith("CKV_CUSTOM")]
    custom_failed = [c for c in failed if str(c.get("check_id", "")).startswith("CKV_CUSTOM")]
    builtin_passed = len(passed) - len(custom_passed)
    builtin_failed = len(failed) - len(custom_failed)

    if len(failed) == 0:
        status_label = "COMPLIANT — DEPLOYMENT APPROVED"
        status_badge = "PASS"
        risk_level = "LOW"
    elif score >= 75:
        status_label = "BLOCKED — MEDIUM RISK VIOLATIONS"
        status_badge = "FAIL"
        risk_level = "MEDIUM"
    else:
        status_label = "BLOCKED — CRITICAL RISK VIOLATIONS"
        status_badge = "FAIL"
        risk_level = "HIGH"

    return {
        "score": score,
        "passed_count": len(passed),
        "failed_count": len(failed),
        "skipped_count": len(skipped),
        "total_evaluated": total_evaluated,
        "custom_passed": len(custom_passed),
        "custom_failed": len(custom_failed),
        "builtin_passed": builtin_passed,
        "builtin_failed": builtin_failed,
        "status_label": status_label,
        "status_badge": status_badge,
        "risk_level": risk_level,
    }


def get_gemini_remediation(
    checks: Dict[str, List[Dict[str, Any]]],
    metrics: Dict[str, Any],
) -> Tuple[str, str]:
    """Call Gemini API for remediation patches (on fail) or posture summary (on pass)."""
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    tf_code = Path("main.tf").read_text(encoding="utf-8") if Path("main.tf").is_file() else ""

    if checks["failed"]:
        violations = "\n".join(
            f"- {c.get('check_id')}: {c.get('check_name')} | "
            f"Resource: {c.get('resource')} | Lines: {c.get('file_line_range')}"
            for c in checks["failed"]
        )
        prompt = (
            "You are a Senior Cloud DevSecOps Engineer reviewing a Terraform AWS deployment "
            "blocked by Checkov.\n\n"
            f"Failed Checks:\n{violations}\n\n"
            f"Current main.tf:\n```hcl\n{tf_code}\n```\n\n"
            "Respond concisely with:\n"
            "1. A short bullet list explaining the exact security risk of each failed check.\n"
            "2. The exact copy-paste Terraform HCL block(s) needed to fix every failed check.\n"
            "Keep the answer crisp, technical, and under 300 words."
        )
    else:
        prompt = (
            "You are a Senior Cloud DevSecOps Engineer auditing a passing Terraform AWS deployment.\n"
            f"Compliance Score: {metrics['score']}% ({metrics['passed_count']} passed, "
            f"{metrics['custom_passed']} custom Python policy checks passed, "
            f"{metrics['skipped_count']} documented skips).\n\n"
            f"Current main.tf:\n```hcl\n{tf_code}\n```\n\n"
            "Write a concise 3-bullet executive security verification summarizing:\n"
            "- Why this Zero-Trust VPC & Security Group architecture is hardened.\n"
            "- How the custom Python rules (CKV_CUSTOM_1 & CKV_CUSTOM_2) enforce governance.\n"
            "- One practical next-step hardening recommendation for production.\n"
            "Keep it crisp and under 180 words."
        )

    if not api_key:
        fallback = build_fallback_advice(checks, metrics, "GEMINI_API_KEY secret is not configured.")
        return fallback, "Built-in Fallback"

    try:
        from google import genai  # type: ignore

        client = genai.Client(api_key=api_key)
        model_candidates = [
            "gemini-3.5-flash-lite",
            "gemini-2.5-flash",
        ]
        last_error = ""
        for model_name in model_candidates:
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                )
                if response and getattr(response, "text", None):
                    return response.text.strip(), f"Gemini API ({model_name})"
            except Exception as exc:
                last_error = str(exc)
                continue

        fallback = build_fallback_advice(checks, metrics, f"Gemini API error: {last_error}")
        return fallback, "Built-in Fallback"
    except Exception as exc:
        fallback = build_fallback_advice(checks, metrics, f"SDK unavailable: {exc}")
        return fallback, "Built-in Fallback"


def build_fallback_advice(
    checks: Dict[str, List[Dict[str, Any]]],
    metrics: Dict[str, Any],
    reason: str,
) -> str:
    if checks["failed"]:
        lines = [f"**Automated Remediation Summary** _(AI fallback active: {reason})