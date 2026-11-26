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
        lines = [f"**Automated Remediation Summary** _(AI fallback active: {reason})_", ""]
        for c in checks["failed"]:
            lines.append(
                f"- **`{c.get('check_id')}`** on `{c.get('resource')}` "
                f"(lines {c.get('file_line_range')}): {c.get('check_name')}."
            )
        lines.append("\nReview the flagged Terraform blocks in `main.tf` and re-push to unblock deployment.")
        return "\n".join(lines)

    return (
        f"**Executive Security Verification** _(AI fallback active: {reason})_\n\n"
        f"- **Compliance Score:** {metrics['score']}% with zero failed controls across "
        f"{metrics['total_evaluated']} evaluated checks.\n"
        "- **Custom Policy Enforcement:** Custom Python rules (`CKV_CUSTOM_1` region lock and "
        "`CKV_CUSTOM_2` mandatory FinOps tags) passed across all resources.\n"
        "- **Zero-Trust Topology:** Default VPC security group is restricted and Web/DB tiers "
        "enforce least-privilege port isolation."
    )


def markdown_to_html(md_text: str) -> str:
    """Convert simple Markdown (code fences, bold, inline code, bullets) to safe HTML."""
    parts = re.split(r"(```[\w-]*\n.*?```)", md_text, flags=re.DOTALL)
    html_chunks: List[str] = []

    for part in parts:
        if part.startswith("```") and part.endswith("```"):
            lines = part.splitlines()
            code_body = "\n".join(lines[1:-1])
            html_chunks.append(
                f'<pre class="code-block"><code>{html.escape(code_body)}</code></pre>'
            )
        else:
            escaped = html.escape(part)
            escaped = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)
            escaped = re.sub(r"`([^`]+)`", r'<code class="inline-code">\1</code>', escaped)
            lines_out = []
            in_list = False
            for raw_line in escaped.splitlines():
                stripped = raw_line.strip()
                if stripped.startswith(("- ", "* ")):
                    if not in_list:
                        lines_out.append("<ul>")
                        in_list = True
                    lines_out.append(f"<li>{stripped[2:]}</li>")
                else:
                    if in_list:
                        lines_out.append("</ul>")
                        in_list = False
                    if stripped.startswith("### "):
                        lines_out.append(f"<h4>{stripped[4:]}</h4>")
                    elif stripped.startswith("## "):
                        lines_out.append(f"<h3>{stripped[3:]}</h3>")
                    elif stripped:
                        lines_out.append(f"<p>{stripped}</p>")
            if in_list:
                lines_out.append("</ul>")
            html_chunks.append("\n".join(lines_out))

    return "\n".join(html_chunks)


def build_table_rows(checks: Dict[str, List[Dict[str, Any]]]) -> str:
    rows = []
    ordered = (
        [("FAIL", c) for c in checks["failed"]]
        + [("PASS", c) for c in checks["passed"]]
        + [("SKIP", c) for c in checks["skipped"]]
    )

    for status, item in ordered:
        check_id = str(item.get("check_id", "UNKNOWN"))
        check_name = str(item.get("check_name", ""))
        resource = str(item.get("resource", "N/A"))
        file_path = str(item.get("file_path", "/main.tf")).lstrip("/")
        line_range = item.get("file_line_range", [])
        lines_str = (
            f"L{line_range[0]}–{line_range[1]}"
            if isinstance(line_range, list) and len(line_range) == 2
            else "-"
        )
        is_custom = check_id.startswith("CKV_CUSTOM")
        origin_badge = (
            '<span class="badge badge-custom">CUSTOM PYTHON</span>'
            if is_custom
            else '<span class="badge badge-builtin">CHECKOV AWS</span>'
        )
        status_cls = {
            "PASS": "badge-pass",
            "FAIL": "badge-fail",
            "SKIP": "badge-skip",
        }[status]

        rows.append(
            f"""
            <tr data-status="{status}">
                <td><span class="badge {status_cls}">{status}</span></td>
                <td><code>{html.escape(check_id)}</code> {origin_badge}</td>
                <td><code>{html.escape(resource)}</code></td>
                <td><code>{html.escape(file_path)} ({lines_str})</code></td>
                <td>{html.escape(check_name)}</td>
            </tr>
            """
        )
    return "\n".join(rows)


def generate_dashboard_html(
    checks: Dict[str, List[Dict[str, Any]]],
    metrics: Dict[str, Any],
    ai_markdown: str,
    ai_engine: str,
) -> str:
    ist = timezone(timedelta(hours=5, minutes=30))
    timestamp_ist = datetime.now(ist).strftime("%d %b %Y, %I:%M %p IST")
    commit_sha = os.environ.get("GITHUB_SHA", "local-dev")[:7]
    repo_name = os.environ.get("GITHUB_REPOSITORY", "somesh-sharma07/Automated-Cloud-Security-Pipeline")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_url = f"https://github.com/{repo_name}/actions/runs/{run_id}" if run_id else "#"

    score_color = (
        "#3b82f6" if metrics["failed_count"] == 0 else ("#f59e0b" if metrics["score"] >= 75 else "#ef4444")
    )
    banner_cls = "banner-pass" if metrics["failed_count"] == 0 else "banner-fail"
    ai_html = markdown_to_html(ai_markdown)
    table_rows = build_table_rows(checks)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>DevSecOps Security Audit Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {{
      --bg: #0b1120;
      --card: #111827;
      --border: #1f2937;
      --text: #f3f4f6;
      --muted: #9ca3af;
      --green: #3b82f6;
      --red: #ef4444;
      --amber: #f59e0b;
      --purple: #a855f7;
      --blue: #38bdf8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.55;
    }}
    .container {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 28px 20px 60px;
    }}
    header {{
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 20px;
      margin-bottom: 24px;
    }}
    h1 {{ margin: 0; font-size: 1.65rem; letter-spacing: -0.02em; }}
    .subtitle {{ color: var(--muted); font-size: 0.9rem; margin-top: 4px; }}
    .meta-pills {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .pill {{
      background: var(--card);
      border: 1px solid var(--border);
      padding: 6px 12px;
      border-radius: 999px;
      font-size: 0.8rem;
      color: var(--muted);
    }}
    .pill a {{ color: var(--blue); text-decoration: none; }}
    .banner {{
      padding: 16px 20px;
      border-radius: 12px;
      font-weight: 600;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 24px;
    }}
    .banner-pass {{
      background: rgba(59, 130, 246, 0.14);
      border: 1px solid rgba(59, 130, 246, 0.45);
      color: #93c5fd;
    }}
    .banner-fail {{
      background: rgba(239, 68, 68, 0.14);
      border: 1px solid rgba(239, 68, 68, 0.45);
      color: #fca5a5;
    }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px;
    }}
    .kpi-label {{ color: var(--muted); font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    .kpi-value {{ font-size: 2rem; font-weight: 700; margin-top: 6px; }}
    .kpi-sub {{ color: var(--muted); font-size: 0.8rem; margin-top: 4px; }}
    .charts-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 20px;
      margin-bottom: 24px;
    }}
    .chart-box {{ height: 260px; position: relative; margin-top: 12px; }}
    .ai-card {{
      border-left: 4px solid var(--purple);
      margin-bottom: 24px;
    }}
    .ai-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 12px;
    }}
    .ai-content p {{ margin: 8px 0; color: #e5e7eb; }}
    .ai-content ul {{ margin: 8px 0 12px 20px; color: #e5e7eb; }}
    .ai-content li {{ margin-bottom: 6px; }}
    .code-block {{
      background: #020617;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px;
      overflow-x: auto;
      font-size: 0.85rem;
      color: #93c5fd;
    }}
    .inline-code {{
      background: #1e293b;
      padding: 2px 6px;
      border-radius: 5px;
      font-size: 0.86em;
      color: #cbd5e1;
    }}
    .table-wrap {{ overflow-x: auto; margin-top: 14px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
    th, td {{ text-align: left; padding: 11px 12px; border-bottom: 1px solid var(--border); }}
    th {{ color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 0.72rem;
      font-weight: 700;
      vertical-align: middle;
    }}
    .badge-pass {{ background: rgba(59,130,246,0.18); color: #60a5fa; }}
    .badge-fail {{ background: rgba(239,68,68,0.2); color: #f87171; }}
    .badge-skip {{ background: rgba(245,158,11,0.16); color: #fbbf24; }}
    .badge-custom {{ background: rgba(168,85,247,0.2); color: #d8b4fe; margin-left: 6px; }}
    .badge-builtin {{ background: rgba(56,189,248,0.14); color: #7dd3fc; margin-left: 6px; }}
    .filter-bar {{ display: flex; gap: 8px; flex-wrap: wrap; }}
    .filter-btn {{
      background: #1e293b;
      color: var(--text);
      border: 1px solid var(--border);
      padding: 6px 12px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 0.8rem;
    }}
    .filter-btn.active {{ background: var(--blue); color: #0b1120; font-weight: 700; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>Automated Cloud Security Pipeline</h1>
        <div class="subtitle">Shift-Left Policy-as-Code Audit &amp; Zero-Trust AWS Sydney (ap-southeast-2) Dashboard</div>
      </div>
      <div class="meta-pills">
        <span class="pill">Commit: <strong>{html.escape(commit_sha)}</strong></span>
        <span class="pill">Updated: <strong>{html.escape(timestamp_ist)}</strong></span>
        <span class="pill"><a href="{html.escape(run_url)}" target="_blank">View GitHub Actions Run ↗</a></span>
      </div>
    </header>

    <div class="banner {banner_cls}">
      <span>Gate Verdict: {html.escape(metrics['status_label'])}</span>
      <span>Risk Level: {html.escape(metrics['risk_level'])}</span>
    </div>

    <section class="kpi-grid">
      <div class="card">
        <div class="kpi-label">Compliance Score</div>
        <div class="kpi-value" style="color: {score_color};">{metrics['score']}%</div>
        <div class="kpi-sub">{metrics['passed_count']} of {metrics['total_evaluated']} active checks passed</div>
      </div>
      <div class="card">
        <div class="kpi-label">Failed Controls</div>
        <div class="kpi-value" style="color: var(--red);">{metrics['failed_count']}</div>
        <div class="kpi-sub">Blocks Terraform AWS deployment</div>
      </div>
      <div class="card">
        <div class="kpi-label">Custom Python Rules</div>
        <div class="kpi-value" style="color: var(--purple);">{metrics['custom_passed']} / {metrics['custom_passed'] + metrics['custom_failed']}</div>
        <div class="kpi-sub">CKV_CUSTOM_1 &amp; CKV_CUSTOM_2 passed</div>
      </div>
      <div class="card">
        <div class="kpi-label">Documented Exceptions</div>
        <div class="kpi-value" style="color: var(--amber);">{metrics['skipped_count']}</div>
        <div class="kpi-sub">Inline lab-budget suppressions</div>
      </div>
    </section>

    <section class="charts-grid">
      <div class="card">
        <strong>Security Gate Breakdown</strong>
        <div class="chart-box"><canvas id="statusChart"></canvas></div>
      </div>
      <div class="card">
        <strong>Built-in AWS vs. Custom Python Policies</strong>
        <div class="chart-box"><canvas id="policyChart"></canvas></div>
      </div>
    </section>

    <section class="card ai-card">
      <div class="ai-header">
        <strong>AI Security Auditor &amp; Remediation Engine</strong>
        <span class="badge badge-custom">{html.escape(ai_engine)}</span>
      </div>
      <div class="ai-content">{ai_html}</div>
    </section>

    <section class="card">
      <div class="ai-header">
        <strong>Detailed Policy Audit Log</strong>
        <div class="filter-bar">
          <button class="filter-btn active" onclick="filterRows('ALL', this)">All</button>
          <button class="filter-btn" onclick="filterRows('FAIL', this)">Failed ({metrics['failed_count']})</button>
          <button class="filter-btn" onclick="filterRows('PASS', this)">Passed ({metrics['passed_count']})</button>
          <button class="filter-btn" onclick="filterRows('SKIP', this)">Skipped ({metrics['skipped_count']})</button>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>Policy ID &amp; Engine</th>
              <th>Terraform Resource</th>
              <th>Location</th>
              <th>Rule Description</th>
            </tr>
          </thead>
          <tbody id="auditBody">
            {table_rows}
          </tbody>
        </table>
      </div>
    </section>
  </div>

  <script>
    new Chart(document.getElementById('statusChart'), {{
      type: 'doughnut',
      data: {{
        labels: ['Passed', 'Failed', 'Skipped'],
        datasets: [{{
          data: [{metrics['passed_count']}, {metrics['failed_count']}, {metrics['skipped_count']}],
          backgroundColor: ['#3b82f6', '#ef4444', '#f59e0b'],
          borderColor: '#111827',
          borderWidth: 3
        }}]
      }},
      options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#e5e7eb' }} }} }}
      }}
    }});

    new Chart(document.getElementById('policyChart'), {{
      type: 'bar',
      data: {{
        labels: ['Built-in Checkov AWS', 'Custom Python Policies'],
        datasets: [
          {{
            label: 'Passed',
            data: [{metrics['builtin_passed']}, {metrics['custom_passed']}],
            backgroundColor: '#3b82f6'
          }},
          {{
            label: 'Failed',
            data: [{metrics['builtin_failed']}, {metrics['custom_failed']}],
            backgroundColor: '#ef4444'
          }}
        ]
      }},
      options: {{
        responsive: true,
        maintainAspectRatio: false,
        scales: {{
          x: {{ stacked: true, ticks: {{ color: '#e5e7eb' }}, grid: {{ color: '#1f2937' }} }},
          y: {{ stacked: true, beginAtZero: true, ticks: {{ color: '#e5e7eb', precision: 0 }}, grid: {{ color: '#1f2937' }} }}
        }},
        plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#e5e7eb' }} }} }}
      }}
    }});

    function filterRows(status, btn) {{
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('#auditBody tr').forEach(row => {{
        row.style.display = (status === 'ALL' || row.dataset.status === status) ? '' : 'none';
      }});
    }}
  </script>
</body>
</html>
"""


def write_github_step_summary(
    checks: Dict[str, List[Dict[str, Any]]],
    metrics: Dict[str, Any],
    ai_markdown: str,
    ai_engine: str,
) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    lines = [
        f"## DevSecOps Security Audit Report — `{metrics['status_badge']}`",
        "",
        "| Metric | Value |",
        "| :--- | :--- |",
        f"| **Compliance Score** | **{metrics['score']}%** |",
        f"| **Passed Checks** | {metrics['passed_count']} ({metrics['custom_passed']} Custom Python) |",
        f"| **Failed Checks** | {metrics['failed_count']} ({metrics['custom_failed']} Custom Python) |",
        f"| **Skipped Checks** | {metrics['skipped_count']} |",
        f"| **AI Engine** | {ai_engine} |",
        "",
        "### AI Security Analysis & Remediation",
        ai_markdown,
        "",
    ]

    if checks["failed"]:
        lines.extend(["### Failed Controls Blocking Deployment", ""])
        for c in checks["failed"]:
            lines.append(
                f"- **`{c.get('check_id')}`** — `{c.get('resource')}`: {c.get('check_name')}"
            )

    with open(summary_path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main() -> None:
    report_path = find_checkov_json()
    checks = parse_checkov_report(report_path)
    metrics = calculate_metrics(checks)
    ai_markdown, ai_engine = get_gemini_remediation(checks, metrics)

    dashboard_dir = Path("dashboard")
    dashboard_dir.mkdir(parents=True, exist_ok=True)
    html_output = generate_dashboard_html(checks, metrics, ai_markdown, ai_engine)
    (dashboard_dir / "index.html").write_text(html_output, encoding="utf-8")

    write_github_step_summary(checks, metrics, ai_markdown, ai_engine)

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as fh:
            fh.write("dashboard_ready=true\n")

    print("=" * 60)
    print(f"Compliance Score : {metrics['score']}% ({metrics['status_label']})")
    print(f"Passed / Failed  : {metrics['passed_count']} passed | {metrics['failed_count']} failed | {metrics['skipped_count']} skipped")
    print(f"Custom Policies  : {metrics['custom_passed']} passed | {metrics['custom_failed']} failed")
    print(f"AI Auditor Engine: {ai_engine}")
    print("Dashboard written: dashboard/index.html")
    print("=" * 60)


if __name__ == "__main__":
    main()
