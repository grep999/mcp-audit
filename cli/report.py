"""Render an audit report (audit-report.json) as a human-readable deliverable.

Two formats, both pure functions over the report dict:
  - text:   terminal summary
  - markdown: the client-facing artefact (the thing someone pays for)

No network, no deps. The report dict is the only input -> trivially testable.
"""
from collections import Counter

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_BADGE = {"critical": "!!", "high": "!", "medium": "~", "low": ".", "info": "i"}


def to_text(report: dict) -> str:
    s = report["summary"]
    lines = [
        f"mcp-audit  target={report['target']}",
        f"  rules={report['source'].get('rules_version')} feed_ok={report['source'].get('feed_ok')}",
        f"  servers={s['total_servers']} findings={s['total_findings']} verdict={s['verdict'].upper()}",
        "",
    ]
    if not report["findings"]:
        lines.append("  No findings.")
        return "\n".join(lines)
    for f in sorted(report["findings"], key=lambda x: SEV_ORDER.index(x["severity"])):
        badge = SEV_BADGE[f["severity"]]
        cve = f" [{f['cve']}]" if f.get("cve") else ""
        lines.append(f"  {badge} {f['severity']:8} {f['category']:18} {f['server']:16}{cve}")
        lines.append(f"      {f['message']}")
    return "\n".join(lines)


def to_markdown(report: dict) -> str:
    s = report["summary"]
    counts = s["by_severity"]
    lines = [
        "# MCP Security Audit",
        "",
        f"**Target:** `{report['target']}`  ",
        f"**Scanned:** {report['scanned_at']}  ",
        f"**Ruleset:** {report['source'].get('rules_version')} "
        f"({'live feed' if report['source'].get('feed_ok') else 'bundled baseline'})  ",
        f"**Verdict:** `{s['verdict'].upper()}`",
        "",
        f"{s['total_servers']} MCP servers audited, {s['total_findings']} findings: "
        + ", ".join(f"{counts.get(k, 0)} {k}" for k in SEV_ORDER if counts.get(k, 0)),
        "",
    ]
    if not report["findings"]:
        lines += ["No findings. Nothing to remediate.", ""]
        return "\n".join(lines)

    lines += ["## Findings", ""]
    by_cat = {}
    for f in report["findings"]:
        by_cat.setdefault(f["category"], []).append(f)
    for cat, items in sorted(by_cat.items()):
        lines.append(f"### {cat} ({len(items)})")
        lines.append("")
        for f in sorted(items, key=lambda x: SEV_ORDER.index(x["severity"])):
            cve = f" — `{f['cve']}`" if f.get("cve") else ""
            lines.append(f"- **{f['severity']}** · `{f['server']}`{cve}")
            lines.append(f"  - {f['message']}")
        lines.append("")

    lines += ["## Server inventory", "", "| Server | Transport | Command/URL |", "|---|---|---|"]
    for sv in report["servers"]:
        dest = sv.get("url") or sv.get("command") or "-"
        lines.append(f"| `{sv['name']}` | {sv['transport']} | `{dest}` |")
    lines.append("")
    return "\n".join(lines)


def to_github_annotations(report: dict) -> str:
    """Emit ::warning/::error lines GitHub Actions understands in logs."""
    out = []
    for f in report["findings"]:
        if f["severity"] in ("critical", "high", "medium"):
            lvl = "error" if f["severity"] in ("critical", "high") else "warning"
            msg = f"[{f['category']}] {f['server']}: {f['message']}".replace("\n", " ")
            out.append(f"::{lvl} file=.mcp.json,title=mcp-audit::{msg}")
    return "\n".join(out)