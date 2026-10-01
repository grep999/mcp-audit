"""Contract tests for the report renderers. Pure; no network, no fixtures."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from cli.report import to_text, to_markdown, to_github_annotations, SEV_BADGE

REPORT = {
    "schema_version": "1.0.0",
    "target": "/repo",
    "scanned_at": "2026-09-01T12:00:00+00:00",
    "source": {"feed_url": None, "feed_ok": True, "rules_version": "2026.09.01"},
    "servers": [{"name": "fetch", "transport": "stdio", "command": "uvx"}, {"name": "db", "transport": "http", "url": "https://db.corp"}],
    "findings": [
        {"id": "MCPA-001", "severity": "critical", "category": "STALE_VERSION", "server": "fetch", "cve": "CVE-2026-14540", "message": "Known-vulnerable server."},
        {"id": "MCPA-002", "severity": "info", "category": "NETWORK_EGRESS", "server": "db", "message": "Remote transport, data leaves host."},
    ],
    "summary": {"total_servers": 2, "total_findings": 2, "by_severity": {"critical": 1, "info": 1}, "verdict": "fail"},
}


def test_text():
    out = to_text(REPORT)
    assert "CVE-2026-14540" in out
    assert "!!" in out
    print("PASS text render")


def test_markdown():
    out = to_markdown(REPORT)
    assert "## Findings" in out
    assert "STALE_VERSION" in out
    assert "CVE-2026-14540" in out
    assert "## Server inventory" in out
    print("PASS markdown render")


def test_annotations():
    out = to_github_annotations(REPORT)
    assert "::error" in out
    assert "::warning" not in out  # no findings at that level
    print("PASS GH annotations")


if __name__ == "__main__":
    test_text()
    test_markdown()
    test_annotations()
    print("\nAll report tests passed")