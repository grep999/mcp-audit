"""Contract test: the scanner's output matches audit-report.json schema, and
known-CVE detection works. Run: python3 tests/test_audit.py
"""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cli.scanner import run_audit

ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _audit(servers_cfg: dict) -> dict:
    tmp = Path(tempfile.mkdtemp())
    (tmp / ".mcp.json").write_text(json.dumps(servers_cfg))
    return run_audit(tmp)


def test_schema_conformance():
    """Every report must validate against the shipped schema (or at least hit
    every required key -- we keep the schema file as the single source)."""
    rep = _audit({"mcpServers": {"github": {"command": "npx", "args": ["x"]}}})
    schema = json.loads((ROOT / "schemas" / "audit-report.json").read_text())
    required = schema["required"]
    assert all(k in rep for k in required), f"missing required keys: {required}"
    assert rep["schema_version"] == schema["properties"]["schema_version"]["const"]
    print("PASS schema conformance")


def test_known_vuln_detected():
    rep = _audit({"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}})
    assert rep["summary"]["verdict"] == "fail"
    sevs = [f["severity"] for f in rep["findings"]]
    assert "critical" in sevs, f"expected critical finding, got {sevs}"
    assert any(f["cve"] == "CVE-2026-14540" for f in rep["findings"]), "wrong/specific CVE"
    print("PASS known-CVE detection")


def test_clean_config_passes():
    rep = _audit({"mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@2.0.1"]}}})
    assert rep["summary"]["verdict"] == "pass", f"expected pass, got {rep['summary']['verdict']}"
    print("PASS clean config")


def test_rug_pull_detection():
    from cli.state import check_rug_pull, save_state
    s1 = [{"name": "db", "transport": "stdio", "command": "mcp-db", "url": None}]
    s2 = [{"name": "db", "transport": "stdio", "command": "mcp-db-evil", "url": None}]
    tmp = Path(tempfile.mkdtemp())
    save_state(tmp, s1)
    findings = check_rug_pull(tmp, s2)
    assert any(f["category"] == "TOOL_POISONING" for f in findings), "rug-pull not caught"
    print("PASS rug-pull detection")


if __name__ == "__main__":
    test_schema_conformance()
    test_known_vuln_detected()
    test_clean_config_passes()
    test_rug_pull_detection()
    print("\nAll tests passed")