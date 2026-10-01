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


def test_hardcoded_secret_and_credential_url():
    """Env secrets and creds embedded in URLs yield HARDCODED_SECRET high findings."""
    rep = _audit({"mcpServers": {
        "leaky": {"command": "python", "args": ["s"], "env": {"API_KEY": "sk-proj-abcdef0123456789abcdef0123"}}
    }})
    assert rep["summary"]["verdict"] == "fail"
    sevs = [f["severity"] for f in rep["findings"]]
    assert "high" in sevs, f"expected high finding, got {sevs}"
    print("PASS hardcoded secret (env) detection")


def test_credential_url_catch():
    rep = _audit({"mcpServers": {
        "db": {"url": "https://user:password123@internal.corp/db"}
    }})
    assert any(f["category"] == "HARDCODED_SECRET" for f in rep["findings"]), "cred URL not flagged"
    print("PASS credential-URL detection")


def test_pinned_vs_floating():
    from cli.scanner import name_pinned
    assert not name_pinned({"name": "x", "command": "", "args": ["-y", "server@latest"]}), "latest should be unpinned"
    assert name_pinned({"name": "x", "command": "", "args": ["@modelcontextprotocol/server-github@2.0.1"]}), "pinned version"
    print("PASS pin detection")


def test_duplicate_name_shadowing():
    """A server name defined in two configs (Claude + Cursor) is shadowing."""
    import json as _json
    tmp = Path(tempfile.mkdtemp())
    (tmp / ".mcp.json").write_text(_json.dumps({"mcpServers": {"github": {"command": "npx", "args": ["a"]}}}))
    cdir = tmp / ".cursor"; cdir.mkdir()
    (cdir / "mcp.json").write_text(_json.dumps({"mcpServers": {"github": {"command": "npx", "args": ["b"]}}}))
    rep = run_audit(tmp)
    assert any(f["category"] == "TOOL_PATH_CONFUSION" for f in rep["findings"]), "shadowing not caught"
    print("PASS cross-config shadowing")


def test_cursor_wrapper():
    rep = _audit({"mcp": {"servers": {
        "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@2.0.1"]}
    }}})
    assert len(rep["servers"]) == 1 and rep["servers"][0]["name"] == "github", f"got {rep['servers']}"
    assert rep["summary"]["verdict"] == "pass"
    print("PASS cursor wrapper parse")


def test_huge_config_ignored():
    """Oversized config is skipped (DoS guard), and the audit still completes."""
    tmp = Path(tempfile.mkdtemp())
    (tmp / ".mcp.json").write_text("{\"data\": \"" + "a" * 2_500_000 + "\"}")
    rep = run_audit(tmp)
    assert len(rep["servers"]) == 0, "oversized config should be ignored"
    print("PASS oversized config guard")


def test_symlink_escape_ignored():
    """A config that symlinks outside the audit root must not be read."""
    import os
    outer = Path(tempfile.mkdtemp())
    inner = Path(tempfile.mkdtemp())
    (outer / "secret.mcp.json").write_text('{"mcpServers": {"fetch": {"command": "uvx"}}}')
    try:
        (inner / ".mcp.json").symlink_to(outer / "secret.mcp.json")
    except OSError:
        print("SKIP symlink test (no symlink support)")
        return
    rep = run_audit(inner)
    assert len(rep["servers"]) == 0, "symlink escape should be ignored, got servers"
    print("PASS symlink-escape guard")


if __name__ == "__main__":
    test_schema_conformance()
    test_known_vuln_detected()
    test_clean_config_passes()
    test_rug_pull_detection()
    test_hardcoded_secret_and_credential_url()
    test_credential_url_catch()
    test_pinned_vs_floating()
    test_duplicate_name_shadowing()
    test_cursor_wrapper()
    test_huge_config_ignored()
    test_symlink_escape_ignored()
    print("\nAll tests passed")