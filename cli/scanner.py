"""POC scanner: config/source inspection for MCP servers.

Emit the audit-report.json standard. Functions are pure -> testable. The
network feed is optional enrichment layered on top (see cli/).
"""
import json
from pathlib import Path

from api.feed import TAXONOMY, build_baseline

SCHEMA_VERSION = "1.0.0"


def _load_configs(root: Path, feed: dict) -> list:
    """Find MCP config files known to major AI clients. Pure file discovery."""
    found = []
    for tgt in feed["targets"] if "targets" in feed else _default_targets():
        for p in root.rglob(tgt["glob"]):
            try:
                data = json.loads(p.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            found.append({"name": tgt["name"], "path": str(p), "data": data})
    return found


def _default_targets():
    return [
        {"name": "Claude Code", "glob": ".mcp.json"},
        {"name": "Cursor", "glob": ".cursor/mcp.json"},
    ]


def _extract_servers(config: dict) -> list:
    """Normalize the many shapes of MCP config into a flat server list.
    Handles: {mcpServers:{}}, {servers:{}}, {mcp:{servers:{}}}, Cursor {mcp:{}}.
    """
    raw = config
    servers = []
    container = None
    # Hunt for the map of server-name -> def. Try several known wrappers.
    if "mcpServers" in raw:
        container = raw["mcpServers"]
    elif "servers" in raw:
        container = raw["servers"]
    elif "mcp" in raw and isinstance(raw["mcp"], dict):
        container = raw["mcp"].get("servers", raw["mcp"])
    if not container:
        return servers
    for name, defn in (container.items() if isinstance(container, dict) else []):
        if not isinstance(defn, dict):
            continue
        # Transport detection
        transport = "stdio"
        url = None
        command = None
        if "url" in defn:
            transport = "http" if defn["url"].startswith(("http://", "https://")) else "sse"
            url = defn["url"]
        if "command" in defn:
            command = defn["command"]
        servers.append({
            "name": name,
            "transport": transport,
            "url": url,
            "command": command,
        })
    return servers


def _audit_servers(servers: list, feed: dict) -> list:
    """Rules eval. Each returns findings. Pure and side-effect-free."""
    findings = []
    risky = feed["risky_name_hints"]
    fhints = feed["file_name_hints"]
    known = feed["known_vulnerable"]

    n = 0
    for s in servers:
        n += 1
        name = (s["name"] or "").lower()
        cmd = (s["command"] or "").lower()
        # 1. Known-vulnerable registry hit.
        for reg_name, rec in known.items():
            if any(k in name for k in rec["match_keys"]):
                findings.append({
                    "id": f"MCPA-{n:03d}", "severity": "critical",
                    "category": "STALE_VERSION", "server": s["name"],
                    "cve": rec["cves"][0], "message": f"Known-vulnerable server: {rec['note']}",
                })
        # 2. Unverified registry name hint.
        if any(h in name for h in risky):
            findings.append({
                "id": f"MCPA-{n:03d}", "severity": "high",
                "category": "UNVERIFIED_SERVER", "server": s["name"],
                "message": "Server lookalike unverified-registry name (community/unverified/unofficial).",
            })
        # 3. File/shell remoting capability without pinning = poison surface.
        if any(h in cmd for h in fhints) and transport_is_local(s) and not name_pinned(s):
            findings.append({
                "id": f"MCPA-{n:03d}", "severity": "medium",
                "category": "TOOL_POISONING", "server": s["name"],
                "message": "Filesystem/shell-capable server command is unpinned (floating ref).",
            })
        # 4. Network egress server.
        if s["transport"] in ("http", "sse", "ws"):
            findings.append({
                "id": f"MCPA-{n:03d}", "severity": "info",
                "category": "NETWORK_EGRESS", "server": s["name"],
                "message": f"Remote transport, data leaves host: {s['url']}",
            })
    return findings


def transport_is_local(s: dict) -> bool:
    return s["transport"] == "stdio"


def name_pinned(s: dict) -> bool:
    # Heuristic: pinned means 'name@version' or 'name-1.2.3' in command path/args.
    cmd = s.get("command", "") or ""
    return ("@" in cmd) or any(ch.isdigit() for ch in (s.get("name", ""))[-2:])


def _summarize(servers: list, findings: list) -> dict:
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    if by_sev["critical"] or by_sev["high"]:
        verdict = "fail"
    elif by_sev["medium"]:
        verdict = "review"
    else:
        verdict = "pass"
    return {
        "total_servers": len(servers),
        "total_findings": len(findings),
        "by_severity": by_sev,
        "verdict": verdict,
    }


def run_audit(root: Path, feed: dict | None = None) -> dict:
    feed = feed or build_baseline()
    configs = _load_configs(root, feed)
    servers = []
    for c in configs:
        servers.extend(_extract_servers(c["data"]))
    # dedupe by name+transport to avoid counting the same server twice
    seen = set()
    uniq = []
    for s in servers:
        k = (s["name"], s["transport"])
        if k not in seen:
            seen.add(k)
            uniq.append(s)
    findings = _audit_servers(uniq, feed)
    return {
        "schema_version": SCHEMA_VERSION,
        "target": str(root),
        "scanned_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat(),
        "source": {"feed_url": None, "feed_ok": True, "rules_version": feed["rules_version"]},
        "servers": uniq,
        "findings": findings,
        "summary": _summarize(uniq, findings),
    }


if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import json as _json
    # quick self-check
    from pathlib import Path as _P
    p = _P(__file__).parent.parent / "examples" / "sample-config.json"
    if p.exists():
        import tempfile, shutil
        # copy config into a temp dir to mimic a project
        tmp = _P(tempfile.mkdtemp())
        shutil.copy(p, tmp / ".mcp.json")
        rep = run_audit(tmp)
        print(_json.dumps(rep, indent=2, default=str))
    else:
        print("no example; run scanner on a dir")