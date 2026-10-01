"""POC scanner: config/source inspection for MCP servers.

Emit the audit-report.json standard. Functions are pure -> testable. The
network feed is optional enrichment layered on top (see cli/).

Trust boundary: configs are attacker-influenced input. We bound file size,
never eval, never follow symlinks out of the audit root, and treat every
string as untrusted data.
"""
import json
import re
from pathlib import Path

from api.feed import build_baseline

SCHEMA_VERSION = "1.0.0"
MAX_CONFIG_BYTES = 2_000_000  # refuse absurd files (DoS guard)

# Credential patterns for config/source. Conservative: prefer false positive
# over missing (this is a gate, not an auto-fixer).
SECRET_PATTERNS = [
    (re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9-]{14,}\b"), "OpenAI-style API key"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "GitHub PAT"),
    (re.compile(r"\bgho_[A-Za-z0-9]{20,}\b"), "GitHub OAuth token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "JWT"),
    (re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*['\"][A-Za-z0-9_\-/+=.@]{12,}"), "inline secret assignment"),
]
CREDENTIAL_URL = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s@]+@")
# Word-boundary patterns so 'git' does not match 'github'
FILE_REMOTE_HINTS = (
    r"\bfilesystem\b", r"\bshell\b", r"\bexec(ute|ution)?\b",
    r"\bbash\b", r"\bssh\b", r"\bchown\b", r"\bchmod\b",
    r"npx[^\"]*server-filesystem", r"uvx[^\"]*server-filesystem",
)


def _load_configs(root: Path, feed: dict) -> list:
    """Find MCP config files known to major AI clients. Bounded + symlink-safe."""
    found = []
    root = root.resolve()
    for tgt in feed.get("targets") or _default_targets():
        for p in root.rglob(tgt["glob"]):
            try:
                rp = p.resolve()
                if not str(rp).startswith(str(root)):
                    continue  # symlink escape guard
                if p.is_symlink() or p.stat().st_size > MAX_CONFIG_BYTES:
                    continue
                data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError, ValueError):
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
    for name, defn in container.items():
        if not isinstance(defn, dict):
            continue
        transport = "stdio"
        url = None
        command = None
        args = defn.get("args") if isinstance(defn.get("args"), list) else []
        env = defn.get("env") if isinstance(defn.get("env"), dict) else {}
        if "url" in defn and isinstance(defn["url"], str):
            transport = "http" if defn["url"].startswith(("http://", "https://")) else "sse"
            url = defn["url"]
        if "command" in defn:
            command = defn["command"]
        servers.append({
            "name": name,
            "transport": transport,
            "url": url,
            "command": command,
            "args": [a for a in args if isinstance(a, str)],
            "env": {k: v for k, v in env.items() if isinstance(v, str)},
        })
    return servers


def _scan_text_for_secrets(text: str) -> list:
    hits = []
    for pat, label in SECRET_PATTERNS:
        if pat.search(text):
            hits.append(label)
    return hits


def _audit_servers(servers: list, feed: dict) -> list:
    """Rules eval. Each returns findings. Pure and side-effect-free."""
    findings = []
    risky = feed["risky_name_hints"]
    known = feed["known_vulnerable"]

    def _secret_hits(s):
        return _scan_text_for_secrets(json.dumps(s, default=str))

    for i, s in enumerate(servers, 1):
        name = (s["name"] or "").lower()
        blob = json.dumps(s, default=str).lower()
        # 1. Known-vulnerable registry hit.
        for reg_name, rec in known.items():
            if any(k in name for k in rec["match_keys"]):
                findings.append({
                    "id": f"MCPA-{i:03d}", "severity": "critical",
                    "category": "STALE_VERSION", "server": s["name"],
                    "cve": rec["cves"][0], "message": f"Known-vulnerable server: {rec['note']}",
                })
        # 2. Unverified registry name hint.
        if any(h in name for h in risky):
            findings.append({
                "id": f"MCPA-{i:03d}", "severity": "high",
                "category": "UNVERIFIED_SERVER", "server": s["name"],
                "message": "Server lookalike unverified-registry name (community/unverified/unofficial).",
            })
        # 3. Hardcoded credential material anywhere in the server def.
        for label in _secret_hits(s):
            findings.append({
                "id": f"MCPA-{i:03d}", "severity": "high",
                "category": "HARDCODED_SECRET", "server": s["name"],
                "message": f"Possible credential in server definition: {label}.",
                "evidence": "redacted",
            })
        # 4. Credentials embedded in a transport URL.
        if s["url"] and CREDENTIAL_URL.search(s["url"]):
            findings.append({
                "id": f"MCPA-{i:03d}", "severity": "high",
                "category": "HARDCODED_SECRET", "server": s["name"],
                "message": "Transport URL embeds credentials (user:pass@host).",
            })
        # 5. Filesystem/shell-capable command unpinned.
        if any(re.search(p, blob) for p in FILE_REMOTE_HINTS) and transport_is_local(s) and not name_pinned(s):
            findings.append({
                "id": f"MCPA-{i:03d}", "severity": "medium",
                "category": "TOOL_POISONING", "server": s["name"],
                "message": "Filesystem/shell-capable server command is unpinned (floating ref).",
            })
        # 6. Network egress server.
        if s["transport"] in ("http", "sse", "ws"):
            findings.append({
                "id": f"MCPA-{i:03d}", "severity": "info",
                "category": "NETWORK_EGRESS", "server": s["name"],
                "message": f"Remote transport; data leaves host: {s['url']}",
            })
    return findings


def _shadow_findings(servers: list) -> list:
    """Same server name defined more than once across config files.
    Run on the RAW (pre-dedup) list, because dedup would already have removed
    the second occurrence by the time the main audit sees it.
    """
    counts = {}
    for s in servers:
        counts[s["name"].lower()] = counts.get(s["name"].lower(), 0) + 1
    findings = []
    for name, n in counts.items():
        if n > 1:
            findings.append({
                "id": "MCPA-TOOLPATH", "severity": "medium",
                "category": "TOOL_PATH_CONFUSION", "server": name,
                "message": f"Server '{name}' defined {n} times (namespace shadowing risk).",
            })
    return findings


def transport_is_local(s: dict) -> bool:
    return s["transport"] == "stdio"


def name_pinned(s: dict) -> bool:
    """Pinned == a version is explicitly specified (X@Y or X.Y.Z anywhere in
    the server def). Bare 'latest' / no version = unpinned."""
    for p in [s.get("name", "") or "", s.get("command", "") or "", *s.get("args", [])]:
        if not p:
            continue
        if "latest" in p.lower():
            return False
        if "@" in p or re.search(r"\d+\.\d+", p):
            return True
    return False


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


def run_audit(root, feed: dict | None = None) -> dict:
    import datetime
    root = Path(root)
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
    shadow = _shadow_findings(servers)  # use pre-dedup list to catch cross-config dupes
    findings.extend(shadow)
    return {
        "schema_version": SCHEMA_VERSION,
        "target": str(root),
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": {"feed_url": None, "feed_ok": True, "rules_version": feed["rules_version"]},
        "servers": uniq,
        "findings": findings,
        "summary": _summarize(uniq, findings),
    }