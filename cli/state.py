"""Stateful rug-pull detection: SHA-256 of tool definitions across scans.

The 'standard' needs a memory. This is the CLI's local memory, stored in a
git-committable file so a rug-pull (tool description changes between scans)
becomes a reviewable diff in a PR - the same shape as a lockfile.

Deliberately boring: one hash file, pure functions, no network.
"""
import hashlib
import json
from pathlib import Path

STATE_FILE = ".mcp-audit-state.json"


def fingerprint(servers: list) -> dict:
    """Stable hash of each server's observable definition."""
    out = {}
    for s in sorted(servers, key=lambda x: x["name"]):
        blob = json.dumps(
            {"n": s["name"], "t": s["transport"], "c": s.get("command"), "u": s.get("url")},
            sort_keys=True,
        )
        out[s["name"]] = hashlib.sha256(blob.encode()).hexdigest()
    return out


def check_rug_pull(root: Path, servers: list) -> list:
    """Compare current fingerprints to the previous state file.
    Returns findings for any server whose definition changed unexpectedly.
    """
    findings = []
    current = fingerprint(servers)
    state_path = root / STATE_FILE
    if not state_path.exists():
        return findings  # first scan: nothing to compare yet
    prev = json.loads(state_path.read_text())
    for name, h in current.items():
        if name in prev and prev[name] != h:
            findings.append({
                "id": f"RUG-{name}",
                "severity": "high",
                "category": "TOOL_POISONING",
                "server": name,
                "message": "Server definition changed since last audit (possible rug-pull). Review the diff.",
            })
    return findings


def save_state(root: Path, servers: list) -> None:
    (root / STATE_FILE).write_text(json.dumps(fingerprint(servers), indent=2))
