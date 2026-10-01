"""The service's source of truth: ruleset + known-vulnerable MCP server registry.

CLI/actions are THIN consumers of this. The registry is what makes the
service 'independent and tailored' - it is transport-agnostic data served
over any channel (HTTP here, but could be a file, git, or CDN).
"""
import json
import os
import time

# Version bump on any ruleset change so consumers can pin and diff.
RULES_VERSION = "2026.09.01"

# NSA May-2026 MCP threat taxonomy (11 categories) -- abridged to those the
# baseline scanner can detect purely from config/source inspection.
TAXONOMY = {
    "HARDCODED_SECRET": "Credential material (API keys/tokens) present in config or source.",
    "TOOL_POISONING": "Tool description or schema engineered to trick/mislead agents.",
    "UNVERIFIED_SERVER": "Server from an unverified/community registry with no publisher pin.",
    "NETWORK_EGRESS": "Server that sends data to a remote endpoint (URL/SSE/http transport).",
    "TOOL_PATH_CONFUSION": "Name collisions or canopy-shadowing between servers.",
    "STALE_VERSION": "Server pinned to a version with a known CVE or an unpinned/floating ref.",
}

# Known-vulnerable public MCP servers: (registry_name, transports, [CVEs], note)
KNOWN_VULNERABLE = {
    "fetch": {
        "match_keys": ["fetch", "mcp-server-fetch"],
        "transports": ["stdio", "sse"],
        "cves": ["CVE-2026-14540"],
        "note": "SSRF in URL input (Google MCP Toolbox family).",
    },
    "toolbox-databases": {
        "match_keys": ["toolbox", "mcp-toolbox", "databases"],
        "transports": ["stdio", "sse"],
        "cves": ["CVE-2026-11719"],
        "note": "AuthZ bypass: protocol-version header downgrade lets low-priv token call admin tools.",
    },
}

# Unverified / risky server-name substrings. Deliberately conservative.
RISKY_NAME_HINTS = ("community", "unverified", "unofficial", "hack")
FILE_NAME_HINTS = ("filesystem", "git", "shell", "exec", "bash", "ssh")

# Config files we know how to find. Keyed by display name for the report.
TARGETS = [
    {"name": "Claude Code", "glob": "**/.mcp.json"},
    {"name": "Cursor", "glob": "**/.cursor/mcp.json"},
    {"name": "Claude Desktop", "glob": "**/claude_desktop_config.json"},
]


def build_baseline() -> dict:
    """Local rules bundled into every binary so the CLI never depends on the
    network to be correct. Feed freshness is an ENRICHMENT, never a necessity.
    """
    return {
        "rules_version": RULES_VERSION,
        "taxonomy": TAXONOMY,
        "known_vulnerable": KNOWN_VULNERABLE,
        "risky_name_hints": RISKY_NAME_HINTS,
        "file_name_hints": FILE_NAME_HINTS,
    }


def serve_payload() -> dict:
    """What /v1/registry returns. Includes an installed-here flag so the
    action can report whether it talked to this service or a bundled copy.
    """
    return {
        "service": "mcp-audit",
        "feed_version": RULES_VERSION,
        "generated_at": int(time.time()),
        "instances_served": int(os.environ.get("MCPA_INSTANCE", "0")) + 1,
        **build_baseline(),
    }