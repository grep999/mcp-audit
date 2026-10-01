# mcp-audit

Audit the MCP servers in a repo before an AI agent trusts them.

MCP (Model Context Protocol) connects AI agents to real tools — filesystem,
DBs, shell. In 2026 adoption outran security: ~97M SDK downloads/month, a
CISA-exploited CVE in an official Google MCP server, and an NSA threat taxonomy
published May 2026. Most teams have MCP configured and no gate. This is the
gate.

## What it checks (NSA May-2026 taxonomy)

- **HARDCODED_SECRET** — keys/tokens in config or source
- **TOOL_POISONING** — tool descriptions engineered to mislead agents; **rug-pull**
  (definition changed since last scan)
- **UNVERIFIED_SERVER** — community/unverified/unofficial registry name
- **NETWORK_EGRESS** — server that sends data off-host (SSE/http transport)
- **STALE_VERSION** — pinned to a version with a known CVE (registry)

## Architecture (the part that makes it a *standard*)

```
                ┌─────────────────────────────────────────────┐
                │  THE STANDARD (transport-agnostic)          │
                │  ┌───────────┐   ┌───────────────────────┐  │
                │  │  SCANNER  │   │  audit-report.json    │  │
                │  │ (pure)    │──▶│  schema v1.0.0        │  │
                │  └───────────┘   │  = the contract       │  │
                │  ┌───────────┐   └───────────────────────┘  │
                │  │  FEED     │   ┌───────────────────────┐  │
                │  │ /v1/registry│ │  state.json           │  │
                │  │ (rules+CVE) │ │  = rug-pull memory    │  │
                │  └───────────┘   └───────────────────────┘  │
                └─────────────────────────────────────────────┘
                        ▲         ▲          ▲
                   ┌────┘         │          └────┐
              GitHub Action    CLI         API     ← delivery channels
              (action/)      (cli/)       (api/)    are THIN adapters
```

The scanner and the report schema are the **standard**. They are pure,
side-effect-free, and need **no network to be correct** — every binary ships a
bundled baseline ruleset so an audit is always authoritative on its own. The
service (`/v1/registry`) is **optional enrichment**: live CVE registry + rules.
A feed outage degrades to baseline; it never blocks or silently passes.

Delivery channels (GitHub Action, CLI, API) are **thin adapters** over the same
scanner. GitHub Actions is *one* channel, not the product — the same scanner
drops into GitLab CI, pre-commit, or a local `make check` unchanged. That
decoupling is what makes it adoptable as a standard instead of a vendor lock.

## Quick start

```bash
# audit a repo (finds .mcp.json, .cursor/mcp.json, claude_desktop_config.json)
python3 -m cli.main scan .
# exit codes: 0=pass 1=fail 2=review  → gate directly in CI

# CI gate
python3 -m cli.main scan . --commit-state   # writes .mcp-audit-state.json
```

Contract tests: `python3 tests/test_audit.py` (4 checks, no network).

## How this becomes a standard (the thesis)

1. **Own the output contract.** `audit-report.json` v1.0.0 is the thing tools
   interop on. Anything that can emit that schema is "mcp-audit compliant".
   Pinning = versioning = the standard lives in the data, not the vendor.
2. **Be correct offline.** A standard that dies when its cloud is down is a
   product. Ship the rules in the binary; treat the feed as a cache refresh.
3. **Be the source of the CVE registry.** The registry (`feed.py`) is the
   moat. Start small (2 entries), grow it as MCP servers ship CVEs, publish it
   as a daily JSON feed. The feed *is* the content marketing / lead gen.
4. **State is a git-committable lockfile.** Rug-pull detection works because
   the previous scan is in version control — a change to your agents' tools
   shows up as a reviewable diff, exactly like a lockfile diff. No new UX.
5. **Transport-agnostic.** GitHub Action now; GitLab/pre-commit/local next for
   zero added code. The scanner doesn't know which door it came through.

## Monetization ladder (later, not POC)

- $99 one-shot "agent tooling audit" report
- $29/mo CI gate seat (the `commit-state` rug-pull loop)
- free daily CVE feed → email alerts → lead-gen for the above

## Layout

```
schemas/audit-report.json   # THE STANDARD (contract)
api/feed.py                 # rules + known-CVE registry + /v1/registry payload
cli/scanner.py              # pure scanner (the heart)
cli/state.py                # rug-pull memory (git-committable)
cli/main.py                 # CLI entry + exit-code gate
action/action.yml           # GitHub Actions composite action (channel #1)
examples/.github/workflows/ci.yml  # reference usage
tests/test_audit.py         # contract tests (4, no network)
```