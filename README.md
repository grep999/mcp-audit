# mcp-audit

Audit the MCP servers in a repo before an AI agent trusts them.

MCP (Model Context Protocol) connects AI agents to real tools — filesystem,
DBs, shell. In 2026 adoption outran security: ~97M SDK downloads/month, a
CISA-exploited CVE in an official Google MCP server, and an NSA threat taxonomy
published May 2026. Most teams have MCP configured and no gate. This is the
gate.

## What it checks (NSA May-2026 taxonomy)

| Category | What it detects | Severity |
|---|---|---|
| **STALE_VERSION** | Known-vulnerable server (registry of CVEs) | critical |
| **UNVERIFIED_SERVER** | community/unverified/unofficial registry names | high |
| **HARDCODED_SECRET** | API keys, PATs, JWTs, URL creds, env secrets | high |
| **TOOL_POISONING** | Unpinned filesystem/shell server; rug-pull (changed def) | medium |
| **TOOL_PATH_CONFUSION** | Same server name in multiple configs (shadowing) | medium |
| **NETWORK_EGRESS** | Remote/SSE/http transport (data leaves host) | info |

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
make check                    # run all contract tests

python3 -m cli.main scan .                     # json (default)
python3 -m cli.main scan . --format text       # terminal
python3 -m cli.main scan . --format markdown   # the $99 deliverable
python3 -m cli.main scan . --commit-state      # write rug-pull lockfile
python3 -m cli.main scan . --feed <url>        # use live registry (optional)

# exit codes: 0=pass 1=fail 2=review → gate directly in CI
```

Run the registry service (channel for live rules):

```bash
make service        # python3 -m api.service --port 8080
curl localhost:8080/v1/registry
```

## Layout

```
schemas/audit-report.json   # THE STANDARD (versioned contract)
api/feed.py                 # rules + known-CVE registry (the moat)
api/service.py              # optional HTTP /v1/registry (channel)
cli/scanner.py              # pure core (the heart)
cli/state.py                # rug-pull memory (git-committable lockfile)
cli/main.py                 # CLI + exit-code gate
cli/report.py               # text / markdown / GH annotations renders
action/action.yml           # GitHub Actions composite action (channel)
pyproject.toml              # packaging: `mcp-audit` console script
Makefile                    # check / test / install / service
tests/                      # 14 contract tests, no network
```

## Current state vs "the wild"

**Done (verified by 14 passing tests + live e2e):**
- Config discovery (Claude, Cursor, Desktop), transport detection, dedupe
- 6 checks + shadowing, secret patterns, credential URLs, pin detection
- Rug-pull lockfile (`.mcp-audit-state.json`)
- Report renderers (text / markdown / GH annotations)
- HTTP registry service with feed fallback (verified live)
- Security guards: symlink-escape, oversized-file, type-checked input
- Packaging via `pyproject.toml`

**Skipped (add when a paying user needs it):**
- Source-tree AST scanning (deeper NSA coverage) — needs a real parser, not the POC's string checks
- Real version-pin resolution (parse the actual version, not heuristics)
- CVE feed growth (registry has 2 entries; the moat is more entries)
- Auth on the registry (currently open; fine for internal/self-host)

## Licensing & note
MIT. The NSA/OWASP classifications are high-level naming, not formal assessment
certs — never claim compliance without an actual auditor's sign-off.