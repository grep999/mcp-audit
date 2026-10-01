"""mcp-audit CLI.

Usage:
    python -m cli.main scan <path> [--format json|text|markdown] [--feed <url>] [--no-network]
    python -m cli.main serve            # one-shot feed dump (used by /v1/registry)

Exit codes: 0=pass, 1=fail, 2=review. CI gate = non-zero.
"""
import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pathlib import Path
from api.feed import build_baseline, serve_payload
from cli.scanner import run_audit
from cli.state import check_rug_pull, save_state
from cli.report import to_markdown, to_text


def _maybe_feed(url: str | None, offline: bool) -> tuple[dict, dict | None]:
    """Fetch live ruleset from the service; on failure fall back to local
    baseline. Never blocks the scan - network is enrichment, not a dependency.
    Returns (feed, meta)."""
    feed = build_baseline()
    meta = {"feed_url": url, "feed_ok": False, "rules_version": feed["rules_version"]}
    if url and not offline:
        try:
            import urllib.request
            with urllib.request.urlopen(url, timeout=5) as r:
                live = json.loads(r.read())
            feed.update(live)
            meta["feed_ok"] = True
            meta["rules_version"] = live.get("feed_version", feed["rules_version"])
        except Exception as e:
            meta["note"] = f"feed unreachable ({e.__class__.__name__}); using local baseline"
    return feed, meta


def main() -> int:
    ap = argparse.ArgumentParser(prog="mcp-audit")
    sub = ap.add_subparsers(dest="cmd", required=True)
    scan = sub.add_parser("scan", help="audit an MCP config tree")
    scan.add_argument("path")
    scan.add_argument("--format", default="json", choices=["json", "text", "markdown"],
                      help="output format (default: json)")
    scan.add_argument("--feed", default=None, help="service URL for live rules")
    scan.add_argument("--no-network", action="store_true")
    scan.add_argument("--commit-state", action="store_true",
                      help="write .mcp-audit-state.json for future rug-pull detection")
    serve = sub.add_parser("serve", help="dump the ruleset payload")
    args = ap.parse_args()

    if args.cmd == "serve":
        print(json.dumps(serve_payload(), indent=2, default=str))
        return 0

    root = Path(args.path)
    feed, meta = _maybe_feed(args.feed, args.no_network)
    report = run_audit(root, feed)

    # rug-pull layer
    rug = check_rug_pull(root, report["servers"])
    if rug:
        report["findings"].extend(rug)
        report["summary"]["total_findings"] = len(report["findings"])
        for f in rug:
            report["summary"]["by_severity"][f["severity"]] = \
                report["summary"]["by_severity"].get(f["severity"], 0) + 1

    report["source"].update(meta)

    if args.format == "json":
        print(json.dumps(report, indent=2, default=str))
    elif args.format == "markdown":
        print(to_markdown(report))
    else:
        print(to_text(report))

    if args.commit_state:
        save_state(root, report["servers"])
    return {"pass": 0, "review": 2, "fail": 1}[report["summary"]["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
