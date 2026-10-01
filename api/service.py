"""HTTP service: the /v1/registry that the CLI/action consume as optional enrichment.

Stdlib http.server only -- YAGNI: no framework, no deps, fits the "thin adapter"
thesis. Serves the ruleset JSON + a metrics endpoint. No state, so trivial to
run under any supervisor. This is the -optional- layer; nothing critical depends
on it (see README architecture).

Usage:
    python3 -m api.service [--port 8080]
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from api.feed import serve_payload


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/v1/registry" or self.path == "/v1/registry/":
            body = json.dumps(serve_payload()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/health":
            body = json.dumps({"ok": True, "ts": int(time.time())}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *a):
        pass  # keep the CLI/action output clean


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    a = ap.parse_args()
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    print(f"mcp-audit registry on http://{a.host}:{a.port}/v1/registry", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()