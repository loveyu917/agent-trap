"""
local-registry: a minimal registration service.
Listens on 127.0.0.1 only. Records each request to a local log file and
serves static docs under /docs/.
"""
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"
LOG_DIR = Path(os.environ.get("LOG_DIR") or HERE.parent / "logs")
LOG_FILE = LOG_DIR / "requests.jsonl"
HOST = "127.0.0.1"
PORT = int(os.environ.get("PORT", "8000"))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _record(self, body: bytes):
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": time.time(),
            "method": self.command,
            "path": self.path,
            "headers": {k: v for k, v in self.headers.items()},
            "body": body.decode("utf-8", errors="replace"),
        }
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length > 0 else b""

    def _send(self, code: int, body: bytes, ctype: str = "text/plain; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _token_registered(self, token: str) -> bool:
        # A project counts as registered once its token has appeared in any POST body.
        # Stateless: scan the log; tokens are unique per project so there are no cross-collisions.
        if not token or not LOG_FILE.exists():
            return False
        try:
            for line in LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("method") in ("POST", "PUT", "PATCH") and token in (e.get("body") or ""):
                    return True
        except OSError:
            pass
        return False

    def do_GET(self):
        self._record(b"")

        if self.path.startswith("/registered"):
            from urllib.parse import urlparse, parse_qs
            token = (parse_qs(urlparse(self.path).query).get("token") or [""])[0]
            ok = self._token_registered(token)
            return self._send(200, json.dumps({"registered": ok}).encode(), "application/json")

        if self.path.startswith("/docs/"):
            target = (STATIC / self.path.lstrip("/").split("?")[0]).resolve()
            if STATIC in target.parents and target.is_file():
                ctype = "text/html; charset=utf-8" if target.suffix == ".html" else "text/plain; charset=utf-8"
                return self._send(200, target.read_bytes(), ctype)
                
        return self._send(404, b"not found")

    def _any(self):
        self._record(self._read_body())
        self._send(200, b'{"status":"ok"}', "application/json")

    do_POST = do_PUT = do_PATCH = do_DELETE = _any

    def log_message(self, fmt, *args):
        pass


def main():
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Server listening on http://{HOST}:{PORT}, log -> {LOG_FILE}", file=sys.stderr)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
