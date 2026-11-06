#!/usr/bin/env python3
"""language: Python 3.12, file: email_worker.py, target: worker de OSINT de email na VPS

Servidor HTTP que expõe o scan de email (holehe + user-scanner + emailosint.org).
Padrão do vulture-ollama: container exposto numa porta, o Vaultgrep local faz proxy
pra cá — assim o fan-out de ~350 requests sai do IP da VPS, não do residencial.

GET /email?q=<email>&provider=all[&refresh=1][&rotate=1]
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import email_osint

PORT = int(os.environ.get("EMAIL_WORKER_PORT", "8091"))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silencia o log por request
        pass

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/email":
            self._send(404, {"error": "not found"})
            return
        qs = parse_qs(parsed.query)
        q = (qs.get("q", [""])[0] or "").strip().lower()
        provider = (qs.get("provider", ["all"])[0] or "all").strip().lower()
        refresh = (qs.get("refresh", ["0"])[0] or "0").lower() in ("1", "true", "yes")
        rotate = (qs.get("rotate", ["1"])[0] or "1").lower() not in ("0", "false", "no")
        if not q:
            self._send(400, {"error": "missing q"})
            return
        try:
            data = email_osint.lookup_email(q, provider=provider, refresh=refresh,
                                            rotate=rotate)
            self._send(200, data)
        except email_osint.EmailOSINTError as e:
            self._send(400, {"error": str(e), "code": e.code})
        except Exception as e:
            self._send(502, {"error": str(e)})


if __name__ == "__main__":
    email_osint.init_email_cache()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"email-worker ouvindo em 0.0.0.0:{PORT}", flush=True)
    srv.serve_forever()
