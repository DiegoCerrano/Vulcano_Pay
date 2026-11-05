#!/usr/bin/env python3
"""Demo destination server: prints every webhook it receives.

Run it in its own terminal while the dispatcher is running::

    python tools/destino_demo.py

It listens on http://127.0.0.1:9000 and answers:

* ``POST /webhook``: prints the signature header and the body, replies 200.
* ``GET /health``: replies 200 (``tools/demo.py`` uses it to know it is up).

IMPORTANT: this file is only the *destination server*. The script that
starts the whole demo is ``tools/demo.py``.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = 9000


class Handler(BaseHTTPRequestHandler):
    """Accept webhooks (POST) and answer health checks (GET)."""

    def do_GET(self):  # noqa: N802 (nombre impuesto por http.server)
        """Answer ``GET /health`` with 200 and anything else with 404."""
        status = 200 if self.path == "/health" else 404
        self.send_response(status)
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}' if status == 200 else b"{}")

    def do_POST(self):  # noqa: N802 (nombre impuesto por http.server)
        """Print the received webhook and answer 200 OK."""
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        print(
            "RECIBIDO:",
            self.headers.get("X-Webhook-Signature"),
            body,
            flush=True,
        )
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):  # noqa: A002
        """Hide the access log of the health checks (they are noise)."""
        if self.path != "/health":
            super().log_message(format, *args)


if __name__ == "__main__":
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
