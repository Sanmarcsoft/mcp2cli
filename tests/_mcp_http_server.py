"""Minimal MCP server for testing — Streamable HTTP over stdlib http.server.

Speaks the JSON-RPC wire protocol directly (see `_mcp_fixture`), so it works
against any `mcp` SDK major and needs no starlette/uvicorn.

This is deliberately **POST-only**: `GET` on the endpoint returns 405, which is
what a server that does not offer a server-to-client stream is supposed to do,
and matches the real-world gateways reported in #68/#74. Exercising that shape
here keeps us honest about whether the client actually needs the GET handshake.

Prints `PORT=<n>` on stdout once bound, so the test fixture can find it.
"""

import json
import socket
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from _mcp_fixture import handle

ENDPOINT = "/mcp"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    session_id = None

    def _send(self, status: int, body: bytes = b"", content_type: str | None = None, extra=()):
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in extra:
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_POST(self):
        if self.path.split("?")[0] != ENDPOINT:
            self._send(404)
            return

        length = int(self.headers.get("Content-Length") or 0)
        try:
            message = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send(400)
            return

        # A batch is a JSON array; a single message is an object.
        batch = message if isinstance(message, list) else [message]
        responses = [r for r in (handle(m) for m in batch) if r is not None]

        extra = []
        if any(m.get("method") == "initialize" for m in batch):
            Handler.session_id = uuid.uuid4().hex
        if Handler.session_id:
            extra.append(("Mcp-Session-Id", Handler.session_id))

        if not responses:
            # Notifications only -- nothing to answer.
            self._send(202, extra=extra)
            return

        payload = responses[0] if not isinstance(message, list) else responses
        self._send(
            200,
            json.dumps(payload).encode(),
            "application/json",
            extra,
        )

    def do_GET(self):
        # POST-only server: no server-to-client stream on offer.
        self._send(405, b"", None, [("Allow", "POST, DELETE")])

    def do_DELETE(self):
        Handler.session_id = None
        self._send(200)

    def log_message(self, fmt, *args):
        pass  # keep test output clean


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> None:
    port = find_free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"PORT={port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
