"""HTTP front-end for the WARC ingestion audit.

Exposes ``POST /api/warc/audit`` (media type ``application/warc``) and a
``GET /healthz`` probe used by the container healthcheck.  The server only
depends on the Python standard library so the runtime image needs no
package installation.
"""

from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .parser import WARCAuditError, audit_warc

MAX_BODY = 16 * 1024 * 1024  # 16 MiB, inclusive
WARC_CONTENT_TYPE = "application/warc"

# Request-level rejections (framing of the HTTP request itself, not of the
# archive) share a stable error-code space below the parser's 4001/4002.
REQUEST_ERRORS = {
    "method_not_allowed": (4005, HTTPStatus.METHOD_NOT_ALLOWED),
    "unsupported_media_type": (4006, HTTPStatus.UNSUPPORTED_MEDIA_TYPE),
    "body_too_large": (4007, HTTPStatus.REQUEST_ENTITY_TOO_LARGE),
    "empty_body": (4008, HTTPStatus.BAD_REQUEST),
    "invalid_request": (4009, HTTPStatus.BAD_REQUEST),
}


def _error_body(code: int, reason: str, message: str, record: int | None = None) -> dict:
    body = {"ok": False, "error": {"code": code, "reason": reason, "message": message}}
    if record is not None:
        body["error"]["record"] = record
    return body


class AuditHandler(BaseHTTPRequestHandler):
    server_version = "WarcAudit/1.0"
    protocol_version = "HTTP/1.1"  # Content-Length is always sent, so keep-alive is safe

    # Quieter, deterministic access log line on stderr.
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        import sys

        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send_json(self, status: HTTPStatus, payload: dict) -> None:
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _reject_request(self, reason: str, message: str) -> None:
        # The request body may be unread on this path (e.g. 413/415); closing
        # the connection avoids desynchronising a keep-alive socket.
        self.close_connection = True
        code, status = REQUEST_ERRORS[reason]
        self._send_json(status, _error_body(code, reason, message))

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") == "/healthz" or self.path == "/":
            self._send_json(HTTPStatus.OK, {"ok": True, "status": "ready"})
        else:
            self._reject_request("method_not_allowed", "use POST /api/warc/audit")

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") != "/api/warc/audit":
            self._reject_request("method_not_allowed", "unknown endpoint")
            return

        ctype = self.headers.get("Content-Type", "")
        media = ctype.split(";", 1)[0].strip().lower()
        if media != WARC_CONTENT_TYPE:
            self._reject_request(
                "unsupported_media_type",
                f"Content-Type must be {WARC_CONTENT_TYPE}",
            )
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._reject_request("invalid_request", "invalid Content-Length")
            return
        if length <= 0:
            self._reject_request("empty_body", "request body is empty")
            return
        if length > MAX_BODY:
            self._reject_request(
                "body_too_large",
                f"WARC archive exceeds the {MAX_BODY}-byte limit",
            )
            return

        # Read exactly Content-Length bytes; chunked uploads are not accepted
        # because an ingestion package must declare its exact size.
        body = self.rfile.read(length)
        if len(body) != length:
            self._reject_request("invalid_request", "request body shorter than Content-Length")
            return

        try:
            result = audit_warc(body)
        except WARCAuditError as exc:
            status = HTTPStatus.BAD_REQUEST
            self._send_json(
                status,
                _error_body(exc.code, exc.reason, exc.message, exc.record),
            )
            return

        self._send_json(
            HTTPStatus.OK,
            {"ok": True, **result.to_dict()},
        )


def build_server(host: str = "0.0.0.0", port: int | None = None) -> ThreadingHTTPServer:
    port = port or int(os.environ.get("PORT", "8080"))
    return ThreadingHTTPServer((host, port), AuditHandler)


def main() -> None:
    server = build_server()
    port = server.server_address[1]
    import sys

    sys.stderr.write(f"warc-audit listening on 0.0.0.0:{port}\n")
    sys.stderr.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
