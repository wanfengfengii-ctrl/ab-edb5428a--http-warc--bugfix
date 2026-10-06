"""Test support: a byte-exact WARC 1.1 record factory.

Used by the unit tests and by the API smoke script.  The factory builds
strictly valid records by default; individual knobs corrupt exactly one
invariant at a time.
"""

from __future__ import annotations

import hashlib
import itertools

_id_counter = itertools.count(1)


def new_record_id() -> str:
    n = next(_id_counter)
    return f"<urn:uuid:00000000-0000-0000-0000-{n:012d}>"


def http_response(
    body: bytes,
    *,
    status: int = 200,
    reason: str = "OK",
    extra_headers: tuple[tuple[str, str], ...] = (),
    version: str = "HTTP/1.1",
    content_length: int | None = None,
    eol: bytes = b"\r\n",
) -> bytes:
    lines = [f"{version} {status} {reason}".encode("ascii")]
    lines.append(f"Content-Type: application/octet-stream".encode())
    lines.append(f"Content-Length: {len(body) if content_length is None else content_length}".encode())
    for name, value in extra_headers:
        lines.append(f"{name}: {value}".encode())
    return eol.join(lines) + eol + eol + body


def http_response_headers_only(
    body_length: int,
    *,
    status: int = 200,
    reason: str = "OK",
    extra_headers: tuple[tuple[str, str], ...] = (),
    version: str = "HTTP/1.1",
    eol: bytes = b"\r\n",
) -> bytes:
    """Canonical revisit block: HTTP response headers WITHOUT an entity body.

    ``body_length`` is the length the origin server declared for the payload
    that this record refers back to; the body bytes themselves are absent.
    """
    lines = [f"{version} {status} {reason}".encode("ascii")]
    lines.append(b"Content-Type: application/octet-stream")
    lines.append(f"Content-Length: {body_length}".encode())
    for name, value in extra_headers:
        lines.append(f"{name}: {value}".encode())
    return eol.join(lines) + eol + eol


def warc_record(
    warc_type: str,
    block: bytes,
    *,
    record_id: str | None = None,
    target_uri: str | None = None,
    block_digest: str | None = None,
    payload_digest: str | None = None,
    refers_to: str | None = None,
    extra_headers: tuple[tuple[str, str], ...] = (),
    duplicate_header: tuple[str, str] | None = None,
    declared_length: int | None = None,
    eol: bytes = b"\r\n",
    date: str = "2026-10-06T00:00:00Z",
) -> bytes:
    record_id = record_id or new_record_id()
    if block_digest is None:
        block_digest = "sha256:" + hashlib.sha256(block).hexdigest()
    headers: list[tuple[str, str]] = [
        ("WARC-Type", warc_type),
        ("WARC-Record-ID", record_id),
        ("WARC-Date", date),
    ]
    if target_uri is not None:
        headers.append(("WARC-Target-URI", target_uri))
    if payload_digest is not None:
        headers.append(("WARC-Payload-Digest", payload_digest))
    if refers_to is not None:
        headers.append(("WARC-Refers-To", refers_to))
    for name, value in extra_headers:
        headers.append((name, value))
    headers.append(("WARC-Block-Digest", block_digest))
    if duplicate_header is not None:
        headers.append(duplicate_header)
    headers.append(("Content-Length", str(len(block) if declared_length is None else declared_length)))

    out = bytearray(b"WARC/1.1" + eol)
    for name, value in headers:
        out += f"{name}: {value}".encode("ascii") + eol
    out += eol
    out += block
    # ISO 28500 record terminator: CRLF ending the block plus a final
    # blank-line CRLF.
    out += eol + eol
    return bytes(out)


def payload_digest_of(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def build_valid_archive() -> tuple[bytes, str]:
    """warcinfo + request + response + matching revisit. Returns (bytes, response_id)."""
    body = b"<!doctype html><title>hello</title>"
    response_id = new_record_id()
    pd = payload_digest_of(body)
    parts = [
        warc_record("warcinfo", b"software: test\r\nformat: WARC File Format 1.1\r\n"),
        warc_record(
            "request",
            b"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n",
            target_uri="http://example.invalid/",
        ),
        warc_record(
            "response",
            http_response(body),
            record_id=response_id,
            target_uri="http://example.invalid/",
            payload_digest=pd,
        ),
        warc_record(
            "revisit",
            http_response_headers_only(len(body)),
            target_uri="http://example.invalid/",
            payload_digest=pd,
            refers_to=response_id,
        ),
    ]
    return b"".join(parts), response_id
