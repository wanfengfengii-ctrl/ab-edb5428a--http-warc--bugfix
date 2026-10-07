"""Byte-strict WARC 1.1 parser.

The parser deliberately avoids the tolerant ``http.client`` header parser:
forensic ingestion must reject malformed framing rather than guess around it.
Every byte of the declared record block is covered by the WARC-Block-Digest,
and response/revisit records additionally carry a payload digest computed
over the HTTP entity body bytes described by the record's HTTP headers —
with any HTTP/1.1 chunked transfer coding removed first.  The block digest
always covers the raw, still transfer-coded bytes; the two never mix.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

WARC_VERSION = "WARC/1.1"
MAX_RECORDS = 500

# Records are logically split into a "boundary" stage (framing + headers +
# block length) and a "content" stage (block digest, HTTP payload, revisit
# references).  A failure in stage one is reported with code 4001, a failure
# in stage two with 4002, so callers can distinguish framing corruption from
# content/reference corruption.
ERR_BOUNDARY = 4001
ERR_CONTENT = 4002


class WARCAuditError(Exception):
    """First validation failure.

    Attributes:
        code: stable machine-readable error code.
        record: 1-based index of the record at which the failure was
            detected, or ``None`` when the failure is not attributable to a
            specific record (empty file, trailing garbage, ...).
        reason: short stable reason token.
        message: human-readable explanation.
    """

    def __init__(self, code: int, record: int | None, reason: str, message: str):
        super().__init__(message)
        self.code = code
        self.record = record
        self.reason = reason
        self.message = message


@dataclass(frozen=True)
class RecordInfo:
    index: int
    warc_type: str
    block_length: int
    block_digest: str  # 64 lowercase hex chars, without algorithm prefix
    payload_digest: str | None = None


@dataclass(frozen=True)
class AuditResult:
    records: tuple[RecordInfo, ...]

    def to_dict(self) -> dict:
        return {
            "count": len(self.records),
            "records": [
                {
                    "index": r.index,
                    "type": r.warc_type,
                    "blockLength": r.block_length,
                    "blockDigest": r.block_digest,
                    **(
                        {"payloadDigest": r.payload_digest}
                        if r.payload_digest is not None
                        else {}
                    ),
                }
                for r in self.records
            ],
        }


def _fail(code: int, record: int | None, reason: str, message: str):
    raise WARCAuditError(code, record, reason, message)


def audit_warc(data: bytes) -> AuditResult:
    """Validate a complete WARC 1.1 archive and return its record summary.

    Raises :class:`WARCAuditError` on the first error.  The empty input is
    rejected before any record is numbered.
    """
    if not isinstance(data, (bytes, bytearray)):
        _fail(4000, None, "invalid_request", "request body must be raw bytes")
    data = bytes(data)
    if len(data) == 0:
        _fail(4000, None, "empty_body", "request body is empty")

    pos = 0
    n = len(data)
    records: list[tuple[RecordInfo, bytes, dict[str, bytes]]] = []
    seen_record_ids: set[bytes] = set()

    # ------------------------------------------------------------------
    # Stage 1: record boundaries, version, headers and block length.
    # ------------------------------------------------------------------
    while pos < n:
        record_no = len(records) + 1
        if record_no > MAX_RECORDS:
            _fail(
                ERR_BOUNDARY,
                record_no,
                "too_many_records",
                f"archive exceeds the {MAX_RECORDS}-record limit",
            )

        # Version line must be exactly "WARC/1.1" terminated by CRLF.
        crlf = data.find(b"\r\n", pos)
        if crlf == -1:
            _fail(
                ERR_BOUNDARY,
                record_no,
                "malformed_record",
                "record version line is not CRLF terminated",
            )
        version_line = data[pos:crlf]
        if b"\n" in version_line or b"\r" in version_line:
            _fail(ERR_BOUNDARY, record_no, "malformed_record", "bare CR or LF in version line")
        if version_line != WARC_VERSION.encode("ascii"):
            _fail(
                ERR_BOUNDARY,
                record_no,
                "unsupported_version",
                f"expected {WARC_VERSION}",
            )
        pos = crlf + 2

        # Header block: strict CRLF folding rules, duplicate detection.
        headers: dict[str, bytes] = {}
        while True:
            line_end = data.find(b"\r\n", pos)
            if line_end == -1:
                _fail(ERR_BOUNDARY, record_no, "unterminated_header", "header line lacks CRLF")
            line = data[pos:line_end]
            pos = line_end + 2
            if line == b"":
                break  # end of headers
            if line[:1] in (b" ", b"\x09"):
                _fail(
                    ERR_BOUNDARY,
                    record_no,
                    "folded_header",
                    "obsolete header folding is not accepted",
                )
            if b"\n" in line or b"\r" in line:
                _fail(
                    ERR_BOUNDARY,
                    record_no,
                    "malformed_header",
                    "bare CR or LF inside header field",
                )
            colon = line.find(b":")
            if colon <= 0:
                _fail(ERR_BOUNDARY, record_no, "malformed_header", "header field missing ':'")
            raw_name = line[:colon]
            raw_value = line[colon + 1 :]
            if b" " in raw_name or b"\t" in raw_name:
                _fail(ERR_BOUNDARY, record_no, "malformed_header", "whitespace in header name")
            try:
                name = raw_name.decode("ascii").lower()
            except UnicodeDecodeError:
                _fail(ERR_BOUNDARY, record_no, "malformed_header", "non-ASCII header name")
            # Value: RFC 7230 OWS — a single SP/HTAB may flank the value.
            value = raw_value
            if value[:1] in (b" ", b"\x09"):
                value = value[1:]
            if value[-1:] in (b" ", b"\x09"):
                value = value[:-1]
            if name in headers:
                _fail(
                    ERR_BOUNDARY,
                    record_no,
                    "duplicate_required_or_header",
                    f"header field {raw_name.decode('ascii', 'replace')!r} appears more than once",
                )
            headers[name] = value

        def required(name: str) -> bytes:
            if name not in headers:
                _fail(
                    ERR_BOUNDARY,
                    record_no,
                    "missing_required_header",
                    f"required header {name} is absent",
                )
            return headers[name]

        type_raw = required("warc-type")
        if not _is_ascii(type_raw):
            _fail(ERR_BOUNDARY, record_no, "malformed_header", "non-ASCII WARC-Type")
        warc_type = type_raw.decode("ascii")
        if warc_type not in ("warcinfo", "request", "response", "revisit"):
            _fail(
                ERR_BOUNDARY,
                record_no,
                "unsupported_record_type",
                f"WARC-Type {warc_type!r} is not accepted",
            )

        # WARC 1.1 mandatory headers, each exactly once (duplicates of any
        # field were already rejected above).
        record_id = required("warc-record-id")
        if not _is_ascii(record_id) or not record_id.strip():
            _fail(ERR_BOUNDARY, record_no, "malformed_header", "invalid WARC-Record-ID")
        warc_date = required("warc-date")
        if not _is_ascii(warc_date) or not warc_date.strip():
            _fail(ERR_BOUNDARY, record_no, "malformed_header", "invalid WARC-Date")
        if record_id in seen_record_ids:
            _fail(
                ERR_BOUNDARY,
                record_no,
                "duplicate_record_id",
                "WARC-Record-ID is not unique within the archive",
            )
        seen_record_ids.add(record_id)

        target_uri = headers.get("warc-target-uri")
        if target_uri is not None and not target_uri:
            _fail(ERR_BOUNDARY, record_no, "malformed_header", "empty WARC-Target-URI")

        cl_raw = required("content-length")
        if not _is_nonneg_integer(cl_raw):
            _fail(ERR_BOUNDARY, record_no, "invalid_content_length", "Content-Length must be a non-negative decimal integer")
        try:
            content_length = int(cl_raw)
        except ValueError:  # absurdly long digit string
            _fail(
                ERR_BOUNDARY,
                record_no,
                "invalid_content_length",
                "Content-Length has an unreasonable number of digits",
            )

        block_start = pos
        block_end = block_start + content_length
        if block_end > n:
            _fail(
                ERR_BOUNDARY,
                record_no,
                "block_truncated",
                "Content-Length extends past end of archive",
            )
        block = data[block_start:block_end]
        pos = block_end

        # WARC 1.1 (ISO 28500) terminates every record block with exactly
        # two CRLFs: one ends the block and a second forms the mandatory
        # blank line before the next record.  Requiring both — rather than
        # tolerating a single CRLF — keeps framing verification byte-exact;
        # a third CRLF or any stray byte is a boundary error.
        if data[pos : pos + 4] != b"\r\n\r\n":
            if data[pos : pos + 2] == b"\r\n" and data[pos + 2 : pos + 4] != b"\r\n":
                _fail(
                    ERR_BOUNDARY,
                    record_no,
                    "missing_record_terminator",
                    "record block must be terminated by CRLF CRLF",
                )
            _fail(
                ERR_BOUNDARY,
                record_no,
                "missing_record_separator",
                "record block must be followed by CRLF CRLF",
            )
        pos += 4
        if data[pos : pos + 2] == b"\r\n":
            _fail(
                ERR_BOUNDARY,
                record_no,
                "extra_blank_line",
                "unexpected extra CRLF between records",
            )

        records.append(
            (
                RecordInfo(
                    index=record_no,
                    warc_type=warc_type,
                    block_length=content_length,
                    block_digest="",  # filled in during the content stage
                ),
                block,
                headers,
            )
        )

    if not records:
        _fail(4000, None, "empty_archive", "archive contains no records")

    # ------------------------------------------------------------------
    # Stage 2: block digests, HTTP payload digests, revisit references.
    # ------------------------------------------------------------------
    results: list[RecordInfo] = []
    # WARC-Record-ID -> (1-based index, payload digest) of earlier responses
    response_by_id: dict[str, tuple[int, str]] = {}

    for partial, block, headers in records:
        idx = partial.index

        digest_value = _header_ascii(headers, "warc-block-digest", idx, required=True)
        declared = _parse_sha256_digest(digest_value, idx, what="WARC-Block-Digest")
        actual = hashlib.sha256(block).hexdigest()
        if actual != declared:
            _fail(
                ERR_CONTENT,
                idx,
                "block_digest_mismatch",
                "WARC-Block-Digest does not match the declared block bytes",
            )

        payload_digest: str | None = None
        if partial.warc_type in ("response", "revisit"):
            # The block is a full HTTP response message: status line, headers,
            # then the entity body — Content-Length delimited or HTTP/1.1
            # chunked.  The payload digest always covers the entity with any
            # transfer coding removed; the block digest above covered the
            # untouched raw bytes.
            payload_bytes, http_status, chunked = _http_entity_body(block)
            if http_status == _HTTP_INVALID:
                _fail(
                    ERR_CONTENT,
                    idx,
                    "invalid_http_message",
                    "record block is not a well-formed CRLF-delimited HTTP message",
                )
            pd_raw = _header_ascii(headers, "warc-payload-digest", idx, required=True)
            payload_digest = _parse_sha256_digest(pd_raw, idx, what="WARC-Payload-Digest")

            if partial.warc_type == "response":
                # A response must carry the complete entity body, which is
                # hashed after removing any transfer coding.  Truncation is
                # never tolerated.
                if http_status != _HTTP_COMPLETE:
                    _fail(
                        ERR_CONTENT,
                        idx,
                        "payload_truncated",
                        "chunked HTTP entity body is incomplete"
                        if chunked
                        else "HTTP entity body is shorter than its Content-Length",
                    )
                if hashlib.sha256(payload_bytes).hexdigest() != payload_digest:
                    _fail(
                        ERR_CONTENT,
                        idx,
                        "payload_digest_mismatch",
                        "WARC-Payload-Digest does not match the HTTP entity body",
                    )
            else:
                # A canonical revisit stores response headers only (no entity
                # body); its declared payload digest is then validated by the
                # reference equality check against the earlier response.  If a
                # body *is* present it must be complete and hash correctly; a
                # partially present body is ambiguous and rejected.
                if http_status == _HTTP_TRUNCATED:
                    _fail(
                        ERR_CONTENT,
                        idx,
                        "payload_truncated",
                        "revisit carries a partial HTTP entity body",
                    )
                if http_status == _HTTP_COMPLETE and hashlib.sha256(payload_bytes).hexdigest() != payload_digest:
                    _fail(
                        ERR_CONTENT,
                        idx,
                        "payload_digest_mismatch",
                        "WARC-Payload-Digest does not match the HTTP entity body",
                    )

        if partial.warc_type == "revisit":
            refers_raw = _header_ascii(headers, "warc-refers-to", idx, required=True)
            refers_to = refers_raw.strip()
            if not _is_token(refers_to):
                _fail(
                    ERR_CONTENT,
                    idx,
                    "invalid_warc_refers_to",
                    "WARC-Refers-To must be the WARC-Record-ID of an earlier response",
                )
            target = response_by_id.get(refers_to)
            if target is None:
                _fail(
                    ERR_CONTENT,
                    idx,
                    "dangling_revisit_reference",
                    "WARC-Refers-To does not resolve to an earlier response record",
                )
            _target_idx, target_payload = target
            if target_payload != payload_digest:
                _fail(
                    ERR_CONTENT,
                    idx,
                    "revisit_payload_mismatch",
                    "revisit payload digest differs from the referenced response",
                )

        info = RecordInfo(
            index=idx,
            warc_type=partial.warc_type,
            block_length=partial.block_length,
            block_digest=actual,
            payload_digest=payload_digest,
        )
        results.append(info)
        if partial.warc_type == "response":
            rid = headers["warc-record-id"].decode("ascii").strip()
            response_by_id.setdefault(rid, (idx, payload_digest))  # type: ignore[arg-type]

    return AuditResult(tuple(results))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_ascii(value: bytes) -> bool:
    try:
        value.decode("ascii")
    except UnicodeDecodeError:
        return False
    return True


def _is_nonneg_integer(value: bytes) -> bool:
    return bool(value) and all(c in b"0123456789" for c in value)


def _is_token(value: str) -> bool:
    # WARC record ids use uri/rfc3986 characters ("<urn:uuid:...>").  Accept
    # the angle-bracket URI-Ref form as well as a bare token.
    if not value:
        return False
    if len(value) >= 2 and value[0] == "<" and value[-1] == ">":
        inner = value[1:-1]
        return bool(inner) and all(32 < ord(c) < 127 and c not in "<>" for c in inner)
    return all(32 < ord(c) < 127 for c in value)


def _header_ascii(headers: dict[str, bytes], name: str, idx: int, *, required: bool) -> str:
    value = headers.get(name)
    if value is None:
        if required:
            _fail(ERR_BOUNDARY, idx, "missing_required_header", f"required header {name} is absent")
        return ""
    if not _is_ascii(value):
        _fail(ERR_CONTENT, idx, "malformed_digest", f"{name} is not ASCII")
    return value.decode("ascii")


def _parse_sha256_digest(value: str, idx: int, *, what: str) -> str:
    # RFC 3230 named syntax: sha256:<64 lowercase hex>.  A bare hex digest
    # is also accepted; any other algorithm label or shape is rejected.
    v = value.strip()
    if ":" in v:
        algo, _, hexpart = v.partition(":")
        if algo.lower() != "sha256":
            _fail(ERR_CONTENT, idx, "unsupported_digest_algorithm", f"{what} must use sha256")
    else:
        hexpart = v
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        _fail(
            ERR_CONTENT,
            idx,
            "malformed_digest",
            f"{what} must be sha256 plus 64 lowercase hexadecimal characters",
        )
    return hexpart


# ---------------------------------------------------------------------------
# HTTP entity extraction
# ---------------------------------------------------------------------------

# Outcomes of _http_entity_body.  "complete" and "truncated" mirror the
# Content-Length semantics; "absent" is the canonical headers-only revisit
# shape; "invalid" covers any framing or syntax violation.
_HTTP_COMPLETE = "complete"
_HTTP_ABSENT = "absent"
_HTTP_TRUNCATED = "truncated"
_HTTP_INVALID = "invalid"

_HEXDIGITS = frozenset(b"0123456789abcdefABCDEF")
_TCHARS = frozenset(
    b"!#$%&'*+-.^_`|~"
    b"0123456789"
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

# Trailer fields that would alter message framing or routing must never
# appear (RFC 7230 §4.1.2 forbids generating them); accepting one would
# make the verified entity boundary ambiguous.
_FORBIDDEN_TRAILER_NAMES = frozenset(
    {"content-length", "transfer-encoding", "trailer", "host"}
)


def _http_entity_body(block: bytes) -> tuple[bytes, str, bool]:
    """Split a block that must be a full HTTP response message.

    Returns ``(entity_body, status, chunked)``:

    * ``entity_body`` is the payload with any transfer coding removed — for
      a chunked message these are the concatenated chunk-data bytes, never
      the raw on-the-wire body;
    * ``status`` is one of ``"complete"`` / ``"absent"`` / ``"truncated"`` /
      ``"invalid"``.  A canonical revisit block carries headers only, so its
      body may legitimately be absent; a partially present body is reported
      as truncated and rejected by the caller;
    * ``chunked`` records which framing was in force, for diagnostics.

    Framing is strict: a single ``Content-Length`` or — for HTTP/1.1 only —
    a bare ``chunked`` transfer coding.  Both together, repeated or
    additional codings and any other transfer coding are refused rather than
    guessed at, because guessing framing would defeat byte verification.
    """
    sep = b"\r\n\r\n"
    head_end = block.find(sep)
    if head_end == -1:
        return b"", _HTTP_INVALID, False
    head = block[:head_end]
    body = block[head_end + 4 :]
    lines = head.split(b"\r\n")
    status_line = lines[0]
    http11 = status_line.startswith(b"HTTP/1.1 ")
    if not http11 and not status_line.startswith(b"HTTP/1.0 "):
        return b"", _HTTP_INVALID, False
    try:
        status_line.decode("ascii")
    except UnicodeDecodeError:
        return b"", _HTTP_INVALID, False

    headers: dict[str, bytes] = {}
    for line in lines[1:]:
        colon = line.find(b":")
        if colon <= 0:
            return b"", _HTTP_INVALID, False
        try:
            name = line[:colon].decode("ascii").lower()
        except UnicodeDecodeError:
            return b"", _HTTP_INVALID, False
        value = line[colon + 1 :].strip()
        if name in headers:  # duplicated HTTP header — refuse rather than merge
            return b"", _HTTP_INVALID, False
        headers[name] = value

    te = headers.get("transfer-encoding", b"").lower()
    if te:
        # Only a bare "chunked" coding can be removed deterministically.
        if te != b"chunked":
            return b"", _HTTP_INVALID, False
        if not http11 or "content-length" in headers:
            return b"", _HTTP_INVALID, True
        if len(body) == 0:
            return b"", _HTTP_ABSENT, True
        decoded, status = _decode_chunked(body)
        return decoded, status, True

    cl = headers.get("content-length")
    if cl is None or not _is_nonneg_integer(cl):
        return b"", _HTTP_INVALID, False
    try:
        length = int(cl)
    except ValueError:  # absurdly long digit string
        return b"", _HTTP_INVALID, False
    if len(body) > length:  # bytes beyond the declared entity body
        return b"", _HTTP_INVALID, False
    if len(body) == 0 and length > 0:
        return b"", _HTTP_ABSENT, False
    if len(body) < length:
        return body, _HTTP_TRUNCATED, False
    return body, _HTTP_COMPLETE, False


def _decode_chunked(body: bytes) -> tuple[bytes, str]:
    """Decode an HTTP/1.1 ``chunked`` body, strictly per RFC 7230 §4.1.

    Returns ``(decoded, status)`` with status ``"complete"`` (last-chunk,
    trailer part and final CRLF all present, nothing after), ``"truncated"``
    (the input ended at a point where more bytes were required) or
    ``"invalid"`` (a present byte violates the grammar).  The decoded bytes
    are the concatenated chunk-data; chunk extensions are validated and
    ignored, and trailer fields are validated but do not contribute to the
    payload.
    """
    decoded = bytearray()
    pos = 0
    n = len(body)
    while True:
        line_end = body.find(b"\r\n", pos)
        if line_end == -1:
            # The size line is cut off: a clean hex prefix is truncation,
            # anything else was never a size line at all.
            if all(c in _HEXDIGITS for c in body[pos:]):
                return bytes(decoded), _HTTP_TRUNCATED
            return b"", _HTTP_INVALID
        size = _parse_chunk_size_line(body[pos:line_end])
        if size is None:
            return b"", _HTTP_INVALID
        pos = line_end + 2
        if size > 0:
            if pos + size > n:
                return bytes(decoded), _HTTP_TRUNCATED
            decoded += body[pos : pos + size]
            pos += size
            if pos + 2 > n:
                return bytes(decoded), _HTTP_TRUNCATED
            if body[pos : pos + 2] != b"\r\n":
                return b"", _HTTP_INVALID
            pos += 2
            continue
        # last-chunk: trailer part, then the CRLF ending the message.
        while True:
            line_end = body.find(b"\r\n", pos)
            if line_end == -1:
                remaining = body[pos:]
                if b"\r" not in remaining and b"\n" not in remaining:
                    return bytes(decoded), _HTTP_TRUNCATED
                return b"", _HTTP_INVALID
            line = body[pos:line_end]
            pos = line_end + 2
            if line == b"":
                if pos != n:
                    return b"", _HTTP_INVALID  # bytes after the message end
                return bytes(decoded), _HTTP_COMPLETE
            if not _valid_trailer_field(line):
                return b"", _HTTP_INVALID


def _parse_chunk_size_line(line: bytes) -> int | None:
    """Parse ``chunk-size [ chunk-ext ]``; ``None`` when not well-formed."""
    semi = line.find(b";")
    size_part = line if semi == -1 else line[:semi]
    if not size_part or any(c not in _HEXDIGITS for c in size_part):
        return None
    if semi != -1 and not _valid_chunk_ext(line[semi:]):
        return None
    try:
        return int(size_part, 16)
    except ValueError:
        return None


def _valid_chunk_ext(ext: bytes) -> bool:
    """Validate a chunk extension string (from the first ``;`` onward).

    Grammar (RFC 7230 §4.1.1): ``*( ";" chunk-ext-name [ "=" chunk-ext-val ] )``
    with ``chunk-ext-val = token / quoted-string``.  Well-formed extensions
    are accepted and ignored, as recipients must; malformed ones are not.
    """
    i = 0
    n = len(ext)
    while i < n:
        if ext[i] != 0x3B:  # ";"
            return False
        i += 1
        start = i
        while i < n and ext[i] in _TCHARS:
            i += 1
        if i == start:
            return False  # empty extension name
        if i < n and ext[i] == 0x3D:  # "="
            i += 1
            if i < n and ext[i] == 0x22:  # quoted-string value
                i += 1
                closed = False
                while i < n:
                    c = ext[i]
                    if c == 0x5C:  # quoted-pair: "\" ( HTAB / SP / VCHAR / obs-text )
                        if i + 1 >= n:
                            return False
                        nxt = ext[i + 1]
                        if not (nxt in (0x09, 0x20) or 0x21 <= nxt <= 0x7E or nxt >= 0x80):
                            return False
                        i += 2
                    elif c == 0x22:  # closing DQUOTE
                        i += 1
                        closed = True
                        break
                    elif c in (0x09, 0x20) or c == 0x21 or 0x23 <= c <= 0x5B or 0x5D <= c <= 0x7E or c >= 0x80:
                        i += 1  # qdtext
                    else:
                        return False
                if not closed:
                    return False
            else:
                start = i
                while i < n and ext[i] in _TCHARS:
                    i += 1
                if i == start:
                    return False  # empty token value
    return True


def _valid_trailer_field(line: bytes) -> bool:
    """Validate one trailer field line (without its CRLF).

    Same shape rules as a strict header field — no folding, a token field
    name, no control characters in the value — plus the RFC 7230 §4.1.2
    prohibition of trailer fields that would alter message framing.
    """
    if line[:1] in (b" ", b"\x09"):
        return False  # folded trailer line
    colon = line.find(b":")
    if colon <= 0:
        return False
    name = line[:colon]
    if any(c not in _TCHARS for c in name):
        return False
    if name.decode("ascii").lower() in _FORBIDDEN_TRAILER_NAMES:
        return False
    value = line[colon + 1 :].strip(b" \x09")
    # field-content allows VCHAR / obs-text joined by SP/HTAB — no controls.
    return all(c in (0x09, 0x20) or 0x21 <= c <= 0x7E or c >= 0x80 for c in value)
