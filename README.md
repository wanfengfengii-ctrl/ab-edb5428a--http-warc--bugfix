# WARC Ingestion Audit

A strict **WARC 1.1** ingestion-gate service for a digital preservation
archive. Before a web-evidence package is archived, it verifies that record
boundaries, digests and de-duplication references all describe the **same
original bytes** — lenient parsing is deliberately avoided, so a corrupt or
internally inconsistent package can never enter the archive.

- Zero third-party runtime dependencies (Python 3.11 standard library only).
- `POST /api/warc/audit` consumes `application/warc`, up to **16 MiB**.

## What is verified

For every record (1–500 records of type `warcinfo`, `request`, `response`
or `revisit`):

- Records begin with the exact `WARC/1.1` line and use **CRLF** throughout;
  bare CR/LF, header folding and duplicate/unknown framing are rejected.
- Mandatory headers (`WARC-Type`, `WARC-Record-ID`, `WARC-Date`,
  `WARC-Block-Digest`, `Content-Length`) appear exactly once; record ids are
  unique.
- `Content-Length` matches the block bytes exactly and the block is
  terminated by the canonical `CRLF CRLF` record terminator.
- `WARC-Block-Digest` is `sha256:` + 64 lowercase hex chars and matches the
  declared block bytes.
- `response` / `revisit` also carry a `WARC-Payload-Digest` over the HTTP
  entity body. A `response` must contain the complete body; a canonical
  headers-only `revisit` has its digest proven via the reference below.
- A `revisit` may only use `WARC-Refers-To` to point to an **earlier**
  `response` in the same file whose payload digest is identical. Forward and
  dangling references, references to non-responses and payload mismatches are
  all rejected.

Any boundary, digest or reference failure rejects the **whole package**.

## Success response

`200 OK` with records in original order plus a total count:

```json
{
  "ok": true,
  "count": 4,
  "records": [
    {"index": 1, "type": "warcinfo", "blockLength": 46, "blockDigest": "…64 hex…"},
    {"index": 2, "type": "request",  "blockLength": 41, "blockDigest": "…"},
    {"index": 3, "type": "response", "blockLength": 114, "blockDigest": "…", "payloadDigest": "…"},
    {"index": 4, "type": "revisit",  "blockLength": 79,  "blockDigest": "…", "payloadDigest": "…"}
  ]
}
```

## Error response

`400 Bad Request` with a stable error code and the **first** failing record
number:

```json
{"ok": false, "error": {"code": 4002, "reason": "block_digest_mismatch",
                       "message": "…", "record": 1}}
```

| Code | Category | Example reasons |
|------|----------|-----------------|
| 4000 | request  | `empty_body`, `invalid_request` |
| 4001 | boundary | `unsupported_version`, `missing_record_separator`, `invalid_content_length`, `duplicate_required_or_header`, `missing_required_header`, `extra_blank_line`, `too_many_records` |
| 4002 | content / reference | `block_digest_mismatch`, `payload_digest_mismatch`, `malformed_digest`, `unsupported_digest_algorithm`, `invalid_http_message`, `payload_truncated`, `dangling_revisit_reference`, `revisit_payload_mismatch` |
| 4005 | request  | `method_not_allowed` (405) |
| 4006 | request  | `unsupported_media_type` (415) |
| 4007 | request  | `body_too_large` (413, > 16 MiB) |
| 4008 | request  | `empty_body` (400) |

## Run locally

```bash
python3 -m warc_audit            # serves on $PORT (default 8080)
curl -s -X POST --data-binary @pkg.warc \
  -H 'Content-Type: application/warc' \
  http://localhost:8080/api/warc/audit
```

## Tests

```bash
python3 -m unittest discover -s tests -v     # 42 parser unit tests
```

## Docker & Docker Compose

The host port is configurable via `HOST_PORT` (default `8080`); the container
port stays `8080`. Both the Dockerfile and compose file declare a healthcheck
against `/healthz`.

```bash
# build + serve on a chosen host port
HOST_PORT=9090 docker compose up --build

# one-shot verification: waits for the API to be healthy, then runs the
# build check, unit tests and valid / bad-digest / bad-reference API smoke
# tests, reports via its exit code and exits
docker compose up --build verify
docker compose ps            # verify shows Exited (0) on success
```

## Layout

```
warc_audit/parser.py   byte-strict WARC 1.1 parser + audit rules
warc_audit/server.py   stdlib HTTP API (/api/warc/audit, /healthz)
scripts/verify.py      one-shot verify service entry point
tests/                 parser unit tests + byte-exact WARC factory
Dockerfile, docker-compose.yml
```
