#!/usr/bin/env python3
"""Entry point for the one-shot ``verify`` compose service.

It waits for the API healthcheck to pass, then runs, in order:

1. a byte-compilation / import build check,
2. the full unit-test suite,
3. API smoke tests against the running service:
   a valid package, a corrupted block digest and a dangling revisit
   reference.

The process exits non-zero on the first failed stage so ``docker compose
up`` (or ``docker compose up verify``) reports the verdict via the exit
code, then the container stops on its own.

Environment:
    AUDIT_URL: base URL of the audit service (default http://api:8080).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.warc_factory import (  # noqa: E402
    build_valid_archive,
    http_response,
    new_record_id,
    payload_digest_of,
    warc_record,
)

BASE_URL = os.environ.get("AUDIT_URL", "http://api:8080")
AUDIT_URL = BASE_URL.rstrip("/") + "/api/warc/audit"
HEALTH_URL = BASE_URL.rstrip("/") + "/healthz"


def stage(title: str):
    print(f"\n=== verify: {title} ===", flush=True)


def wait_for_ready(timeout: float = 60.0) -> None:
    stage(f"waiting for {HEALTH_URL}")
    deadline = time.time() + timeout
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(HEALTH_URL, timeout=2) as resp:
                if resp.status == 200:
                    print("service is ready")
                    return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            time.sleep(1)
    print(f"FATAL: service did not become ready: {last_error}")
    sys.exit(1)


def build_check() -> None:
    stage("build check (compileall + import)")
    subprocess.run(
        [sys.executable, "-m", "compileall", "-q", "warc_audit", "tests", "scripts"],
        check=True,
    )
    subprocess.run([sys.executable, "-c", "import warc_audit.server, warc_audit.parser"], check=True)
    print("compile + import OK")


def unit_tests() -> None:
    stage("unit tests")
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]
    )
    if result.returncode != 0:
        sys.exit(result.returncode)


def post_archive(payload: bytes) -> tuple[int, dict]:
    request = urllib.request.Request(
        AUDIT_URL,
        data=payload,
        headers={"Content-Type": "application/warc"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def check(condition: bool, message: str) -> None:
    if not condition:
        print(f"FAIL: {message}")
        sys.exit(1)
    print(f"ok: {message}")


def smoke_valid() -> None:
    stage("smoke 1/3: valid package accepted")
    data, _rid = build_valid_archive()
    status, body = post_archive(data)
    check(status == 200, f"HTTP 200 (got {status}, {body})")
    check(body["ok"] is True, "ok flag")
    check(body["count"] == 4, f"count == 4 (got {body.get('count')})")
    types = [r["type"] for r in body["records"]]
    check(
        types == ["warcinfo", "request", "response", "revisit"],
        f"records kept in original order {types}",
    )
    for record in body["records"]:
        check(len(record["blockDigest"]) == 64, "64-char lowercase block digest")
        check(record["blockLength"] >= 0, "block length present")
    check("payloadDigest" in body["records"][2], "response carries payload digest")
    check("payloadDigest" in body["records"][3], "revisit carries payload digest")
    print(json.dumps(body, indent=2)[:800])


def smoke_bad_digest() -> None:
    stage("smoke 2/3: corrupted block digest rejected")
    data, _rid = build_valid_archive()
    corrupted = bytearray(data)
    corrupted[data.index(b"software:")] = ord("Z")  # flip a payload byte
    status, body = post_archive(bytes(corrupted))
    check(status == 400, f"HTTP 400 (got {status})")
    check(body["ok"] is False, "ok flag false")
    err = body["error"]
    check(err["code"] == 4002, f"stable error code 4002 (got {err['code']})")
    check(err["reason"] == "block_digest_mismatch", f"reason block_digest_mismatch (got {err['reason']})")
    check(err["record"] == 1, f"first failing record is #1 (got {err.get('record')})")
    print(json.dumps(err, indent=2))


def smoke_bad_reference() -> None:
    stage("smoke 3/3: dangling revisit reference rejected")
    body_text = b"<html>revisited</html>"
    pd = payload_digest_of(body_text)
    package = b"".join(
        [
            warc_record(
                "response",
                http_response(body_text),
                record_id=new_record_id(),
                target_uri="http://example.invalid/",
                payload_digest=pd,
            ),
            warc_record(
                "revisit",
                http_response(body_text),
                target_uri="http://example.invalid/",
                payload_digest=pd,
                refers_to="<urn:uuid:00000000-0000-0000-0000-ffffffffffff>",
            ),
        ]
    )
    status, body = post_archive(package)
    check(status == 400, f"HTTP 400 (got {status})")
    err = body["error"]
    check(err["code"] == 4002, f"stable error code 4002 (got {err['code']})")
    check(
        err["reason"] == "dangling_revisit_reference",
        f"reason dangling_revisit_reference (got {err['reason']})",
    )
    check(err["record"] == 2, f"first failing record is #2 (got {err.get('record')})")
    print(json.dumps(err, indent=2))


def main() -> None:
    wait_for_ready()
    build_check()
    unit_tests()
    smoke_valid()
    smoke_bad_digest()
    smoke_bad_reference()
    print("\nALL VERIFICATION STAGES PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
