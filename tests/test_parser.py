"""Unit tests for the strict WARC 1.1 parser.

Run with: python -m unittest discover -s tests -v
"""

from __future__ import annotations

import copy
import hashlib
import unittest

from warc_audit.parser import ERR_BOUNDARY, ERR_CONTENT, WARCAuditError, audit_warc

from tests.warc_factory import (
    build_valid_archive,
    http_response,
    http_response_headers_only,
    new_record_id,
    payload_digest_of,
    warc_record,
)


class ValidArchiveTests(unittest.TestCase):
    def test_full_valid_archive(self):
        data, _rid = build_valid_archive()
        result = audit_warc(data)
        self.assertEqual(len(result.records), 4)
        types = [r.warc_type for r in result.records]
        self.assertEqual(types, ["warcinfo", "request", "response", "revisit"])
        for i, r in enumerate(result.records, start=1):
            self.assertEqual(r.index, i)
            self.assertEqual(len(r.block_digest), 64)
            self.assertNotIn("X", r.block_digest)
        self.assertIsNone(result.records[0].payload_digest)
        self.assertIsNone(result.records[1].payload_digest)
        self.assertIsNotNone(result.records[2].payload_digest)
        self.assertEqual(result.records[2].payload_digest, result.records[3].payload_digest)
        d = result.to_dict()
        self.assertEqual(d["count"], 4)
        self.assertEqual(set(d["records"][0]), {"index", "type", "blockLength", "blockDigest"})
        self.assertIn("payloadDigest", d["records"][2])

    def test_block_lengths_reported_in_order(self):
        body = b"abc"
        data = b"".join(
            [
                warc_record("warcinfo", b"x"),
                warc_record(
                    "response",
                    http_response(body),
                    target_uri="http://e.test/",
                    payload_digest=payload_digest_of(body),
                ),
            ]
        )
        result = audit_warc(data)
        self.assertEqual(result.records[0].block_length, 1)
        self.assertEqual(result.records[1].block_length, len(http_response(body)))

    def test_revisit_of_earliest_response_with_duplicate_payload(self):
        body = b"same bytes"
        rid1, rid2 = new_record_id(), new_record_id()
        pd = payload_digest_of(body)
        data = b"".join(
            [
                warc_record(
                    "response", http_response(body), record_id=rid1,
                    target_uri="http://a/", payload_digest=pd,
                ),
                warc_record(
                    "response", http_response(body), record_id=rid2,
                    target_uri="http://b/", payload_digest=pd,
                ),
                warc_record(
                    "revisit", http_response(body), target_uri="http://b/",
                    payload_digest=pd, refers_to=rid1,
                ),
            ]
        )
        result = audit_warc(data)
        self.assertEqual([r.warc_type for r in result.records], ["response", "response", "revisit"])


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.valid, _ = build_valid_archive()

    def assertRejects(self, data, reason, record=None, code=ERR_BOUNDARY):
        with self.assertRaises(WARCAuditError) as cm:
            audit_warc(data)
        err = cm.exception
        self.assertEqual(err.reason, reason, err.message)
        self.assertEqual(err.code, code)
        if record is not None:
            self.assertEqual(err.record, record)

    def test_empty(self):
        self.assertRejects(b"", "empty_body", record=None, code=4000)

    def test_bad_version(self):
        bad = self.valid.replace(b"WARC/1.1", b"WARC/1.0", 1)
        self.assertRejects(bad, "unsupported_version", record=1)

    def test_lf_only_record_start(self):
        # Replace first CRLF after version with bare LF.
        bad = b"WARC/1.1\n" + self.valid[len(b"WARC/1.1\r\n"):]
        self.assertRejects(bad, "malformed_record", record=1)

    def test_bare_lf_in_header(self):
        # CRLF after the WARC-Type header line replaced with a bare LF.
        needle = b"WARC/1.1\r\nWARC-Type: warcinfo\r\n"
        fixed_head = b"WARC/1.1\r\nWARC-Type: warcinfo\n"
        bad = fixed_head + self.valid[len(needle):]
        self.assertRejects(bad, "malformed_header", record=1)

    def test_single_crlf_terminator_rejected(self):
        rec = warc_record("warcinfo", b"hi")
        stripped = rec[:-2]  # leaves only the CRLF ending the block
        self.assertRejects(stripped, "missing_record_terminator", record=1)

    def test_block_separator_must_be_crlf(self):
        # First block ended by a bare LF instead of the CRLF CRLF terminator.
        first = warc_record("warcinfo", b"hi")
        body = b"x"
        second = warc_record(
            "response", http_response(body), target_uri="http://e/",
            payload_digest=payload_digest_of(body),
        )
        bad = first[:-4] + b"\n" + second
        self.assertRejects(bad, "missing_record_separator", record=1)

    def test_duplicate_required_header(self):
        rec = warc_record("warcinfo", b"hi", duplicate_header=("WARC-Type", "request"))
        self.assertRejects(rec, "duplicate_required_or_header", record=1)

    def test_duplicate_any_header_rejected(self):
        rec = warc_record(
            "warcinfo", b"hi",
            extra_headers=(("X-Custom", "0"),),
            duplicate_header=("X-Custom", "1"),
        )
        self.assertRejects(rec, "duplicate_required_or_header", record=1)

    def test_missing_required_header(self):
        rec = warc_record("warcinfo", b"hi")
        # Strip WARC-Date line.
        bad = rec.replace(b"WARC-Date: 2026-10-06T00:00:00Z\r\n", b"")
        self.assertRejects(bad, "missing_required_header", record=1)

    def test_missing_content_length(self):
        rec = warc_record("warcinfo", b"hi").replace(b"Content-Length: 2\r\n", b"")
        self.assertRejects(rec, "missing_required_header", record=1)

    def test_content_length_non_numeric(self):
        rec = warc_record("warcinfo", b"hi", declared_length=2).replace(
            b"Content-Length: 2", b"Content-Length: two", 1
        )
        self.assertRejects(rec, "invalid_content_length", record=1)

    def test_content_length_shorter_than_block(self):
        rec = warc_record("warcinfo", b"hello", declared_length=3)
        # declared block 3 bytes, real bytes "hello" + CRLF -> separator check
        # fails on the 'l' bytes; it is still a boundary error at record 1.
        with self.assertRaises(WARCAuditError) as cm:
            audit_warc(rec)
        self.assertEqual(cm.exception.code, ERR_BOUNDARY)
        self.assertEqual(cm.exception.record, 1)

    def test_content_length_longer_than_archive(self):
        rec = warc_record("warcinfo", b"hi", declared_length=999)
        self.assertRejects(rec, "block_truncated", record=1)

    def test_trailing_garbage_after_record(self):
        rec = warc_record("warcinfo", b"hi")
        self.assertRejects(rec + b"\x00", "malformed_record", record=2)

    def test_extra_blank_line_between_records(self):
        first = warc_record("warcinfo", b"hi")
        second = warc_record("warcinfo", b"yo")
        self.assertRejects(first + b"\r\n" + second, "extra_blank_line", record=1)

    def test_unknown_record_type(self):
        rec = warc_record("metadata", b"hi")
        self.assertRejects(rec, "unsupported_record_type", record=1)

    def test_duplicate_warc_record_id(self):
        rid = new_record_id()
        data = b"".join(
            [
                warc_record("warcinfo", b"a", record_id=rid),
                warc_record("warcinfo", b"bb", record_id=rid),
            ]
        )
        self.assertRejects(data, "duplicate_record_id", record=2)

    def test_too_many_records(self):
        data = b"".join(warc_record("warcinfo", b"x") for _ in range(501))
        with self.assertRaises(WARCAuditError) as cm:
            audit_warc(data)
        self.assertEqual(cm.exception.reason, "too_many_records")
        self.assertEqual(cm.exception.record, 501)

    def test_header_folding_rejected(self):
        rec = b"WARC/1.1\r\nWARC-Type: warcinfo\r\n folded\r\n"
        with self.assertRaises(WARCAuditError) as cm:
            audit_warc(rec)
        self.assertEqual(cm.exception.reason, "folded_header")


class ContentTests(unittest.TestCase):
    def assertRejects(self, data, reason, record=None, code=ERR_CONTENT):
        with self.assertRaises(WARCAuditError) as cm:
            audit_warc(data)
        err = cm.exception
        self.assertEqual(err.reason, reason, err.message)
        self.assertEqual(err.code, code)
        if record is not None:
            self.assertEqual(err.record, record)

    def test_bad_block_digest_record_2(self):
        body = b"x"
        rid = new_record_id()
        data = b"".join(
            [
                warc_record("warcinfo", b"a"),
                warc_record(
                    "response", http_response(body), record_id=rid, target_uri="http://e/",
                    payload_digest=payload_digest_of(body),
                    block_digest="sha256:" + "0" * 64,
                ),
            ]
        )
        self.assertRejects(data, "block_digest_mismatch", record=2)

    def test_digest_must_be_lowercase_hex(self):
        upper = "sha256:" + ("A" * 64)
        rec = warc_record("warcinfo", b"a", block_digest=upper)
        self.assertRejects(rec, "malformed_digest", record=1)

    def test_digest_other_algorithm_rejected(self):
        rec = warc_record("warcinfo", b"a", block_digest="md5:0" * 1)
        # Build an actually well-shaped md5 label with bogus hex
        rec = warc_record("warcinfo", b"a", block_digest="md5:" + "0" * 32)
        self.assertRejects(rec, "unsupported_digest_algorithm", record=1)

    def test_missing_block_digest(self):
        rec = warc_record("warcinfo", b"a").replace(b"WARC-Block-Digest: ", b"WARC-X: ")
        self.assertRejects(rec, "missing_required_header", record=1, code=ERR_BOUNDARY)

    def test_response_requires_payload_digest(self):
        body = b"x"
        rec = warc_record("response", http_response(body), target_uri="http://e/")
        with self.assertRaises(WARCAuditError) as cm:
            audit_warc(rec)
        self.assertEqual(cm.exception.reason, "missing_required_header")

    def test_bad_payload_digest(self):
        body = b"x"
        rec = warc_record(
            "response", http_response(body), target_uri="http://e/",
            payload_digest="sha256:" + "1" * 64,
        )
        self.assertRejects(rec, "payload_digest_mismatch", record=1)

    def test_payload_digest_covers_entity_body_only(self):
        body = b"<html/>"
        rec = warc_record(
            "response", http_response(body), target_uri="http://e/",
            payload_digest="sha256:" + hashlib.sha256(body).hexdigest(),
        )
        result = audit_warc(rec)
        self.assertEqual(result.records[0].payload_digest, hashlib.sha256(body).hexdigest())

    def test_http_content_length_mismatch_rejected(self):
        body = b"x"
        block = http_response(body, content_length=5)  # says 5, body is 1 byte
        rec = warc_record(
            "response", block, target_uri="http://e/",
            payload_digest=payload_digest_of(body),
        )
        self.assertRejects(rec, "payload_truncated", record=1)

    def test_response_body_longer_than_content_length_rejected(self):
        block = http_response(b"x", content_length=1) + b"extra"
        rec = warc_record(
            "response", block, target_uri="http://e/",
            payload_digest="sha256:" + hashlib.sha256(b"x").hexdigest(),
        )
        self.assertRejects(rec, "invalid_http_message", record=1)

    def test_chunked_http_rejected(self):
        block = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n"
        rec = warc_record(
            "response", block, target_uri="http://e/",
            payload_digest="sha256:" + hashlib.sha256(b"").hexdigest(),
        )
        self.assertRejects(rec, "invalid_http_message", record=1)

    def test_block_byte_corruption_detected(self):
        data, _ = build_valid_archive()
        # Flip a byte inside the first record's block.
        bad = bytearray(data)
        idx = data.index(b"software:")
        bad[idx] = ord("Z")
        self.assertRejects(bytes(bad), "block_digest_mismatch", record=1)


class RevisitReferenceTests(unittest.TestCase):
    def assertRejects(self, data, reason, record):
        with self.assertRaises(WARCAuditError) as cm:
            audit_warc(data)
        self.assertEqual(cm.exception.reason, reason, cm.exception.message)
        self.assertEqual(cm.exception.code, ERR_CONTENT)
        self.assertEqual(cm.exception.record, record)

    def test_forward_reference_rejected(self):
        body = b"page"
        rid = new_record_id()
        pd = payload_digest_of(body)
        data = b"".join(
            [
                warc_record(
                    "revisit", http_response(body), target_uri="http://e/",
                    payload_digest=pd, refers_to=rid,
                ),
                warc_record(
                    "response", http_response(body), record_id=rid,
                    target_uri="http://e/", payload_digest=pd,
                ),
            ]
        )
        self.assertRejects(data, "dangling_revisit_reference", record=1)

    def test_dangling_reference_rejected(self):
        body = b"page"
        pd = payload_digest_of(body)
        data = b"".join(
            [
                warc_record(
                    "response", http_response(body), record_id=new_record_id(),
                    target_uri="http://e/", payload_digest=pd,
                ),
                warc_record(
                    "revisit", http_response(body), target_uri="http://e/",
                    payload_digest=pd, refers_to="<urn:uuid:deadbeef>",
                ),
            ]
        )
        self.assertRejects(data, "dangling_revisit_reference", record=2)

    def test_reference_to_non_response_rejected(self):
        body = b"page"
        rid = new_record_id()
        pd = payload_digest_of(body)
        data = b"".join(
            [
                warc_record("warcinfo", b"x", record_id=rid),
                warc_record(
                    "revisit", http_response(body), target_uri="http://e/",
                    payload_digest=pd, refers_to=rid,
                ),
            ]
        )
        self.assertRejects(data, "dangling_revisit_reference", record=2)

    def test_payload_mismatch_rejected(self):
        body1, body2 = b"one", b"two"
        rid = new_record_id()
        data = b"".join(
            [
                warc_record(
                    "response", http_response(body1), record_id=rid,
                    target_uri="http://e/", payload_digest=payload_digest_of(body1),
                ),
                warc_record(
                    "revisit", http_response(body2), target_uri="http://e/",
                    payload_digest=payload_digest_of(body2), refers_to=rid,
                ),
            ]
        )
        self.assertRejects(data, "revisit_payload_mismatch", record=2)

    def test_missing_refers_to_rejected(self):
        body = b"page"
        rec = warc_record(
            "revisit", http_response(body), target_uri="http://e/",
            payload_digest=payload_digest_of(body),
        )
        with self.assertRaises(WARCAuditError) as cm:
            audit_warc(rec)
        self.assertEqual(cm.exception.reason, "missing_required_header")
        self.assertEqual(cm.exception.record, 1)

    def test_canonical_headers_only_revisit_accepted(self):
        # Canonical ISO/WARC shape: revisit block carries HTTP headers only,
        # no entity body; digest validated via the response reference.
        body = b"<html>canonical</html>"
        rid = new_record_id()
        pd = payload_digest_of(body)
        data = b"".join(
            [
                warc_record(
                    "response", http_response(body), record_id=rid,
                    target_uri="http://e/", payload_digest=pd,
                ),
                warc_record(
                    "revisit", http_response_headers_only(len(body)),
                    target_uri="http://e/", payload_digest=pd, refers_to=rid,
                ),
            ]
        )
        result = audit_warc(data)
        self.assertEqual(result.records[1].warc_type, "revisit")
        self.assertEqual(result.records[1].payload_digest, result.records[0].payload_digest)

    def test_headers_only_revisit_with_wrong_declared_digest_rejected(self):
        body = b"<html>canonical</html>"
        rid = new_record_id()
        data = b"".join(
            [
                warc_record(
                    "response", http_response(body), record_id=rid,
                    target_uri="http://e/", payload_digest=payload_digest_of(body),
                ),
                warc_record(
                    "revisit", http_response_headers_only(len(body)),
                    target_uri="http://e/",
                    payload_digest="sha256:" + "9" * 64, refers_to=rid,
                ),
            ]
        )
        self.assertRejects(data, "revisit_payload_mismatch", record=2)

    def test_partial_body_revisit_rejected(self):
        # A body is present but shorter than its declared Content-Length:
        # ambiguous and therefore refused.
        body = b"0123456789"
        rid = new_record_id()
        pd = payload_digest_of(body)
        partial_block = http_response_headers_only(len(body)) + b"0123"
        data = b"".join(
            [
                warc_record(
                    "response", http_response(body), record_id=rid,
                    target_uri="http://e/", payload_digest=pd,
                ),
                warc_record(
                    "revisit", partial_block, target_uri="http://e/",
                    payload_digest=pd, refers_to=rid,
                ),
            ]
        )
        self.assertRejects(data, "payload_truncated", record=2)


class FirstFailureTests(unittest.TestCase):
    def test_first_failing_record_is_reported(self):
        body = b"ok"
        data = b"".join(
            [
                warc_record("warcinfo", b"good"),
                warc_record(
                    "response", http_response(body), target_uri="http://e/",
                    payload_digest=payload_digest_of(body),
                ),
                warc_record(
                    "response", http_response(body), target_uri="http://f/",
                    payload_digest="sha256:" + "f" * 64,
                ),
                warc_record("warcinfo", b"never reached"),
            ]
        )
        with self.assertRaises(WARCAuditError) as cm:
            audit_warc(data)
        self.assertEqual(cm.exception.record, 3)
        self.assertEqual(cm.exception.reason, "payload_digest_mismatch")


if __name__ == "__main__":
    unittest.main()
