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
    chunked_transfer,
    http_chunked_response,
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

    def test_block_byte_corruption_detected(self):
        data, _ = build_valid_archive()
        # Flip a byte inside the first record's block.
        bad = bytearray(data)
        idx = data.index(b"software:")
        bad[idx] = ord("Z")
        self.assertRejects(bytes(bad), "block_digest_mismatch", record=1)


class ChunkedTransferTests(unittest.TestCase):
    """RFC 7230 chunked transfer coding: legal forms accepted and decoded,
    every malformed or truncated framing rejected as a stable content error."""

    def assertRejects(self, block, reason, record=1):
        rec = warc_record(
            "response", block, target_uri="http://e/",
            payload_digest="sha256:" + "0" * 64,  # digest checked after framing
        )
        with self.assertRaises(WARCAuditError) as cm:
            audit_warc(rec)
        err = cm.exception
        self.assertEqual(err.reason, reason, err.message)
        self.assertEqual(err.code, ERR_CONTENT)
        self.assertEqual(err.record, record)

    def chunked_record(self, entity: bytes, chunks: list[bytes], **kw):
        block = http_chunked_response(chunked_transfer(chunks, **kw))
        return warc_record(
            "response", block, target_uri="http://e/",
            payload_digest=payload_digest_of(entity),
        )

    # ---- legal forms ----------------------------------------------------

    def test_two_chunk_wikipedia_body(self):
        # The regression scenario: "Wiki" + "pedia", complete raw block
        # digest, payload digest over the decoded entity only.
        entity = b"Wikipedia"
        data = self.chunked_record(entity, [b"Wiki", b"pedia"])
        result = audit_warc(data)
        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0].payload_digest, hashlib.sha256(entity).hexdigest())
        # Block length/digest cover the undecoded chunked HTTP message.
        block = http_chunked_response(chunked_transfer([b"Wiki", b"pedia"]))
        self.assertEqual(result.records[0].block_length, len(block))
        self.assertEqual(result.records[0].block_digest, hashlib.sha256(block).hexdigest())

    def test_single_chunk(self):
        data = self.chunked_record(b"hello", [b"hello"])
        result = audit_warc(data)
        self.assertEqual(result.records[0].payload_digest, hashlib.sha256(b"hello").hexdigest())

    def test_empty_entity_last_chunk_only(self):
        data = self.chunked_record(b"", [])
        result = audit_warc(data)
        self.assertEqual(result.records[0].payload_digest, hashlib.sha256(b"").hexdigest())

    def test_last_chunk_always_terminates(self):
        # Per RFC 7230 a zero-size chunk IS the last-chunk: bytes after it
        # are the trailer section, not more chunks, so a "0" followed by
        # another chunk-size line is malformed.
        self.assertRejects(
            http_chunked_response(b"1\r\na\r\n0\r\n1\r\nb\r\n0\r\n\r\n"),
            "invalid_http_message",
        )

    def test_lowercase_hex_chunk_sizes(self):
        block = http_chunked_response(b"a\r\n0123456789\r\n0\r\n\r\n")
        rec = warc_record(
            "response", block, target_uri="http://e/",
            payload_digest=payload_digest_of(b"0123456789"),
        )
        result = audit_warc(rec)
        self.assertEqual(result.records[0].payload_digest, hashlib.sha256(b"0123456789").hexdigest())

    def test_chunk_extensions_on_data_and_last_chunk(self):
        transfer = chunked_transfer(
            [b"abc"],
            extensions=[b'name="value;x";foo=bar'],
            last_chunk_ext=b'path="/tmp/x"',
        )
        block = http_chunked_response(transfer)
        rec = warc_record(
            "response", block, target_uri="http://e/",
            payload_digest=payload_digest_of(b"abc"),
        )
        result = audit_warc(rec)
        self.assertEqual(result.records[0].payload_digest, hashlib.sha256(b"abc").hexdigest())

    def test_chunk_extension_quoted_pair_and_obs_text(self):
        transfer = chunked_transfer([b"x"], extensions=[b'q="a\\"b\x80"'])
        block = http_chunked_response(transfer)
        rec = warc_record(
            "response", block, target_uri="http://e/",
            payload_digest=payload_digest_of(b"x"),
        )
        audit_warc(rec)  # must not raise

    def test_trailer_fields(self):
        transfer = chunked_transfer([b"body"], trailers=(("Content-MD5", "zzz"), ("X-Trailer", "1")))
        block = http_chunked_response(transfer)
        rec = warc_record(
            "response", block, target_uri="http://e/",
            payload_digest=payload_digest_of(b"body"),
        )
        result = audit_warc(rec)
        self.assertEqual(result.records[0].payload_digest, hashlib.sha256(b"body").hexdigest())

    def test_many_chunks(self):
        entity = bytes(range(250))
        chunks = [bytes([b]) for b in entity]
        data = self.chunked_record(entity, chunks)
        result = audit_warc(data)
        self.assertEqual(result.records[0].payload_digest, hashlib.sha256(entity).hexdigest())

    def test_chunked_response_then_revisit_reference(self):
        entity = b"deduplicated bytes"
        rid = new_record_id()
        pd = payload_digest_of(entity)
        data = b"".join(
            [
                warc_record(
                    "response",
                    http_chunked_response(chunked_transfer([entity[:5], entity[5:]])),
                    record_id=rid, target_uri="http://e/", payload_digest=pd,
                ),
                warc_record(
                    "revisit", http_response_headers_only(len(entity)),
                    target_uri="http://e/", payload_digest=pd, refers_to=rid,
                ),
            ]
        )
        result = audit_warc(data)
        self.assertEqual([r.warc_type for r in result.records], ["response", "revisit"])
        self.assertEqual(result.records[1].payload_digest, result.records[0].payload_digest)

    def test_wrong_payload_digest_over_encoded_bytes_rejected(self):
        # Digest of the raw (still-chunked) block body must NOT be accepted
        # as the payload digest; only the decoded entity counts.
        raw_transfer = chunked_transfer([b"Wiki", b"pedia"])
        block = http_chunked_response(raw_transfer)
        rec = warc_record(
            "response", block, target_uri="http://e/",
            payload_digest=payload_digest_of(raw_transfer),
        )
        with self.assertRaises(WARCAuditError) as cm:
            audit_warc(rec)
        self.assertEqual(cm.exception.reason, "payload_digest_mismatch")

    def test_block_digest_still_covers_raw_chunked_block(self):
        # Corrupting a chunk-size byte must break the block digest even
        # though the decoded entity would otherwise be valid.
        block = http_chunked_response(chunked_transfer([b"abc"]))
        good = warc_record(
            "response", block, target_uri="http://e/",
            payload_digest=payload_digest_of(b"abc"),
        )
        bad = bytearray(good)
        idx = good.index(b"3\r\nabc")
        bad[idx] = ord("4")  # size line now claims 4 bytes -> framing error too
        with self.assertRaises(WARCAuditError) as cm:
            audit_warc(bytes(bad))
        # Block digest is checked first: the raw block changed.
        self.assertEqual(cm.exception.code, ERR_CONTENT)

    # ---- malformed framing (invalid_http_message) ------------------------

    def test_chunk_size_not_hex_rejected(self):
        self.assertRejects(
            http_chunked_response(b"xy\r\nx\r\n0\r\n\r\n"), "invalid_http_message"
        )

    def test_chunk_size_line_without_crlf_rejected(self):
        self.assertRejects(http_chunked_response(b"4x\r\nWiki\r\n0\r\n\r\n"), "invalid_http_message")

    def test_chunk_data_boundary_must_be_crlf(self):
        self.assertRejects(
            http_chunked_response(b"4\r\nWiki\rX\r\n0\r\n\r\n"), "invalid_http_message"
        )

    def test_chunk_data_shorter_but_boundary_present_rejected(self):
        # Size says 4 but the next four bytes include a CRLF in the wrong
        # place: "Wik\r" then "\n0\r\n..." — boundary after 4 bytes fails.
        self.assertRejects(
            http_chunked_response(b"4\r\nWik\r\n\r\n0\r\n\r\n"), "invalid_http_message"
        )

    def test_bad_chunk_extension_name_rejected(self):
        self.assertRejects(
            http_chunked_response(b"4;bad name\r\nWiki\r\n0\r\n\r\n"), "invalid_http_message"
        )

    def test_bad_chunk_extension_value_rejected(self):
        self.assertRejects(
            http_chunked_response(b'4;x="unterminated\r\nWiki\r\n0\r\n\r\n'),
            "invalid_http_message",
        )

    def test_bad_chunk_extension_quoted_pair_rejected(self):
        self.assertRejects(
            http_chunked_response(b'4;x="a\\\x7fb"\r\nWiki\r\n0\r\n\r\n'),
            "invalid_http_message",
        )

    def test_chunk_extension_dangling_equals_rejected(self):
        self.assertRejects(
            http_chunked_response(b"4;x=\r\nWiki\r\n0\r\n\r\n"), "invalid_http_message"
        )

    def test_trailer_field_without_colon_rejected(self):
        self.assertRejects(
            http_chunked_response(b"4\r\nWiki\r\n0\r\nnot-a-field\r\n\r\n"),
            "invalid_http_message",
        )

    def test_trailer_folding_rejected(self):
        self.assertRejects(
            http_chunked_response(b"4\r\nWiki\r\n0\r\nX: a\r\n b\r\n\r\n"),
            "invalid_http_message",
        )

    def test_duplicate_trailer_field_rejected(self):
        self.assertRejects(
            http_chunked_response(b"0\r\nX: 1\r\nX: 2\r\n\r\n"), "invalid_http_message"
        )

    def test_trailer_field_name_must_be_token_rejected(self):
        self.assertRejects(
            http_chunked_response(b"0\r\nX\x01: y\r\n\r\n"), "invalid_http_message"
        )

    def test_extra_bytes_after_terminator_rejected(self):
        self.assertRejects(
            http_chunked_response(b"4\r\nWiki\r\n0\r\n\r\nX"), "invalid_http_message"
        )

    def test_extra_crlf_after_terminator_rejected(self):
        self.assertRejects(
            http_chunked_response(b"4\r\nWiki\r\n0\r\n\r\n\r\n"), "invalid_http_message"
        )

    def test_missing_final_blank_line_rejected(self):
        # Last chunk present but the trailer section never closes.
        self.assertRejects(http_chunked_response(b"4\r\nWiki\r\n0\r\n"), "payload_truncated")

    def test_chunked_with_content_length_rejected(self):
        block = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
            b"Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n"
            b"4\r\nWiki\r\n0\r\n\r\n"
        )
        self.assertRejects(block, "invalid_http_message")

    def test_non_chunked_transfer_encoding_rejected(self):
        block = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
            b"Transfer-Encoding: gzip\r\n\r\n\x00\x00"
        )
        self.assertRejects(block, "invalid_http_message")

    def test_chunked_on_http_1_0_rejected(self):
        block = (
            b"HTTP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        )
        self.assertRejects(block, "invalid_http_message")

    def test_duplicate_transfer_encoding_header_rejected(self):
        block = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
            b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"0\r\n\r\n"
        )
        self.assertRejects(block, "invalid_http_message")

    # ---- truncation (payload_truncated) ---------------------------------

    def test_truncated_in_size_line(self):
        self.assertRejects(http_chunked_response(b"4\r\nWiki\r\n4"), "payload_truncated")

    def test_truncated_chunk_data(self):
        self.assertRejects(http_chunked_response(b"4\r\nWik"), "payload_truncated")

    def test_truncated_chunk_data_crlf_missing(self):
        self.assertRejects(http_chunked_response(b"4\r\nWiki"), "payload_truncated")

    def test_truncated_chunk_data_only_cr(self):
        self.assertRejects(http_chunked_response(b"4\r\nWiki\r"), "payload_truncated")

    def test_truncated_before_last_chunk(self):
        self.assertRejects(http_chunked_response(b"4\r\nWiki\r\n"), "payload_truncated")

    def test_truncated_inside_extension(self):
        self.assertRejects(
            http_chunked_response(b"4\r\nWiki\r\n0;foo=ba"), "payload_truncated"
        )

    def test_truncated_trailer_field(self):
        self.assertRejects(
            http_chunked_response(b"4\r\nWiki\r\n0\r\nX: partial"), "payload_truncated"
        )

    def test_declared_chunk_size_exceeding_block_is_truncation(self):
        # A syntactically legal but enormous chunk size: the declared data
        # is absent, so this is truncation, not a malformed size line.
        self.assertRejects(
            http_chunked_response(b"ffffffffffffffff\r\nX"), "payload_truncated"
        )

    def test_chunked_revisit_without_last_chunk_rejected(self):
        # A chunked revisit may not masquerade as a canonical headers-only
        # revisit: an incomplete chunked body is always payload_truncated.
        rid = new_record_id()
        pd = payload_digest_of(b"abc")
        data = b"".join(
            [
                warc_record(
                    "response", http_response(b"abc"), record_id=rid,
                    target_uri="http://e/", payload_digest=pd,
                ),
                warc_record(
                    "revisit", http_chunked_response(b"3\r\nab"),
                    target_uri="http://e/", payload_digest=pd, refers_to=rid,
                ),
            ]
        )
        with self.assertRaises(WARCAuditError) as cm:
            audit_warc(data)
        self.assertEqual(cm.exception.reason, "payload_truncated")
        self.assertEqual(cm.exception.record, 2)

    def test_complete_chunked_revisit_accepted(self):
        entity = b"revisited entity"
        rid = new_record_id()
        pd = payload_digest_of(entity)
        data = b"".join(
            [
                warc_record(
                    "response", http_response(entity), record_id=rid,
                    target_uri="http://e/", payload_digest=pd,
                ),
                warc_record(
                    "revisit",
                    http_chunked_response(chunked_transfer([entity[:4], entity[4:]])),
                    target_uri="http://e/", payload_digest=pd, refers_to=rid,
                ),
            ]
        )
        result = audit_warc(data)
        self.assertEqual(result.records[1].payload_digest, pd[len("sha256:"):])


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
