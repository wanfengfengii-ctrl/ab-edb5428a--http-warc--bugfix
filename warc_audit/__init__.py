"""Strict WARC 1.1 ingestion audit for a digital preservation archive.

The package exposes :func:`audit_warc`, which parses a WARC 1.1 byte string
and either returns an ordered description of every record or raises
:class:`WARCAuditError` describing the first boundary, digest or reference
failure.  Nothing about the input is parsed leniently: a rejected archive is
never partially admitted.
"""

from .parser import AuditResult, RecordInfo, WARCAuditError, audit_warc

__all__ = ["AuditResult", "RecordInfo", "WARCAuditError", "audit_warc"]
