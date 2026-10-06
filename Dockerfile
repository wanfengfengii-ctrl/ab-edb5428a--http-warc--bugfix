# WARC ingestion audit service — no third-party runtime dependencies.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

WORKDIR /app

# Standard-library-only application; copy source and verification assets.
COPY warc_audit/ ./warc_audit/
COPY tests/ ./tests/
COPY scripts/ ./scripts/

# Container-level health probe (compose declares the same check so the
# one-shot verify service can wait for service_healthy).
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=10 \
    CMD python -c "import os,urllib.request,sys; p=os.environ.get('PORT','8080'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{p}/healthz', timeout=2).status == 200 else 1)"

EXPOSE 8080

CMD ["python", "-m", "warc_audit"]
