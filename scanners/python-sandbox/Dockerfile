# Plan E: python-sandbox for poc_forge reproducer scripts.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Just enough to reproduce common Python web vulns from the test fixtures.
RUN pip install --no-cache-dir \
    "Flask>=3,<4" \
    "SQLAlchemy>=2,<3" \
    "requests>=2,<3"

COPY run-reproducer.py /usr/local/bin/run-reproducer
RUN chmod +x /usr/local/bin/run-reproducer

COPY entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint

WORKDIR /tmp
ENTRYPOINT ["/usr/local/bin/entrypoint"]
