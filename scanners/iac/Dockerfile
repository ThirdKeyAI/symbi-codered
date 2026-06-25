# symbi-codered IaC scanner sidecar.
#
# Bundles three IaC scanners that cover overlapping but complementary
# surfaces:
#   - checkov  — Terraform / CloudFormation / Kubernetes / Helm / Dockerfile / Serverless / ARM / GitHub Actions
#   - tfsec    — Terraform-specific; faster, catches a few patterns checkov misses
#   - trivy    — container image + IaC scanning; secret detection
#
# Same long-running pattern as the other scanner sidecars: the
# orchestrator invokes the runner via `docker exec`.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="symbi-codered-scanner-iac"
LABEL org.opencontainers.image.description="IaC scanner sidecar (checkov + tfsec + trivy)"
LABEL org.opencontainers.image.licenses="Proprietary"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git jq \
    && rm -rf /var/lib/apt/lists/*

# checkov via pip — pure Python, no extra runtime needed.
RUN pip install --no-cache-dir "checkov>=3.2,<4.0"

# tfsec — single Go binary, fetched from upstream releases.
ARG TFSEC_VERSION=1.28.13
RUN curl -sSfL "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-amd64" \
        -o /usr/local/bin/tfsec \
    && chmod +x /usr/local/bin/tfsec \
    && tfsec --version

# trivy — direct release tarball, avoids the install-script's quiet
# failure modes inside buildkit. The script approach silently exits 0
# on some asset-resolution failures; the explicit URL fails loudly.
ARG TRIVY_VERSION=0.70.0
RUN curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
        -o /tmp/trivy.tar.gz \
    && tar -xzf /tmp/trivy.tar.gz -C /tmp/ \
    && install -m 0755 /tmp/trivy /usr/local/bin/trivy \
    && rm -f /tmp/trivy.tar.gz /tmp/trivy /tmp/LICENSE /tmp/README.md \
    && trivy --version

# Pre-warm trivy's vuln DB at image-build so the first scan doesn't
# try to fetch. Failure here is non-fatal — first runtime scan with
# network access (if any) will populate. Without network, scans run
# misconfig + secret only, which is still useful.
RUN trivy --download-db-only --quiet --no-progress 2>/dev/null || true

COPY scanner-runner.py /usr/local/bin/scanner-runner
RUN chmod +x /usr/local/bin/scanner-runner

COPY entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint

WORKDIR /repo
ENTRYPOINT ["/usr/local/bin/entrypoint"]
