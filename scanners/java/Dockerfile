# symbi-codered Java scanner sidecar.
#
# Bundles: semgrep (java security ruleset) + the jaschadub/compromised-packages
# known-malicious dependency check. Java SAST is source-based via semgrep, so
# no JVM/bytecode tooling is needed and the image stays a lightweight python
# base. Long-running container; the orchestrator invokes scanners via
# `docker exec`.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="symbi-codered-scanner-java"
LABEL org.opencontainers.image.description="Java scanner sidecar (semgrep java ruleset + compromised-packages)"
LABEL org.opencontainers.image.licenses="Proprietary"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git jq \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    "semgrep>=1.90,<2.0"

# Pre-warm semgrep
RUN semgrep --version

# Bake offline semgrep ruleset into the image: sidecar runs with
# network_mode: none, so it cannot reach the Semgrep registry. The runner
# uses --config /opt/semgrep-rules/java. Drop the dilutive non-security
# rule-dirs and semgrep's own test fixture .yml files (which semgrep would
# otherwise reject as missing rule metadata).
RUN git clone --depth=1 https://github.com/semgrep/semgrep-rules.git /opt/semgrep-rules \
    && rm -rf /opt/semgrep-rules/.git \
              /opt/semgrep-rules/stats \
              /opt/semgrep-rules/template \
              /opt/semgrep-rules/scripts \
              /opt/semgrep-rules/.github \
              /opt/semgrep-rules/libsonnet \
    && find /opt/semgrep-rules -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) -delete \
    && find /opt/semgrep-rules -name '*.test.yaml' -delete \
    && find /opt/semgrep-rules -name '*.test.yml' -delete \
    && find /opt/semgrep-rules -type d \( \
              -name correctness -o -name maintainability -o -name best-practice \
              -o -name style -o -name performance \) -prune -exec rm -rf {} +

# Bake the initial copy of jaschadub/compromised-packages-check. The
# orchestrator can `docker cp` a fresher copy in before each hunt to pick up
# the upstream list without breaking the sidecar's network_mode: none guarantee.
RUN git clone --depth=1 https://github.com/jaschadub/compromised-packages-check.git /opt/compromised-packages-check \
    && rm -rf /opt/compromised-packages-check/.git

COPY scanner-runner.py /usr/local/bin/scanner-runner
RUN chmod +x /usr/local/bin/scanner-runner

COPY entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint

ENTRYPOINT ["/usr/local/bin/entrypoint"]
