# symbi-codered PHP scanner sidecar.
#
# Bundles: semgrep (php security ruleset) + Progpilot (PHP-native security
# taint analysis) + the jaschadub/compromised-packages known-malicious
# dependency check. PHP SAST is source-based, so no vendor/autoload
# resolution is needed and the sidecar runs fully offline. Long-running
# container; the orchestrator invokes scanners via `docker exec`.
FROM php:8.3-cli

LABEL org.opencontainers.image.title="symbi-codered-scanner-php"
LABEL org.opencontainers.image.description="PHP scanner sidecar (semgrep php ruleset + progpilot + compromised-packages)"
LABEL org.opencontainers.image.licenses="Proprietary"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git jq python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

# semgrep via pip (php base image has no semgrep). Use a venv to avoid the
# Debian "externally-managed-environment" pip restriction.
RUN python3 -m venv /opt/semgrep-venv \
    && /opt/semgrep-venv/bin/pip install --no-cache-dir "semgrep>=1.90,<2.0"
ENV PATH="/opt/semgrep-venv/bin:${PATH}"

# Pre-warm semgrep
RUN semgrep --version

# Progpilot PHAR (pinned release). Verify it runs.
RUN curl -fsSL -o /opt/progpilot.phar \
      https://github.com/designsecurity/progpilot/releases/download/v1.3.0/progpilot_v1.3.0.phar \
    && php /opt/progpilot.phar --version || true
RUN php -r "exit(file_exists('/opt/progpilot.phar') ? 0 : 1);"

# Bake offline semgrep ruleset (sidecar has no network). Drop the dilutive
# non-security rule-dirs and semgrep's own test fixture .yml files. Runner
# points at /opt/semgrep-rules/php.
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

# Bake the initial compromised-packages list. The orchestrator `docker cp`s a
# fresher copy in before each hunt.
RUN git clone --depth=1 https://github.com/jaschadub/compromised-packages-check.git /opt/compromised-packages-check \
    && rm -rf /opt/compromised-packages-check/.git

COPY scanner-runner.py /usr/local/bin/scanner-runner
RUN chmod +x /usr/local/bin/scanner-runner

COPY entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint

ENTRYPOINT ["/usr/local/bin/entrypoint"]
