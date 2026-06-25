# symbi-codered TypeScript scanner sidecar.
#
# Bundles: eslint (security + no-unsanitized plugins), npm-audit, semgrep
# (typescript / javascript rulesets). Long-running container; the orchestrator
# invokes scanners via `docker exec`.
FROM node:22-slim

LABEL org.opencontainers.image.title="symbi-codered-scanner-typescript"
LABEL org.opencontainers.image.description="TypeScript scanner sidecar (eslint-security + npm-audit + semgrep)"
LABEL org.opencontainers.image.licenses="Proprietary"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git jq \
    python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Python venv for semgrep (PEP 668: system Python is externally-managed in
# Debian-derived images). The runner shebangs `python3` and we put venv on
# PATH so `semgrep` resolves.
RUN python3 -m venv /opt/semgrep-venv \
    && /opt/semgrep-venv/bin/pip install --no-cache-dir "semgrep>=1.90,<2.0"
ENV PATH="/opt/semgrep-venv/bin:${PATH}"

# Pre-warm semgrep
RUN semgrep --version

# eslint 9 + security plugins + typescript-eslint stack, pinned to avoid
# silent breakage from upstream releases. Installed globally so the runner
# can invoke `eslint` from any cwd without per-repo `npm install`.
RUN npm install -g --omit=dev \
        eslint@9 \
        eslint-plugin-security@3 \
        eslint-plugin-no-unsanitized@4 \
        typescript@5 \
        @typescript-eslint/parser@8 \
        @typescript-eslint/eslint-plugin@8

# Bake offline semgrep ruleset into the image: sidecar runs with
# network_mode: none at runtime, so --config auto cannot reach the
# Semgrep registry. The runner uses --config /opt/semgrep-rules/typescript
# (falling back to /opt/semgrep-rules/javascript or /opt/semgrep-rules if
# the typescript subdir is absent). Strip non-rule directories and test
# fixture .yml files that semgrep would reject as missing the top-level
# `rules:` key.
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
            -name 'correctness' -o -name 'maintainability' \
         -o -name 'best-practice' -o -name 'style' \
         -o -name 'performance' -o -name 'compatibility' \
       \) -prune -exec rm -rf {} +

# Bundled eslint config: flat-config era still supports --no-eslintrc +
# legacy --config for runtime overrides. We use the legacy shape so the
# security plugins (which haven't fully migrated to flat config) work out
# of the box.
COPY eslintrc.json /usr/local/etc/eslintrc.json

# Bake initial copy of compromised-packages-check; see scanners/python/Dockerfile
# for the refresh contract.
RUN git clone --depth=1 https://github.com/jaschadub/compromised-packages-check.git /opt/compromised-packages-check \
    && rm -rf /opt/compromised-packages-check/.git

COPY scanner-runner.py /usr/local/bin/scanner-runner
RUN chmod +x /usr/local/bin/scanner-runner

COPY entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint

WORKDIR /repo
ENTRYPOINT ["/usr/local/bin/entrypoint"]
