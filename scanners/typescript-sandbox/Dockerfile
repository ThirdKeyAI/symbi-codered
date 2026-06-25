# Plan F: typescript-sandbox for poc_forge reproducer scripts.
FROM node:22-slim

ENV NODE_ENV=development \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

# Pre-seed package.json with common deps; install offline-ready node_modules
# so the sandbox can run without network.
COPY package.json.seed /tmp/package.json
RUN cd /tmp && npm install --silent

COPY run-reproducer.py /usr/local/bin/run-reproducer
RUN chmod +x /usr/local/bin/run-reproducer

COPY entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint

ENTRYPOINT ["/usr/local/bin/entrypoint"]
