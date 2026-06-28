# php-sandbox for poc_forge reproducer scripts.
#
# Same posture as python-sandbox: no network egress, read-only /repo
# bind-mount, stays alive so the host orchestrator can `docker exec` in.
# The runner harness is Python (matching the other sandboxes); it shells
# out to `php` to execute the reproducer.
FROM php:8.3-cli

ENV PYTHONDONTWRITEBYTECODE=1

# python3 for the run-reproducer harness; pdo_sqlite so SQLi/RCE repros can
# stand up an in-process SQLite DB without any network or DB server.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates python3 libsqlite3-dev \
    && docker-php-ext-install pdo pdo_sqlite \
    && rm -rf /var/lib/apt/lists/*

COPY run-reproducer.py /usr/local/bin/run-reproducer
RUN chmod +x /usr/local/bin/run-reproducer

COPY entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint

WORKDIR /tmp
ENTRYPOINT ["/usr/local/bin/entrypoint"]
