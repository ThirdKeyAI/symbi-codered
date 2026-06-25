# symbi-codered Go scanner sidecar.
#
# Bundles: gosec (security checker), govulncheck (Go vuln DB + reachability),
# staticcheck (correctness lints SA*/S*). Long-running container; the
# orchestrator invokes scanners via `docker exec`.
FROM golang:1.24-alpine

LABEL org.opencontainers.image.title="symbi-codered-scanner-go"
LABEL org.opencontainers.image.description="Go scanner sidecar (gosec + govulncheck + staticcheck)"
LABEL org.opencontainers.image.licenses="Proprietary"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    CGO_ENABLED=0 \
    GOTOOLCHAIN=local

# Alpine ships musl + busybox; we need python3 for the runner, git for
# go-get-style installs of scanner binaries, and ca-certificates so the
# initial `go install` resolves module proxy TLS. jq is a quality-of-life
# tool for debugging from inside the container.
RUN apk add --no-cache \
        ca-certificates git jq \
        python3 py3-pip bash

# Pinned versions: bump deliberately, never via "latest".
# GOBIN must be in PATH so the runner can invoke scanners by bare name.
ENV GOBIN=/usr/local/bin

RUN go install github.com/securego/gosec/v2/cmd/gosec@v2.21.4 \
 && go install golang.org/x/vuln/cmd/govulncheck@v1.1.4 \
 && go install honnef.co/go/tools/cmd/staticcheck@2024.1.1 \
 && rm -rf /root/.cache/go-build /go/pkg/mod

COPY scanner-runner.py /usr/local/bin/scanner-runner
RUN chmod +x /usr/local/bin/scanner-runner

COPY entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint

WORKDIR /repo
ENTRYPOINT ["/usr/local/bin/entrypoint"]
