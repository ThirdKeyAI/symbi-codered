# Plan F: go-sandbox for poc_forge reproducer scripts.
FROM golang:1.24-alpine

ENV GOFLAGS=-mod=mod \
    CGO_ENABLED=0

RUN apk add --no-cache \
    python3 \
    py3-pip \
    bash \
    ca-certificates

# Module lives in /sandbox, NOT /tmp: Go 1.21+ refuses to honor a go.mod in a
# "system temp root" (/tmp), printing "ignoring go.mod in system temp root"
# and failing `go get`. The reproducer writes main.go here too (see
# run-reproducer.py), so the pre-seeded module is in scope at runtime.
WORKDIR /sandbox

# Pre-seed go module with common deps so the sandbox doesn't need network
# at runtime. net/http is stdlib (no fetch needed); lib/pq is a common
# SQL driver many vuln repros depend on.
RUN go mod init repro \
    && go get github.com/lib/pq \
    && go mod download

COPY run-reproducer.py /usr/local/bin/run-reproducer
RUN chmod +x /usr/local/bin/run-reproducer

COPY entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint

ENTRYPOINT ["/usr/local/bin/entrypoint"]
