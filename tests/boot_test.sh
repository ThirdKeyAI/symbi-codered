#!/usr/bin/env bash
# tests/boot_test.sh
#
# Integration test: build the orchestrator image, run the four smoke
# commands, assert each succeeds and produces expected output.
#
# Exits 0 on success, non-zero on first failure.

set -euo pipefail

IMG="${IMG:-symbi-codered-orchestrator:dev}"
LOG_DIR="$(mktemp -d)"
trap 'rm -rf "$LOG_DIR"' EXIT

step() { printf '  [TEST] %s\n' "$*"; }
fail() { printf '  [FAIL] %s\n' "$*" >&2; exit 1; }
pass() { printf '  [PASS] %s\n' "$*"; }

step "build orchestrator image"
docker build -f orchestrator/Dockerfile -t "$IMG" . > "$LOG_DIR/build.log" 2>&1 \
    || { cat "$LOG_DIR/build.log"; fail "docker build"; }
pass "image built: $IMG"

step "codered --version"
docker run --rm "$IMG" --version > "$LOG_DIR/version.log"
grep -q 'codered 0.1.0' "$LOG_DIR/version.log" \
    || { cat "$LOG_DIR/version.log"; fail "version not printed"; }
pass "codered --version OK"

step "tools list shows repo_overview"
docker run --rm "$IMG" tools list > "$LOG_DIR/tools-list.log"
grep -q 'repo_overview' "$LOG_DIR/tools-list.log" \
    || { cat "$LOG_DIR/tools-list.log"; fail "repo_overview missing from tools list"; }
pass "tools list OK"

step "tools validate succeeds"
docker run --rm "$IMG" tools validate > "$LOG_DIR/tools-validate.log"
# Count-agnostic: 'tools validate' prints "validated <N> manifest(s) in <dir>".
# Match any N so adding scanner manifests never breaks this boot check.
grep -qE 'validated [0-9]+ manifest' "$LOG_DIR/tools-validate.log" \
    || { cat "$LOG_DIR/tools-validate.log"; fail "tools validate output unexpected"; }
pass "tools validate OK"

step "audit stub creates engagement"
DEMO="$(mktemp -d)"
mkdir -p "$DEMO/data" "$DEMO/.symbiont/audit"
docker run --rm \
    -v "$DEMO/data:/opt/codered/data" \
    -v "$DEMO/.symbiont/audit:/opt/codered/.symbiont/audit" \
    -v "$DEMO:/audit:ro" \
    "$IMG" audit /audit > "$LOG_DIR/audit.log"
grep -q 'engagement_id:' "$LOG_DIR/audit.log" \
    || { cat "$LOG_DIR/audit.log"; fail "audit did not emit engagement_id"; }
test -s "$DEMO/data/codered.db" || fail "codered.db not created"
test -s "$DEMO/.symbiont/audit/audit.jsonl" || fail "audit.jsonl not written"
pass "audit stub OK"

step "tools repo_overview on python-flask-vuln fixture"
FIXTURE="$(pwd)/tests/fixtures/python-flask-vuln"
test -d "$FIXTURE" || fail "fixture not found at $FIXTURE"
docker run --rm \
    -v "$FIXTURE:/audit:ro" \
    "$IMG" tools repo-overview --dir /audit > "$LOG_DIR/repo-overview.log"
grep -q '"python"'  "$LOG_DIR/repo-overview.log" || { cat "$LOG_DIR/repo-overview.log"; fail "repo_overview missing python"; }
grep -q '"flask"'   "$LOG_DIR/repo-overview.log" || { cat "$LOG_DIR/repo-overview.log"; fail "repo_overview missing flask"; }
pass "tools repo_overview OK"

step "tools route_map on python-flask-vuln fixture"
docker run --rm \
    -v "$FIXTURE:/audit:ro" \
    "$IMG" tools route-map --dir /audit > "$LOG_DIR/route-map.log"
grep -q '"/users"'       "$LOG_DIR/route-map.log" || { cat "$LOG_DIR/route-map.log"; fail "route_map missing /users"; }
grep -q '"/dashboard"'   "$LOG_DIR/route-map.log" || { cat "$LOG_DIR/route-map.log"; fail "route_map missing /dashboard"; }
pass "tools route_map OK"

step "build python-scanner image"
docker build -f scanners/python/Dockerfile -t symbi-codered-scanner-python:dev scanners/python/ \
    > "$LOG_DIR/scanner-build.log" 2>&1 \
    || { tail -50 "$LOG_DIR/scanner-build.log"; fail "scanner build"; }
pass "scanner image built"

step "bandit smoke on python-flask-vuln fixture"
docker run --rm \
    -v "$FIXTURE:/repo:ro" \
    --entrypoint /usr/local/bin/scanner-runner \
    symbi-codered-scanner-python:dev \
    < <(echo '{"tool":"bandit","target_dir":"/repo"}') \
    > "$LOG_DIR/bandit.log" 2>&1
grep -q '"tool": "bandit"' "$LOG_DIR/bandit.log" \
    || { cat "$LOG_DIR/bandit.log"; fail "bandit smoke missing tool field"; }
pass "bandit smoke OK"

step "Plan D: codered hunt smoke (taint + pattern + chain)"
# Skips if ANTHROPIC_API_KEY is not set so CI without secrets still passes.
if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
    PLAN_D_DEMO="$(mktemp -d)"
    mkdir -p "$PLAN_D_DEMO/data" "$PLAN_D_DEMO/.symbiont/audit"
    docker run --rm \
        -v "$FIXTURE:/audit:ro" \
        -v "$PLAN_D_DEMO/data:/opt/codered/data" \
        -v "$PLAN_D_DEMO/.symbiont/audit:/opt/codered/.symbiont/audit" \
        -e "ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY" \
        "$IMG" hunt --engagement deadbeef-0000-0000-0000-000000000000 \
        > "$LOG_DIR/plan-d-hunt.log" 2>&1 || true
    if grep -q 'attack_chains:' "$LOG_DIR/plan-d-hunt.log"; then
        pass "Plan D hunt prints attack_chains:"
    else
        cat "$LOG_DIR/plan-d-hunt.log"
        fail "Plan D hunt did not print attack_chains:"
    fi
else
    pass "Plan D hunt smoke skipped (ANTHROPIC_API_KEY not set)"
fi

step "Plan E: build python-sandbox image"
docker build -f scanners/python-sandbox/Dockerfile -t symbi-codered-sandbox-python:dev scanners/python-sandbox/ \
    > "$LOG_DIR/sandbox-build.log" 2>&1 \
    || { tail -50 "$LOG_DIR/sandbox-build.log"; fail "sandbox build"; }
pass "sandbox image built"

step "Plan E: trivial reproducer smoke"
echo '{"script":"print(\"REPRODUCED\")","timeout_seconds":5}' | \
    docker run --rm -i --entrypoint /usr/local/bin/run-reproducer \
        symbi-codered-sandbox-python:dev \
    > "$LOG_DIR/sandbox-trivial.log" 2>&1 || true
if grep -q '"verdict": "reproduced"' "$LOG_DIR/sandbox-trivial.log"; then
    pass "sandbox trivial reproducer OK"
else
    cat "$LOG_DIR/sandbox-trivial.log"
    fail "sandbox trivial reproducer wrong verdict"
fi

# ---------------------------------------------------------------------------
# Plan F: rust / typescript / go scanner + sandbox sidecars.
#
# Six docker builds (rust-scanner + rust-sandbox each pull a >1GB rust
# toolchain) cumulatively take ~10-20 min on a cold cache, which is too
# slow for default CI runs. Gate behind SYMBI_BOOT_TEST_MULTILANG=1.
# ---------------------------------------------------------------------------

if [[ "${SYMBI_BOOT_TEST_MULTILANG:-0}" != "0" ]]; then
    RUST_FIXTURE="$(pwd)/tests/fixtures/rust-axum-vuln"
    TS_FIXTURE="$(pwd)/tests/fixtures/typescript-express-vuln"
    GO_FIXTURE="$(pwd)/tests/fixtures/go-net-http-vuln"
    JAVA_FIXTURE="$(pwd)/tests/fixtures/java-servlet-vuln"
    PHP_FIXTURE="$(pwd)/tests/fixtures/php-sqli-vuln"
    test -d "$RUST_FIXTURE" || fail "rust fixture missing at $RUST_FIXTURE"
    test -d "$TS_FIXTURE"   || fail "typescript fixture missing at $TS_FIXTURE"
    test -d "$GO_FIXTURE"   || fail "go fixture missing at $GO_FIXTURE"
    test -d "$JAVA_FIXTURE" || fail "java fixture missing at $JAVA_FIXTURE"
    test -d "$PHP_FIXTURE"  || fail "php fixture missing at $PHP_FIXTURE"

    # ---- rust-scanner --------------------------------------------------
    step "Plan F: build rust-scanner image"
    docker build -f scanners/rust/Dockerfile -t symbi-codered-scanner-rust:dev scanners/rust/ \
        > "$LOG_DIR/rust-scanner-build.log" 2>&1 \
        || { tail -50 "$LOG_DIR/rust-scanner-build.log"; fail "rust-scanner build"; }
    pass "rust-scanner image built"

    step "Plan F: clippy smoke on rust-axum-vuln fixture"
    docker run --rm -i \
        -v "$RUST_FIXTURE:/repo:ro" \
        --entrypoint /usr/local/bin/scanner-runner \
        symbi-codered-scanner-rust:dev \
        < <(echo '{"tool":"clippy","target_dir":"/repo"}') \
        > "$LOG_DIR/rust-clippy.log" 2>&1
    if grep -qE '"tool": "(clippy|cargo-clippy)"' "$LOG_DIR/rust-clippy.log"; then
        pass "rust-scanner clippy smoke OK"
    else
        cat "$LOG_DIR/rust-clippy.log"
        fail "rust-scanner clippy smoke missing tool field"
    fi

    # ---- typescript-scanner --------------------------------------------
    step "Plan F: build typescript-scanner image"
    docker build -f scanners/typescript/Dockerfile -t symbi-codered-scanner-typescript:dev scanners/typescript/ \
        > "$LOG_DIR/ts-scanner-build.log" 2>&1 \
        || { tail -50 "$LOG_DIR/ts-scanner-build.log"; fail "typescript-scanner build"; }
    pass "typescript-scanner image built"

    step "Plan F: eslint smoke on typescript-express-vuln fixture"
    docker run --rm -i \
        -v "$TS_FIXTURE:/repo:ro" \
        --entrypoint /usr/local/bin/scanner-runner \
        symbi-codered-scanner-typescript:dev \
        < <(echo '{"tool":"eslint","target_dir":"/repo"}') \
        > "$LOG_DIR/ts-eslint.log" 2>&1
    if grep -q '"tool": "eslint"' "$LOG_DIR/ts-eslint.log"; then
        pass "typescript-scanner eslint smoke OK"
    else
        cat "$LOG_DIR/ts-eslint.log"
        fail "typescript-scanner eslint smoke missing tool field"
    fi

    # ---- go-scanner ----------------------------------------------------
    step "Plan F: build go-scanner image"
    docker build -f scanners/go/Dockerfile -t symbi-codered-scanner-go:dev scanners/go/ \
        > "$LOG_DIR/go-scanner-build.log" 2>&1 \
        || { tail -50 "$LOG_DIR/go-scanner-build.log"; fail "go-scanner build"; }
    pass "go-scanner image built"

    step "Plan F: gosec smoke on go-net-http-vuln fixture"
    docker run --rm -i \
        -v "$GO_FIXTURE:/repo:ro" \
        --entrypoint /usr/local/bin/scanner-runner \
        symbi-codered-scanner-go:dev \
        < <(echo '{"tool":"gosec","target_dir":"/repo"}') \
        > "$LOG_DIR/go-gosec.log" 2>&1
    if grep -q '"tool": "gosec"' "$LOG_DIR/go-gosec.log"; then
        pass "go-scanner gosec smoke OK"
    else
        cat "$LOG_DIR/go-gosec.log"
        fail "go-scanner gosec smoke missing tool field"
    fi

    # ---- java-scanner --------------------------------------------------
    step "Plan F: build java-scanner image"
    docker build -f scanners/java/Dockerfile -t symbi-codered-scanner-java:dev scanners/java/ \
        > "$LOG_DIR/java-scanner-build.log" 2>&1 \
        || { tail -50 "$LOG_DIR/java-scanner-build.log"; fail "java-scanner build"; }
    pass "java-scanner image built"

    step "Plan F: semgrep smoke on java-servlet-vuln fixture"
    docker run --rm -i \
        -v "$JAVA_FIXTURE:/repo:ro" \
        --entrypoint /usr/local/bin/scanner-runner \
        symbi-codered-scanner-java:dev \
        < <(echo '{"tool":"semgrep","target_dir":"/repo"}') \
        > "$LOG_DIR/java-semgrep.log" 2>&1
    if grep -q '"tool": "semgrep"' "$LOG_DIR/java-semgrep.log"; then
        pass "java-scanner semgrep smoke OK"
    else
        cat "$LOG_DIR/java-semgrep.log"
        fail "java-scanner semgrep smoke missing tool field"
    fi

    # ---- php-scanner ---------------------------------------------------
    step "Plan F: build php-scanner image"
    docker build -f scanners/php/Dockerfile -t symbi-codered-scanner-php:dev scanners/php/ \
        > "$LOG_DIR/php-scanner-build.log" 2>&1 \
        || { tail -50 "$LOG_DIR/php-scanner-build.log"; fail "php-scanner build"; }
    pass "php-scanner image built"

    step "Plan F: semgrep smoke on php-sqli-vuln fixture"
    docker run --rm -i \
        -v "$PHP_FIXTURE:/repo:ro" \
        --entrypoint /usr/local/bin/scanner-runner \
        symbi-codered-scanner-php:dev \
        < <(echo '{"tool":"semgrep","target_dir":"/repo"}') \
        > "$LOG_DIR/php-semgrep.log" 2>&1
    if grep -q '"tool": "semgrep"' "$LOG_DIR/php-semgrep.log"; then
        pass "php-scanner semgrep smoke OK"
    else
        cat "$LOG_DIR/php-semgrep.log"
        fail "php-scanner semgrep smoke missing tool field"
    fi

    step "Plan F: progpilot smoke on php-sqli-vuln fixture"
    docker run --rm -i \
        -v "$PHP_FIXTURE:/repo:ro" \
        --entrypoint /usr/local/bin/scanner-runner \
        symbi-codered-scanner-php:dev \
        < <(echo '{"tool":"progpilot","target_dir":"/repo"}') \
        > "$LOG_DIR/php-progpilot.log" 2>&1
    if grep -q 'sql_injection' "$LOG_DIR/php-progpilot.log" || grep -q 'mysqli_query' "$LOG_DIR/php-progpilot.log"; then
        pass "php-scanner progpilot smoke OK"
    else
        cat "$LOG_DIR/php-progpilot.log"
        fail "php-scanner progpilot smoke found no vuln"
    fi

    # ---- rust-sandbox --------------------------------------------------
    step "Plan F: build rust-sandbox image"
    docker build -f scanners/rust-sandbox/Dockerfile -t symbi-codered-sandbox-rust:dev scanners/rust-sandbox/ \
        > "$LOG_DIR/rust-sandbox-build.log" 2>&1 \
        || { tail -50 "$LOG_DIR/rust-sandbox-build.log"; fail "rust-sandbox build"; }
    pass "rust-sandbox image built"

    step "Plan F: rust-sandbox trivial reproducer smoke"
    echo '{"script":"fn main(){println!(\"REPRODUCED\");}","timeout_seconds":10}' | \
        docker run --rm -i --entrypoint /usr/local/bin/run-reproducer \
            symbi-codered-sandbox-rust:dev \
        > "$LOG_DIR/rust-sandbox-trivial.log" 2>&1 || true
    if grep -q '"verdict": "reproduced"' "$LOG_DIR/rust-sandbox-trivial.log"; then
        pass "rust-sandbox trivial reproducer OK"
    else
        cat "$LOG_DIR/rust-sandbox-trivial.log"
        fail "rust-sandbox trivial reproducer wrong verdict"
    fi

    # ---- typescript-sandbox --------------------------------------------
    step "Plan F: build typescript-sandbox image"
    docker build -f scanners/typescript-sandbox/Dockerfile -t symbi-codered-sandbox-typescript:dev scanners/typescript-sandbox/ \
        > "$LOG_DIR/ts-sandbox-build.log" 2>&1 \
        || { tail -50 "$LOG_DIR/ts-sandbox-build.log"; fail "typescript-sandbox build"; }
    pass "typescript-sandbox image built"

    step "Plan F: typescript-sandbox trivial reproducer smoke"
    echo '{"script":"console.log(\"REPRODUCED\");","timeout_seconds":10}' | \
        docker run --rm -i --entrypoint /usr/local/bin/run-reproducer \
            symbi-codered-sandbox-typescript:dev \
        > "$LOG_DIR/ts-sandbox-trivial.log" 2>&1 || true
    if grep -q '"verdict": "reproduced"' "$LOG_DIR/ts-sandbox-trivial.log"; then
        pass "typescript-sandbox trivial reproducer OK"
    else
        cat "$LOG_DIR/ts-sandbox-trivial.log"
        fail "typescript-sandbox trivial reproducer wrong verdict"
    fi

    # ---- go-sandbox ----------------------------------------------------
    step "Plan F: build go-sandbox image"
    docker build -f scanners/go-sandbox/Dockerfile -t symbi-codered-sandbox-go:dev scanners/go-sandbox/ \
        > "$LOG_DIR/go-sandbox-build.log" 2>&1 \
        || { tail -50 "$LOG_DIR/go-sandbox-build.log"; fail "go-sandbox build"; }
    pass "go-sandbox image built"

    step "Plan F: go-sandbox trivial reproducer smoke"
    echo '{"script":"package main; import \"fmt\"; func main(){fmt.Println(\"REPRODUCED\")}","timeout_seconds":10}' | \
        docker run --rm -i --entrypoint /usr/local/bin/run-reproducer \
            symbi-codered-sandbox-go:dev \
        > "$LOG_DIR/go-sandbox-trivial.log" 2>&1 || true
    if grep -q '"verdict": "reproduced"' "$LOG_DIR/go-sandbox-trivial.log"; then
        pass "go-sandbox trivial reproducer OK"
    else
        cat "$LOG_DIR/go-sandbox-trivial.log"
        fail "go-sandbox trivial reproducer wrong verdict"
    fi
else
    pass "Plan F multilang sidecar build skipped (set SYMBI_BOOT_TEST_MULTILANG=1)"
fi

step "Plan G: codered report --help"
docker run --rm "$IMG" report --help > "$LOG_DIR/report-help.log" 2>&1
grep -q 'engagement' "$LOG_DIR/report-help.log" \
    || { cat "$LOG_DIR/report-help.log"; fail "report --help missing engagement flag"; }
pass "codered report --help OK"

printf '\n[OK] all orchestrator boot checks passed\n'
