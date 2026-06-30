# Contributing

## Build + test

```bash
cargo build  -j2 --workspace
cargo test   -j2 --workspace
cargo clippy -j2 --workspace --all-targets -- -D warnings
```

## Boot tests

```bash
# Builds + smokes the orchestrator + python sidecars:
./tests/boot_test.sh

# With all multi-language sidecar builds (slow, ~20 min):
SYMBI_BOOT_TEST_MULTILANG=1 ./tests/boot_test.sh
```

## Live end-to-end

Requires an LLM API key and running sidecars:

```bash
cargo test -j2 -p symbi-codered-cli --test plan_g_e2e -- --ignored
```

## Extending codered

- [Adding a new scanner](language-coverage.md#adding-a-new-scanner)
- [Adding a new language](language-coverage.md#adding-a-new-language)

## Reporting security issues

See [SECURITY.md](https://github.com/ThirdKeyAI/symbi-codered/blob/main/SECURITY.md) for the coordinated-disclosure process. Please do not open public issues for vulnerabilities.

## Code of conduct

This project follows the [Contributor Covenant](https://github.com/ThirdKeyAI/symbi-codered/blob/main/CODE_OF_CONDUCT.md).
