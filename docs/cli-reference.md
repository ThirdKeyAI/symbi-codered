# CLI Reference

The `codered` binary drives the whole pipeline. Run `codered --help` or `codered <cmd> --help` for the authoritative flag list.

```
codered <command> [options]
```

## Commands

| Command | What it does |
|---------|-------------|
| `carto` | Run the cartographer pure-fact phase — tree-sitter facts, symbols, routes, `dataflow_edges`, code-chunk index. Prints the new `engagement_id`. |
| `specifier` | Pin and sign the engagement's threat model (sources, sinks, scope) with the per-engagement Ed25519 key. |
| `hunt` | Run the hunt: scanners → taint → `pattern_scout` → `chain_builder` → `poc_forge` → `devils_advocate` → `reflector`. |
| `advocate` | Re-run only the `devils_advocate` stage against an existing engagement. |
| `report` | Generate the engagement report — SARIF, Markdown, and the Ed25519-signed `engagement-seed.json`. |
| `export-grc` | Push a signed engagement seed to a GRC platform (gapps / comp) as mapped risks. |
| `audit` | Run an audit (Plan A stub). |
| `tools` | ToolClad manifest utilities. |

## Typical run

```bash
codered carto /path/to/target/repo          # capture <eid> from stdout
codered specifier --engagement <eid> --target /path/to/target/repo
codered hunt --engagement <eid>
codered report --engagement <eid>
```

## Useful flags

### `hunt`

The independent devil's-advocate flags break the confirmation-bias loop by pointing the rebuttal at a non-mirroring model:

```bash
codered hunt --engagement <eid> \
  --advocate-provider openrouter \
  --advocate-model openai/gpt-4.1 \
  --advocate-fallback minimax/minimax-m2
```

A startup warning fires if the advocate ends up mirroring the generation tier.

The PHP sandbox container is selectable with `--php-sandbox-container` (default `symbi-codered-sandbox-php`).

### `specifier`

`--target` is an explicit scan-target override. Normally `hunt` derives its target from the engagement's signed threat model so it can't drift onto the wrong tree.

---

A read-only web viewer (`serve`) ships only in the enterprise build and is not part of the Apache-2.0 core.
