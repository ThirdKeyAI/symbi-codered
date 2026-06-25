#!/usr/bin/env python3
"""Plan F Rust scanner sidecar runner.

Reads a JSON request from stdin:
  {"tool": "cargo_audit" | "clippy" | "semgrep",
   "target_dir": "/repo",
   "extra_args": []}

Runs the requested scanner over `target_dir` and prints a JSON response
to stdout:
  {"tool": str, "ok": bool, "exit_code": int, "cmd": str,
   "stdout": str, "stderr": str, "raw_json": object|null}
"""
import json
import os
import shlex
import subprocess
import sys


def run_cargo_audit(target_dir: str, extra: list) -> dict:
    # cargo-audit reads ./Cargo.lock from the cwd; target_dir is the repo
    # root that contains Cargo.toml/Cargo.lock.
    cmd = ["cargo", "audit", "--json", *extra]
    return _run(cmd, parse_stdout_json=True, success_exit_codes=(0, 1),
                cwd=target_dir)


def run_clippy(target_dir: str, extra: list) -> dict:
    manifest = f"{target_dir}/Cargo.toml"
    cmd = ["cargo", "clippy",
           "--message-format=json",
           "--manifest-path", manifest,
           "--",
           "-W", "clippy::suspicious",
           "-W", "clippy::unwrap_used",
           "-W", "clippy::indexing_slicing",
           *extra]
    # clippy emits NDJSON (one JSON object per line). Don't try to parse
    # stdout as a single document; downstream parser handles line splitting.
    return _run(cmd, parse_stdout_json=False, success_exit_codes=(0, 1, 101))


def run_semgrep(target_dir: str, extra: list) -> dict:
    # Dockerfile pre-deletes noise rule-dirs (correctness/maintainability/
    # best-practice/style/performance) across all languages at build, so
    # we can point at /opt/semgrep-rules/rust without pulling in dilutive
    # rules while keeping framework-specific security.
    for candidate in (
        "/opt/semgrep-rules/rust",
        "/opt/semgrep-rules",
    ):
        if os.path.isdir(candidate):
            rules_root = candidate
            break
    else:
        rules_root = "/opt/semgrep-rules"
    cmd = ["semgrep", "scan", "--config", rules_root,
           "--json", "--quiet", "--timeout", "120",
           "--metrics", "off",
           target_dir, *extra]
    return _run(cmd, parse_stdout_json=True, success_exit_codes=(0, 1))


def run_compromised_packages(target_dir: str, extra: list) -> dict:
    # See scanners/python/scanner-runner.py for the freshness contract.
    script = "/opt/compromised-packages-check/check_compromised_packages.py"
    cmd = ["python3", script, target_dir, *extra]
    return _run(cmd, parse_stdout_json=False, success_exit_codes=(0, 1))


def _run(cmd, parse_stdout_json: bool = False, success_exit_codes=(0,),
         cwd: str | None = None) -> dict:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False,
                          cwd=cwd)
    ok = proc.returncode in success_exit_codes
    raw_json = None
    if parse_stdout_json and proc.stdout:
        try:
            raw_json = json.loads(proc.stdout)
        except json.JSONDecodeError:
            raw_json = None
    return {
        "tool": cmd[0] if cmd[0] != "cargo" else f"cargo-{cmd[1]}",
        "ok": ok,
        "exit_code": proc.returncode,
        "cmd": " ".join(shlex.quote(c) for c in cmd),
        "stdout": proc.stdout[:65536],
        "stderr": proc.stderr[:8192],
        "raw_json": raw_json,
    }


def main() -> int:
    try:
        req = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(json.dumps({"ok": False, "error": f"bad request json: {e}"}))
        return 2

    tool = req.get("tool", "")
    target = req.get("target_dir", "/repo")
    extra = req.get("extra_args", []) or []

    dispatch = {
        "cargo_audit": run_cargo_audit,
        "clippy": run_clippy,
        "semgrep": run_semgrep,
        "compromised_packages": run_compromised_packages,
    }
    runner = dispatch.get(tool)
    if not runner:
        print(json.dumps({"ok": False, "error": f"unknown tool: {tool}"}))
        return 2

    result = runner(target, extra)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
