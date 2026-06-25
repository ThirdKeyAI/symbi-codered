#!/usr/bin/env python3
"""Plan F Java scanner sidecar runner.

Reads a JSON request from stdin:
  {"tool": "semgrep" | "compromised_packages",
   "target_dir": "/repo",
   "extra_args": []}

Runs the requested scanner over `target_dir` and prints a JSON response
to stdout:
  {"tool": str, "ok": bool, "exit_code": int, "cmd": str,
   "stdout": str, "stderr": str, "raw_json": object|null}

Java SAST is source-based via semgrep's java ruleset — no JVM or compiled
bytecode is required, so the sidecar stays a lightweight python image.
(find-sec-bugs/spotbugs need compiled classes and are intentionally out of
scope here.)
"""
import json
import os
import shlex
import subprocess
import sys


def run_semgrep(target_dir: str, extra: list) -> dict:
    # `--config auto` would hit the Semgrep registry, but the sidecar runs
    # network_mode: none. Use the offline ruleset baked at
    # /opt/semgrep-rules. The Dockerfile pre-deletes the noise rule-dirs
    # (correctness/maintainability/best-practice/style/performance) across
    # all language subtrees, so we point at the java root and still get the
    # framework-specific security rules (java/spring, java/jdbc, java/jwt,
    # java/servlets, java/xml, ...).
    config = "/opt/semgrep-rules/java"
    if not os.path.isdir(config):
        config = "/opt/semgrep-rules"
    cmd = ["semgrep", "scan", "--config", config,
           "--json", "--quiet", "--timeout", "120",
           "--metrics", "off",
           target_dir, *extra]
    return _run(cmd, parse_stdout_json=True, success_exit_codes=(0, 1))


def run_compromised_packages(target_dir: str, extra: list) -> dict:
    # jaschadub/compromised-packages-check is baked into the image at
    # /opt/compromised-packages-check/. The orchestrator can `docker cp` a
    # fresher copy in before each hunt to pick up the upstream 4×/day list
    # without breaking the sidecar's network_mode: none guarantee.
    # Exit codes: 0 clean, 1 hit(s), 2 error. We treat both 0 and 1 as
    # success; the parser handles empty stdout gracefully.
    script = "/opt/compromised-packages-check/check_compromised_packages.py"
    cmd = ["python3", script, target_dir, *extra]
    return _run(cmd, parse_stdout_json=False, success_exit_codes=(0, 1))


def _run(cmd, parse_stdout_json: bool = False, success_exit_codes=(0,)) -> dict:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    ok = proc.returncode in success_exit_codes
    raw_json = None
    if parse_stdout_json and proc.stdout:
        try:
            raw_json = json.loads(proc.stdout)
        except json.JSONDecodeError:
            raw_json = None
    return {
        "tool": cmd[0],
        "ok": ok,
        "exit_code": proc.returncode,
        "cmd": " ".join(shlex.quote(c) for c in cmd),
        "stdout": proc.stdout[:8192],
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
