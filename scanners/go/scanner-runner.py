#!/usr/bin/env python3
"""Plan F Go scanner sidecar runner.

Reads a JSON request from stdin:
  {"tool": "gosec" | "govulncheck" | "staticcheck",
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


def run_gosec(target_dir: str, extra: list) -> dict:
    # gosec -fmt=json emits a single JSON document on stdout. Exit 1 means
    # "findings present" — still a success. ./... walks the module rooted
    # at target_dir; we cd in so module resolution honours the local go.mod.
    cmd = ["gosec", "-fmt=json", "-quiet", *extra, "./..."]
    return _run(cmd, parse_stdout_json=True, success_exit_codes=(0, 1),
                cwd=target_dir)


def run_govulncheck(target_dir: str, extra: list) -> dict:
    # govulncheck requires a Go module to analyze. Bail early with an empty
    # envelope if the repo lacks a go.mod (e.g. a polyglot repo where Go
    # files exist but aren't an actual module). Otherwise emit NDJSON via
    # -json; pass through raw stdout, the downstream parser splits lines.
    # Exit 3 = vulnerabilities found (still success in our pipeline).
    if not os.path.isfile(os.path.join(target_dir, "go.mod")):
        return {
            "tool": "govulncheck",
            "ok": False,
            "exit_code": 0,
            "cmd": "govulncheck -json ./...",
            "stdout": "",
            "stderr": "no go.mod in target",
            "raw_json": None,
        }
    cmd = ["govulncheck", "-json", *extra, "./..."]
    return _run(cmd, parse_stdout_json=False, success_exit_codes=(0, 1, 3),
                cwd=target_dir)


def run_staticcheck(target_dir: str, extra: list) -> dict:
    # staticcheck -f json emits NDJSON. Exit 1 means "diagnostics present".
    cmd = ["staticcheck", "-f", "json", *extra, "./..."]
    return _run(cmd, parse_stdout_json=False, success_exit_codes=(0, 1),
                cwd=target_dir)


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
        "tool": cmd[0],
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
        "gosec": run_gosec,
        "govulncheck": run_govulncheck,
        "staticcheck": run_staticcheck,
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
