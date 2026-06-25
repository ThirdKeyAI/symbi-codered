#!/usr/bin/env python3
"""Plan H IaC scanner sidecar runner.

Reads a JSON request from stdin:
  {"tool": "checkov" | "tfsec" | "trivy",
   "target_dir": "/repo",
   "extra_args": []}

Runs the requested scanner over `target_dir` and prints a JSON response
to stdout:
  {"tool": str, "ok": bool, "exit_code": int, "cmd": str,
   "stdout": str, "stderr": str, "raw_json": object|null}
"""
import json
import shlex
import subprocess
import sys


def run_checkov(target_dir: str, extra: list) -> dict:
    # checkov walks the directory and detects all supported frameworks
    # (Terraform, CloudFormation, Kubernetes, Helm, Dockerfile,
    # Serverless, ARM, GitHub Actions, Argo) automatically. -o json emits
    # a single document. Exit 0 = clean, 1 = findings (still success
    # here), 2 = error.
    cmd = ["checkov", "-d", target_dir, "-o", "json",
           "--quiet", "--soft-fail", *extra]
    return _run(cmd, parse_stdout_json=True, success_exit_codes=(0, 1))


def run_tfsec(target_dir: str, extra: list) -> dict:
    # tfsec is Terraform-only — we still run it on the repo root; tfsec
    # walks looking for .tf files and exits 0 if none are found.
    # --format json emits a single doc. Exit 1 = findings, treat as ok.
    cmd = ["tfsec", "--format", "json", "--soft-fail", *extra, target_dir]
    return _run(cmd, parse_stdout_json=True, success_exit_codes=(0, 1))


def run_trivy(target_dir: str, extra: list) -> dict:
    # trivy fs scans filesystem-mode (IaC files + secrets + vulns).
    # --skip-db-update so we don't try to fetch at scan time. Exit codes:
    # 0 ok, 1+ findings or error — we widen to (0, 1) for "findings".
    cmd = ["trivy", "fs",
           "--format", "json",
           "--skip-db-update",
           "--skip-java-db-update",
           "--scanners", "vuln,misconfig,secret",
           "--quiet",
           *extra,
           target_dir]
    return _run(cmd, parse_stdout_json=True, success_exit_codes=(0, 1))


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
        "stdout": proc.stdout[:131072],
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
        "checkov": run_checkov,
        "tfsec": run_tfsec,
        "trivy": run_trivy,
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
