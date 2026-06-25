#!/usr/bin/env python3
"""Plan F TypeScript scanner sidecar runner.

Reads a JSON request from stdin:
  {"tool": "eslint" | "npm_audit" | "semgrep",
   "target_dir": "/repo",
   "extra_args": []}

Runs the requested scanner over `target_dir` and prints a JSON response
to stdout:
  {"tool": str, "ok": bool, "exit_code": int, "cmd": str,
   "stdout": str, "stderr": str, "raw_json": object|null}
"""
import json
import os
import re
import shlex
import subprocess
import sys


# --- Lit-aware jQuery false-positive suppression --------------------------
#
# semgrep's javascript/jquery ruleset (check_ids containing ".jquery.") flags
# jQuery's unsafe DOM sinks — `.html()`, `.append()`, etc. Lit / lit-html
# exposes an `html` tagged-template literal whose interpolations are
# auto-escaped, so a Lit component that writes `html\`...${x}...\`` is NOT a
# jQuery XSS sink. semgrep cannot tell the two `html` symbols apart and fires
# the jQuery rule on every Lit template — observed as 71/88 findings on the
# symbiont a2ui panels. We drop jQuery-ruleset findings for files that import
# Lit and do not import jQuery.
_JQUERY_RULE_MARKER = ".jquery."

_LIT_IMPORT_RE = re.compile(
    r"""(?mx)
        ^\s*import\b [^;\n]* \bfrom\s* ['"] lit (?: -html | -element | /[^'"]* )? ['"]
      | ^\s*import\s* ['"] lit (?: -html | /[^'"]* )? ['"]
    """
)
_JQUERY_IMPORT_RE = re.compile(
    r"""(?mx)
        \bfrom\s* ['"] jquery ['"]
      | \brequire\(\s* ['"] jquery ['"] \s*\)
      | \bimport\s* ['"] jquery ['"]
    """
)


def _imports_lit_not_jquery(source: str) -> bool:
    """True when the source uses Lit/lit-html and does not import jQuery."""
    return bool(_LIT_IMPORT_RE.search(source)) and not _JQUERY_IMPORT_RE.search(source)


def suppress_lit_jquery_fps(raw_json, read_source):
    """Drop jQuery-ruleset semgrep results for Lit files.

    `read_source(path) -> str` reads a result's source file (injectable for
    tests). Returns (possibly-new raw_json, suppressed_count). The original
    object is left untouched; suppressed count is recorded under
    `codered_suppressed.lit_jquery_false_positives` for the evidence envelope.
    """
    if not isinstance(raw_json, dict):
        return raw_json, 0
    results = raw_json.get("results")
    if not isinstance(results, list):
        return raw_json, 0

    source_cache: dict = {}
    kept = []
    suppressed = 0
    for r in results:
        check_id = r.get("check_id") or ""
        path = r.get("path") or ""
        if _JQUERY_RULE_MARKER in check_id and path:
            if path not in source_cache:
                try:
                    source_cache[path] = read_source(path)
                except OSError:
                    source_cache[path] = ""
            if _imports_lit_not_jquery(source_cache[path]):
                suppressed += 1
                continue
        kept.append(r)

    if not suppressed:
        return raw_json, 0
    new = dict(raw_json)
    new["results"] = kept
    new.setdefault("codered_suppressed", {})["lit_jquery_false_positives"] = suppressed
    return new, suppressed


def run_eslint(target_dir: str, extra: list) -> dict:
    # eslint exits 1 when it found lint problems (our success case) and 2 on
    # config/IO errors. --no-eslintrc forces our bundled config instead of any
    # in-tree .eslintrc / eslint.config.js that might fail to load.
    cmd = ["eslint",
           "--no-eslintrc",
           "--config", "/usr/local/etc/eslintrc.json",
           "--format", "json",
           "--ext", ".js,.jsx,.ts,.tsx,.mjs,.cjs",
           target_dir, *extra]
    return _run(cmd, parse_stdout_json=True, success_exit_codes=(0, 1))


def run_npm_audit(target_dir: str, extra: list) -> dict:
    # npm audit needs a package.json in the cwd; bail early with an empty
    # envelope if the repo doesn't have one (e.g. a TS lib with no published
    # manifest). Exit 1 means "vulnerabilities found" — that's still success.
    if not os.path.isfile(os.path.join(target_dir, "package.json")):
        return {
            "tool": "npm-audit",
            "ok": False,
            "exit_code": 0,
            "cmd": "npm audit --json",
            "stdout": "",
            "stderr": "no package.json",
            "raw_json": None,
        }
    cmd = ["npm", "audit", "--json", *extra]
    return _run(cmd, parse_stdout_json=True, success_exit_codes=(0, 1),
                cwd=target_dir)


def run_semgrep(target_dir: str, extra: list) -> dict:
    # Dockerfile pre-deletes noise rule-dirs across all languages at build.
    # For TS we want BOTH the typescript-specific tree AND the javascript
    # tree — most JS security rules apply unchanged to TS, and the TS
    # subtree alone is tiny. Pass each as its own --config; semgrep merges
    # them. Both are best-effort: missing dirs fall through to /opt/semgrep-rules.
    configs = []
    for candidate in (
        "/opt/semgrep-rules/typescript",
        "/opt/semgrep-rules/javascript",
    ):
        if os.path.isdir(candidate):
            configs.append(candidate)
    if not configs:
        configs.append("/opt/semgrep-rules")
    cmd = ["semgrep", "scan"]
    for c in configs:
        cmd.extend(["--config", c])
    cmd.extend(["--json", "--quiet", "--timeout", "120",
                "--metrics", "off",
                target_dir, *extra])
    result = _run(cmd, parse_stdout_json=True, success_exit_codes=(0, 1))

    # Lit-aware suppression of jQuery-ruleset false positives. static_hunter
    # parses findings from raw_json, so filtering it here drops the FPs at the
    # source while keeping the count auditable in the evidence envelope.
    raw_json = result.get("raw_json")
    if isinstance(raw_json, dict):
        def _read(path: str) -> str:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        filtered, suppressed = suppress_lit_jquery_fps(raw_json, _read)
        if suppressed:
            result["raw_json"] = filtered
            result["stdout"] = json.dumps(filtered)
    return result


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
        "tool": _tool_label(cmd),
        "ok": ok,
        "exit_code": proc.returncode,
        "cmd": " ".join(shlex.quote(c) for c in cmd),
        "stdout": proc.stdout[:65536],
        "stderr": proc.stderr[:8192],
        "raw_json": raw_json,
    }


def _tool_label(cmd: list) -> str:
    head = cmd[0]
    if head == "npm" and len(cmd) > 1:
        return f"npm-{cmd[1]}"
    return head


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
        "eslint": run_eslint,
        "npm_audit": run_npm_audit,
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
