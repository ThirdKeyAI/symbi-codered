#!/usr/bin/env python3
"""Plan F poc_forge typescript-sandbox runner.

Reads JSON request from stdin: {"script": "<ts/js source>", "timeout_seconds": 30}
By default writes /tmp/repro.ts and runs `npx tsx /tmp/repro.ts`.
If the script's first line is `// @lang js`, writes /tmp/repro.js and runs `node /tmp/repro.js`.
Returns JSON: {"ok", "exit_code", "stdout", "stderr", "timed_out", "verdict"}.
verdict in {"reproduced","refuted","unknown"} per stdout string match.
"""
import json
import subprocess
import sys

DEFAULT_TIMEOUT = 30

def main() -> int:
    try:
        req = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(json.dumps({"ok": False, "error": f"bad request json: {e}"}))
        return 2
    script = req.get("script", "")
    if not script:
        print(json.dumps({"ok": False, "error": "script required"}))
        return 2
    timeout = int(req.get("timeout_seconds", DEFAULT_TIMEOUT))

    first_line = script.splitlines()[0] if script else ""
    is_js = first_line.strip().startswith("// @lang js")

    if is_js:
        path = "/tmp/repro.js"
        cmd = ["node", path]
    else:
        path = "/tmp/repro.ts"
        cmd = ["npx", "--prefix", "/tmp", "tsx", path]

    with open(path, "w") as f:
        f.write(script)

    timed_out = False
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=timeout,
            check=False,
            cwd="/tmp",
        )
        out = proc.stdout[:8192]
        err = proc.stderr[:8192]
        rc = proc.returncode
    except subprocess.TimeoutExpired as e:
        timed_out = True
        out = (e.stdout or b"").decode("utf-8", errors="replace")[:8192]
        err = (e.stderr or b"").decode("utf-8", errors="replace")[:8192]
        rc = -1

    if "REPRODUCED" in out:
        verdict = "reproduced"
    elif "REFUTED" in out:
        verdict = "refuted"
    else:
        verdict = "unknown"

    print(json.dumps({
        "ok": not timed_out and rc == 0,
        "exit_code": rc,
        "stdout": out,
        "stderr": err,
        "timed_out": timed_out,
        "verdict": verdict,
    }))
    return 0

if __name__ == "__main__":
    sys.exit(main())
