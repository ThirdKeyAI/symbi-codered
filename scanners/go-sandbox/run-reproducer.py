#!/usr/bin/env python3
"""Plan F poc_forge go-sandbox runner.

Reads JSON request from stdin: {"script": "<go source>", "timeout_seconds": 30}
Writes /sandbox/main.go and runs `go run main.go` there. The module root is
/sandbox (with pre-seeded deps), NOT /tmp — Go refuses to honor a go.mod under
the system temp root, which would break dependency resolution.
Returns JSON: {"ok", "exit_code", "stdout", "stderr", "timed_out", "verdict"}.
verdict in {"reproduced","refuted","unknown"} per stdout string match.
"""
import json
import subprocess
import sys

DEFAULT_TIMEOUT = 30
MODULE_DIR = "/sandbox"

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

    with open(f"{MODULE_DIR}/main.go", "w") as f:
        f.write(script)

    timed_out = False
    try:
        proc = subprocess.run(
            ["go", "run", "main.go"],
            capture_output=True, text=True,
            timeout=timeout,
            check=False,
            cwd=MODULE_DIR,
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
