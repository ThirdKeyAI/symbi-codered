#!/usr/bin/env python3
"""Plan E poc_forge sandbox runner.

Reads JSON request from stdin: {"script": "<python source>", "timeout_seconds": 30}
Writes /tmp/repro.py and runs `python3 /tmp/repro.py` with the timeout.
Returns JSON: {"ok", "exit_code", "stdout", "stderr", "timed_out", "verdict"}.
verdict ∈ {"reproduced","refuted","unknown"} per stdout string match.
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

    with open("/tmp/repro.py", "w") as f:
        f.write(script)

    timed_out = False
    try:
        proc = subprocess.run(
            ["python3", "/tmp/repro.py"],
            capture_output=True, text=True,
            timeout=timeout,
            check=False,
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
