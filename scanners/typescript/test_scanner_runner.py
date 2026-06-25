#!/usr/bin/env python3
"""Tests for the TS scanner-runner's Lit-aware jQuery FP suppression.

Run: python3 scanners/typescript/test_scanner_runner.py
"""
import importlib.util
import os
import tempfile

_spec = importlib.util.spec_from_file_location(
    "runner", os.path.join(os.path.dirname(__file__), "scanner-runner.py")
)
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)


def _mk(text: str) -> str:
    fh = tempfile.NamedTemporaryFile("w", suffix=".ts", delete=False)
    fh.write(text)
    fh.close()
    return fh.name


def test_suppresses_jquery_rule_on_lit_file():
    lit = _mk("import { LitElement, html, css } from 'lit';\n"
              "render(){ return html`<div>${this.x}</div>`; }\n")
    raw = {"results": [{
        "check_id": "opt.semgrep-rules.javascript.jquery.security.audit.prohibit-jquery-html",
        "path": lit, "start": {"line": 2},
    }]}
    out, n = runner.suppress_lit_jquery_fps(raw, lambda p: open(p).read())
    assert n == 1, n
    assert out["results"] == []
    assert out["codered_suppressed"]["lit_jquery_false_positives"] == 1
    os.unlink(lit)


def test_keeps_genuine_jquery():
    jq = _mk("import $ from 'jquery';\n$('#x').html(userInput);\n")
    raw = {"results": [{
        "check_id": "opt.semgrep-rules.javascript.jquery.security.audit.prohibit-jquery-html",
        "path": jq, "start": {"line": 2},
    }]}
    out, n = runner.suppress_lit_jquery_fps(raw, lambda p: open(p).read())
    assert n == 0, n
    assert len(out["results"]) == 1
    os.unlink(jq)


def test_keeps_non_lit_file_conservatively():
    plain = _mk("const html = (s)=>s;\nel.html(x);\n")
    raw = {"results": [{
        "check_id": "opt.semgrep-rules.javascript.jquery.security.audit.prohibit-jquery-html",
        "path": plain, "start": {"line": 2},
    }]}
    out, n = runner.suppress_lit_jquery_fps(raw, lambda p: open(p).read())
    assert n == 0, n
    os.unlink(plain)


def test_keeps_non_jquery_rule_on_lit_file():
    lit = _mk("import { html } from 'lit';\n")
    raw = {"results": [{
        "check_id": "opt.semgrep-rules.typescript.lang.security.audit.something",
        "path": lit, "start": {"line": 1},
    }]}
    out, n = runner.suppress_lit_jquery_fps(raw, lambda p: open(p).read())
    assert n == 0, n
    assert len(out["results"]) == 1
    os.unlink(lit)


def test_lit_importing_jquery_is_not_suppressed():
    mixed = _mk("import { html } from 'lit';\nimport $ from 'jquery';\n")
    raw = {"results": [{
        "check_id": "opt.semgrep-rules.javascript.jquery.security.audit.prohibit-jquery-html",
        "path": mixed, "start": {"line": 2},
    }]}
    out, n = runner.suppress_lit_jquery_fps(raw, lambda p: open(p).read())
    assert n == 0, n
    os.unlink(mixed)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
