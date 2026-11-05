"""SECURITY tests: the properties that must hold because this tool handles live credentials.

A pentesting tool renders attacker-influenced data (target responses) and holds session tokens,
cracked secrets and private keys. These tests pin the defences that keep that safe. See
tests/TEST-PLAN.md (SEC-*).
"""

import inspect
from pathlib import Path

import pytest
import requests

from jwtpen.core import checker
from jwtpen.report.html import _inline_code, render_report
from jwtpen.attacks.base import Finding, HIGH, VULNERABLE

from conftest import hs256_token, raw_request_with, secure

PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_JS = PROJECT_ROOT / "jwtpen" / "webapp" / "static" / "app.js"

XSS = '<script>alert("xss")</script>'
IMG_XSS = '<img src=x onerror=alert(1)>'


# --- SEC-01..04: the report must never execute data it renders ------------------------------
def test_report_escapes_html_from_a_target_response():
    """Response bodies land in the report; a hostile target must not get script execution."""
    finding = Finding(
        attack="Test", status=VULNERABLE, severity=HIGH,
        summary=f"Target returned {XSS}",
        evidence={"Body": IMG_XSS}, methodology=[XSS], reproduction=[IMG_XSS],
    )
    html = render_report([finding], target="target.test")

    assert XSS not in html
    assert IMG_XSS not in html
    assert "&lt;script&gt;" in html or "&lt;img" in html


def test_report_escapes_a_hostile_target_name():
    html = render_report([], target=XSS)
    assert XSS not in html


def test_inline_code_escapes_everything_outside_the_backticks():
    rendered = str(_inline_code(f"{XSS} and `ls -la` after"))
    assert "<code>ls -la</code>" in rendered   # real markup only for the code span
    assert "<script>" not in rendered


def test_inline_code_escapes_content_inside_the_backticks_too():
    rendered = str(_inline_code("run `<script>alert(1)</script>` now"))
    assert "<script>" not in rendered


def test_inline_code_leaves_an_unbalanced_backtick_as_text():
    """An odd number of backticks must not emit a dangling tag."""
    rendered = str(_inline_code("a ` dangling backtick"))
    assert "<code>" not in rendered


# --- SEC-05..07: the outbound request boundary ----------------------------------------------
def test_send_verifies_tls_by_default():
    """Verification must be on: a forged token sent over a spoofed TLS session proves nothing."""
    source = inspect.getsource(checker.send)
    assert "verify=True" in source


def test_send_strips_content_length_so_a_swapped_token_cannot_truncate_the_body():
    """Forged tokens differ in length; a stale Content-Length would corrupt every POST."""
    source = inspect.getsource(checker.send)
    assert "content-length" in source.lower()


def test_send_does_not_follow_redirects():
    """We must judge the response to our own request, not the page it redirects to."""
    assert "allow_redirects=False" in inspect.getsource(checker.send)


def test_importing_the_engine_does_not_disable_tls_warnings_globally():
    """A library module must not mutate global warning state for the whole process."""
    source = Path(checker.__file__).read_text(encoding="utf-8")
    assert "disable_warnings" not in source


# --- SEC-08: the frontend must not treat server text as markup ------------------------------
def test_frontend_sets_error_text_rather_than_writing_it_as_html():
    """An error can quote a server response; splicing it into HTML would be a DOM XSS sink."""
    source = APP_JS.read_text(encoding="utf-8")
    assert "textContent" in source
    # The old splice-into-HTML helper must stay gone.
    assert "reportErrorDoc" not in source


def test_frontend_never_writes_a_message_into_the_error_document_string():
    """writeErrorTab writes a static shell, then sets the message as text."""
    source = APP_JS.read_text(encoding="utf-8")
    shell = source.split("function errorShellDoc()")[1].split("}")[0]
    assert "message" not in shell


# --- SEC-09..11: data handling --------------------------------------------------------------
def test_a_wordlist_is_treated_as_secrets_not_as_a_file_path(api, fake_target):
    """The API takes wordlist TEXT. A path must be tried as a literal secret, never opened."""
    from jwtpen.attacks import weak_secret

    secrets = weak_secret._secrets_for({"use_builtin": False,
                                        "wordlist": "C:/Windows/win.ini\n/etc/passwd"})
    assert secrets == ["C:/Windows/win.ini", "/etc/passwd"]


def test_no_report_is_retained_before_a_scan_runs(api):
    """Reports hold credentials, so nothing must be served until the operator runs a scan."""
    assert "No report yet" in api.get("/report").text


def test_scan_response_never_returns_the_forged_tokens_or_keys(api, fake_target):
    """The summary the browser receives must not carry credential material."""
    token = hs256_token()
    fake_target(secure(token))
    body = api.post("/scan", json={
        "raw_request": raw_request_with(token), "token": token,
        "scheme": "https", "checks": ["none_algorithm"],
    }).text

    assert "PRIVATE KEY" not in body
    assert token not in body


# --- SEC-12: the suite itself must stay offline ----------------------------------------------
def test_the_network_guard_is_active():
    """Proves the autouse guard works, so a passing suite really did stay offline."""
    with pytest.raises(AssertionError, match="real network request"):
        requests.get("https://example.test")


def test_attacks_cannot_reach_the_network_without_a_fake_target():
    """Without the fixture installed, any attempt to send must fail loudly rather than go out."""
    from jwtpen.attacks import none_algorithm

    token = hs256_token()
    with pytest.raises(AssertionError, match="real network request"):
        none_algorithm.run(raw_request_with(token), token, "https")
