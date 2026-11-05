"""REGRESSION tests: defects that were found and fixed must never come back.

Every test here maps to a specific bug. The comment says which one, so a future reader knows
why the assertion exists and must not weaken it. See tests/TEST-PLAN.md (RG-*).
"""

from pathlib import Path

from jwtpen.core import checker, keys

PROJECT_ROOT = Path(__file__).resolve().parents[1]


# RG-01: public_key_to_jwk included alg/use even when the caller passed nothing, because the
# guard tested truthiness of a value the test was passing as the string "None".
def test_optional_jwk_fields_are_omitted_when_not_requested():
    key = keys.generate_rsa_keypair().public_key()
    bare = keys.public_key_to_jwk(key, alg=None, use=None)
    assert "alg" not in bare and "use" not in bare and "kid" not in bare
    assert bare["kty"] == "RSA"      # the required members are still there


def test_optional_jwk_fields_are_included_when_requested():
    key = keys.generate_rsa_keypair().public_key()
    tagged = keys.public_key_to_jwk(key, kid="abc", alg="RS256", use="sig")
    assert (tagged["kid"], tagged["alg"], tagged["use"]) == ("abc", "RS256", "sig")


# RG-02: core/checker.py called urllib3.disable_warnings() at import, silencing TLS warnings
# for the whole process even though every request verifies. A library must not do that.
def test_the_engine_does_not_silence_tls_warnings_on_import():
    source = Path(checker.__file__).read_text(encoding="utf-8")
    assert "disable_warnings" not in source
    assert "urllib3" not in source


# RG-03: requirements.txt listed urllib3 only for that call, and still filed cryptography under
# "not imported yet" long after the RSA attacks shipped.
def test_requirements_reflect_what_the_code_actually_imports():
    text = (PROJECT_ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert "cryptography" in text
    assert "not imported yet" not in text
    assert not any(line.strip().startswith("urllib3") for line in text.splitlines())


# RG-04: the frontend built its error page by splicing the server's error text into an HTML
# string and document.write()ing it, which is a DOM XSS sink waiting for a reachable message.
def test_the_frontend_error_page_does_not_splice_text_into_html():
    source = (PROJECT_ROOT / "jwtpen" / "webapp" / "static" / "app.js").read_text(encoding="utf-8")
    assert "reportErrorDoc" not in source
    assert "writeErrorTab" in source


# RG-05: a docstring claimed TLS warnings were "already silenced by core.checker's import",
# which stopped being true when RG-02 was fixed. Stale security comments mislead reviewers.
def test_no_module_claims_warnings_are_silenced_elsewhere():
    for path in (PROJECT_ROOT / "jwtpen").rglob("*.py"):
        assert "already silenced" not in path.read_text(encoding="utf-8"), path


# RG-06: Content-Length must be dropped when the token is swapped, or a forged token of a
# different length corrupts every POST body and the verdicts become meaningless.
def test_content_length_is_still_stripped_before_resending():
    import inspect
    assert "content-length" in inspect.getsource(checker.send).lower()
