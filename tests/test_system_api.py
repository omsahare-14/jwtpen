"""SYSTEM tests: the assembled application driven through its HTTP API.

The TestClient speaks to the ASGI app in-process, so no socket is opened and no port is bound.
This is the whole stack: routing, validation, the engine, and report rendering. See
tests/TEST-PLAN.md (ST-*).
"""

import shutil

import pytest

from jwtpen.attacks import registry

from conftest import TARGET_HOST, accepts_alg_none, hs256_token, raw_request_with, secure


EXPECTED_CHECKS = {
    "unverified_signature", "none_algorithm", "weak_secret", "jwk_injection",
    "jku_injection", "kid_path_traversal", "algorithm_confusion",
}


# --- ST-01..02: the UI page and static assets ---------------------------------------------
def test_root_serves_the_ui_page(api):
    response = api.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


@pytest.mark.parametrize("asset", ["/static/app.js", "/static/styles.css"])
def test_static_assets_are_served(api, asset):
    assert api.get(asset).status_code == 200


# --- ST-03..04: the check catalogue --------------------------------------------------------
def test_checks_endpoint_lists_every_registered_attack(api):
    checks = api.get("/checks").json()["checks"]
    assert {c["name"] for c in checks} == EXPECTED_CHECKS
    assert all(c["title"] and c["description"] for c in checks)


def test_checks_expose_the_ui_flags_the_frontend_needs(api):
    by_name = {c["name"]: c for c in api.get("/checks").json()["checks"]}
    assert by_name["weak_secret"]["requires_wordlist"] is True
    assert by_name["weak_secret"]["builtin_wordlist_count"] > 0
    assert by_name["jku_injection"]["requires_hosted_jwks"] is True
    assert by_name["algorithm_confusion"]["pubkey_option"] is True


# --- ST-05..08: token detection ------------------------------------------------------------
def test_detect_finds_and_decodes_the_session_token(api):
    token = hs256_token()
    candidates = api.post("/detect", json={"raw_request": raw_request_with(token)}).json()["candidates"]

    assert len(candidates) == 1
    assert candidates[0]["token"] == token
    assert candidates[0]["header"]["alg"] == "HS256"
    assert candidates[0]["payload"]["sub"] == "alice"
    assert candidates[0]["has_signature"] is True


def test_detect_returns_nothing_for_a_request_with_no_token(api):
    raw = "GET / HTTP/1.1\r\nHost: x\r\nCookie: session=not-a-jwt\r\n\r\n"
    assert api.post("/detect", json={"raw_request": raw}).json()["candidates"] == []


def test_detect_lists_several_tokens_without_duplicates(api):
    first, second = hs256_token(payload={"sub": "a"}), hs256_token(payload={"sub": "b"})
    raw = f"GET / HTTP/1.1\r\nHost: x\r\nCookie: s={first}; r={second}; again={first}\r\n\r\n"
    candidates = api.post("/detect", json={"raw_request": raw}).json()["candidates"]
    assert [c["token"] for c in candidates] == [first, second]


def test_detect_rejects_an_empty_request(api):
    assert api.post("/detect", json={"raw_request": ""}).status_code == 422


# --- ST-09..12: scanning -------------------------------------------------------------------
def test_scan_reports_a_vulnerable_target_and_stores_a_report(api, fake_target):
    token = hs256_token()
    fake_target(accepts_alg_none(token))

    body = api.post("/scan", json={
        "raw_request": raw_request_with(token),
        "token": token,
        "scheme": "https",
        "checks": ["none_algorithm"],
    }).json()

    assert body["target"] == TARGET_HOST
    assert body["findings"] == [{"attack": registry.get("none_algorithm").NAME,
                                "status": "VULNERABLE"}]

    report = api.get("/report")
    assert report.status_code == 200
    assert TARGET_HOST in report.text


def test_scan_runs_several_checks_in_one_pass(api, fake_target):
    token = hs256_token()
    fake_target(secure(token))

    body = api.post("/scan", json={
        "raw_request": raw_request_with(token),
        "token": token,
        "scheme": "https",
        "checks": ["none_algorithm", "unverified_signature"],
    }).json()

    assert len(body["findings"]) == 2
    assert all(f["status"] == "NOT_VULNERABLE" for f in body["findings"])


def test_scan_does_not_leak_finding_detail_to_the_summary(api, fake_target):
    """The UI summary carries only attack + status; detail belongs in the report."""
    token = hs256_token()
    fake_target(accepts_alg_none(token))

    finding = api.post("/scan", json={
        "raw_request": raw_request_with(token), "token": token,
        "scheme": "https", "checks": ["none_algorithm"],
    }).json()["findings"][0]

    assert set(finding) == {"attack", "status"}


def test_scan_survives_an_unknown_check_name(api, fake_target):
    """An unknown check must become an INCONCLUSIVE finding, never a 500."""
    token = hs256_token()
    fake_target(secure(token))

    response = api.post("/scan", json={
        "raw_request": raw_request_with(token), "token": token,
        "scheme": "https", "checks": ["no_such_check"],
    })

    assert response.status_code == 200
    assert response.json()["findings"][0]["status"] == "INCONCLUSIVE"


def test_scan_rejects_weak_secret_with_no_wordlist_source(api):
    token = hs256_token()
    response = api.post("/scan", json={
        "raw_request": raw_request_with(token), "token": token, "scheme": "https",
        "checks": ["weak_secret"], "use_builtin_wordlist": False, "wordlist": "   ",
    })
    assert response.status_code == 422


@pytest.mark.parametrize("payload_change", [
    {"scheme": "ftp"},        # not an allowed scheme
    {"checks": []},           # no checks selected
    {"token": ""},            # empty token
    {"raw_request": ""},      # empty request
])
def test_scan_validates_its_input(api, payload_change):
    token = hs256_token()
    body = {"raw_request": raw_request_with(token), "token": token,
            "scheme": "https", "checks": ["none_algorithm"]}
    body.update(payload_change)
    assert api.post("/scan", json=body).status_code == 422


# --- ST-13..15: report and prepare ---------------------------------------------------------
def test_report_explains_itself_before_any_scan(api):
    response = api.get("/report")
    assert response.status_code == 200
    assert "No report yet" in response.text


def test_report_pdf_is_unavailable_before_any_scan(api):
    assert api.get("/report.pdf").status_code == 404


def test_prepare_returns_hosting_material_for_jku(api):
    body = api.post("/prepare/jku_injection").json()
    assert set(body) == {"kid", "jwks_text", "private_key_pem"}
    assert "-----BEGIN PRIVATE KEY-----" in body["private_key_pem"]
    assert body["kid"] in body["jwks_text"]


def test_prepare_404s_for_a_check_with_nothing_to_prepare(api):
    assert api.post("/prepare/none_algorithm").status_code == 404


def test_prepare_404s_for_an_unknown_check(api):
    assert api.post("/prepare/no_such_check").status_code == 404


@pytest.mark.skipif(shutil.which("node") is None and not shutil.which("chrome"),
                    reason="headless Chromium not verifiable in this environment")
def test_report_pdf_renders_after_a_scan(api, fake_target):
    """End-to-end PDF export. Skipped when the Playwright browser is unavailable."""
    playwright = pytest.importorskip("playwright.sync_api")
    token = hs256_token()
    fake_target(accepts_alg_none(token))
    api.post("/scan", json={"raw_request": raw_request_with(token), "token": token,
                            "scheme": "https", "checks": ["none_algorithm"]})

    try:
        response = api.get("/report.pdf")
    except playwright.Error as exc:
        pytest.skip(f"Chromium not installed for Playwright: {exc}")

    assert response.status_code == 200
    assert response.content.startswith(b"%PDF-")
    assert "attachment" in response.headers["content-disposition"]
