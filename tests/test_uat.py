"""USER ACCEPTANCE tests: the journeys a pentester actually performs, start to finish.

Each test is one scenario written from the user's point of view, driven through the same HTTP
API the browser uses. These answer "can a tester do their job with this?" rather than "is this
function correct?". See tests/TEST-PLAN.md (UAT-*).
"""

from conftest import (
    TARGET_HOST, WEAK_SECRET, accepts_alg_none, accepts_everything, hs256_token,
    accepts_hmac_signed_with, raw_request_with, secure,
)


def _detect_then_scan(api, token, checks, **extra):
    """The real sequence: paste a request, confirm the detected token, run the chosen checks."""
    raw = raw_request_with(token)
    candidates = api.post("/detect", json={"raw_request": raw}).json()["candidates"]
    chosen = candidates[0]["token"]
    body = {"raw_request": raw, "token": chosen, "scheme": "https", "checks": checks}
    body.update(extra)
    return api.post("/scan", json=body).json()


# --- UAT-01: find a real vulnerability and get a usable report -------------------------------
def test_tester_finds_an_unsigned_token_flaw_and_gets_a_reproducible_report(api, fake_target):
    token = hs256_token()
    fake_target(accepts_alg_none(token))

    result = _detect_then_scan(api, token, ["none_algorithm"])

    # 1. The tool tells them it is vulnerable, and against which host.
    assert result["target"] == TARGET_HOST
    assert result["findings"][0]["status"] == "VULNERABLE"

    # 2. The report explains what was done, how to redo it by hand, and how to fix it.
    report = api.get("/report").text
    assert "What The Tool Did" in report
    assert "How To Reproduce" in report
    assert "Remediation" in report
    # 3. And it can be handed to a client as a PDF.
    assert "export-pdf" in report


# --- UAT-02: a hardened target comes back clean ----------------------------------------------
def test_tester_gets_a_clean_result_against_a_correctly_implemented_server(api, fake_target):
    token = hs256_token(secret="H7!vQ2pLx9_zW3rKfJhGdA1cS6nY2q8X")
    fake_target(secure(token))

    result = _detect_then_scan(
        api, token, ["none_algorithm", "unverified_signature", "weak_secret"],
    )

    assert {f["status"] for f in result["findings"]} == {"NOT_VULNERABLE"}
    assert "0 Vulnerabilities Found" in api.get("/report").text or "No Vulnerabilities" in api.get("/report").text


# --- UAT-03: the tool admits when it cannot tell ---------------------------------------------
def test_tester_is_told_when_no_verdict_can_be_trusted(api, fake_target):
    """An endpoint that looks the same logged in or out must produce honesty, not a guess."""
    token = hs256_token()
    fake_target(accepts_everything())

    result = _detect_then_scan(api, token, ["none_algorithm"])

    assert result["findings"][0]["status"] == "INCONCLUSIVE"
    assert "could not be judged automatically" in api.get("/report").text


# --- UAT-04: crack a weak secret and see the secret itself -----------------------------------
def test_tester_recovers_a_guessable_signing_secret(api, fake_target):
    token = hs256_token(secret=WEAK_SECRET)
    fake_target(accepts_hmac_signed_with(WEAK_SECRET))

    result = _detect_then_scan(api, token, ["weak_secret"], use_builtin_wordlist=True)

    assert result["findings"][0]["status"] == "VULNERABLE"
    # The recovered secret is the proof, so it must appear in the report.
    assert WEAK_SECRET in api.get("/report").text


# --- UAT-05: bring your own wordlist ----------------------------------------------------------
def test_tester_can_supply_their_own_wordlist(api, fake_target):
    custom = "acme-staging-key-2024"
    token = hs256_token(secret=custom)
    fake_target(accepts_hmac_signed_with(custom))

    result = _detect_then_scan(api, token, ["weak_secret"],
                               use_builtin_wordlist=False, wordlist=f"{custom}\nother\n")

    assert result["findings"][0]["status"] == "VULNERABLE"


# --- UAT-06: prepare the hosted key set for the jku attack ------------------------------------
def test_tester_gets_hostable_material_for_the_jku_check(api):
    """The tester must be handed a key set to host and the private key that matches it."""
    material = api.post("/prepare/jku_injection").json()

    assert material["kid"] in material["jwks_text"]
    assert '"keys"' in material["jwks_text"]
    assert "-----BEGIN PRIVATE KEY-----" in material["private_key_pem"]


# --- UAT-07: run every check in one pass -------------------------------------------------------
def test_tester_can_run_the_whole_suite_in_one_go(api, fake_target, monkeypatch):
    """Selecting everything must produce one finding per check and never crash the run."""
    from jwtpen.attacks import algorithm_confusion

    token = hs256_token()
    monkeypatch.setattr(algorithm_confusion, "_http_get", lambda url: None)
    fake_target(secure(token))

    all_checks = [c["name"] for c in api.get("/checks").json()["checks"]]
    result = _detect_then_scan(api, token, all_checks, use_builtin_wordlist=True)

    assert len(result["findings"]) == len(all_checks)
    assert api.get("/report").status_code == 200


# --- UAT-08: the report orders the worst news first ---------------------------------------------
def test_confirmed_problems_are_presented_before_clean_results(api, fake_target):
    token = hs256_token()
    fake_target(accepts_alg_none(token))

    result = _detect_then_scan(api, token, ["unverified_signature", "none_algorithm"])
    statuses = [f["status"] for f in result["findings"]]

    assert statuses[0] == "VULNERABLE"
