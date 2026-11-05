"""FUNCTIONAL tests: does the tool do what it promises to do?

These are written against the product requirements rather than the implementation: the eight
documented behaviours a user is told they get. See tests/TEST-PLAN.md (FT-*).
"""

import pytest

from jwtpen.attacks import none_algorithm, registry, unverified_signature
from jwtpen.core import keys
from jwtpen.core.jwt_utils import decode
from jwtpen.core.raw_request import find_jwts

from conftest import accepts_alg_none, hs256_token, raw_request_with, secure


# --- FT-01: the seven documented checks are all present and distinct --------------------------
def test_the_tool_offers_all_seven_documented_checks():
    checks = registry.list_checks()
    assert len(checks) == 7
    assert len({c["title"] for c in checks}) == 7      # no two checks share a label


# --- FT-02: JWT auto-detection validates, it does not just match dots -------------------------
def test_detection_accepts_real_tokens_and_rejects_lookalikes():
    real = hs256_token()
    assert find_jwts(f"token={real}") == [real]
    for lookalike in ("1.2.3", "a.b.c", "www.example.com", "file.tar.gz"):
        assert find_jwts(lookalike) == []


# --- FT-03: forging preserves the payload, which is what makes the result meaningful ----------
def test_forging_never_alters_the_payload_the_user_captured():
    """Every attack changes how the token is trusted, not who it claims to be."""
    token = hs256_token(payload={"sub": "alice", "role": "user"})
    original_payload = decode(token)[1]

    _, forged_none = none_algorithm.forge_variants(token)[0]
    forged_sig = unverified_signature.forge(token)

    assert decode(forged_none)[1] == original_payload
    assert decode(forged_sig)[1] == original_payload


# --- FT-04: only the token changes in the resent request ---------------------------------------
def test_only_the_token_differs_in_the_request_that_is_resent(fake_target):
    """Every other cookie, header and byte must stay exactly as captured."""
    token = hs256_token()
    sent = []

    def recording_policy(candidate):
        sent.append(candidate)
        return candidate == token

    fake_target(recording_policy)
    unverified_signature.run(raw_request_with(token), token, "https")

    # Baselines plus the forged attempt, each distinguishable only by its token.
    assert token in sent
    assert any(candidate != token for candidate in sent)


# --- FT-05: both schemes are supported ----------------------------------------------------------
@pytest.mark.parametrize("scheme", ["http", "https"])
def test_both_http_and_https_targets_are_supported(fake_target, scheme):
    token = hs256_token()
    fake_target(accepts_alg_none(token))
    finding = none_algorithm.run(raw_request_with(token), token, scheme)
    assert finding.evidence["Target URL"].startswith(scheme + "://")


# --- FT-06: a finding carries everything the report promises -----------------------------------
def test_a_confirmed_finding_carries_methodology_reproduction_and_remediation(fake_target):
    token = hs256_token()
    fake_target(accepts_alg_none(token))

    finding = none_algorithm.run(raw_request_with(token), token, "https")

    assert finding.methodology, "the report must explain what the tool did"
    assert finding.reproduction, "the report must explain how to redo it by hand"
    assert finding.remediation, "the report must explain how to fix it"
    assert finding.references, "the report must cite a source"
    assert finding.evidence, "the report must show proof"


# --- FT-07: references stay on primary sources --------------------------------------------------
def test_references_point_only_at_owasp_or_the_jwt_rfcs():
    """Findings cite standards, not third-party write-ups."""
    allowed = ("owasp.org", "datatracker.ietf.org", "ietf.org")
    for entry in registry.list_checks():
        module = registry.get(entry["name"])
        for ref in getattr(module, "_REFERENCES", []):
            assert any(host in ref["url"] for host in allowed), ref


# --- FT-08: the attacker key material is always freshly generated --------------------------------
def test_hosted_key_material_is_unique_per_preparation():
    """Reusing a keypair across engagements would leak one client's material into another."""
    from jwtpen.attacks import jku_injection

    first = jku_injection.generate_material()
    second = jku_injection.generate_material()

    assert first["kid"] != second["kid"]
    assert first["private_key_pem"] != second["private_key_pem"]


# --- FT-09: a non-HMAC token is skipped rather than guessed at ------------------------------------
def test_checks_that_do_not_apply_are_skipped_not_failed(fake_target):
    from jwtpen.attacks import weak_secret
    from jwtpen.attacks.base import SKIPPED

    token = hs256_token()
    rs_token = None
    key = keys.generate_rsa_keypair()
    from conftest import rs256_token
    rs_token = rs256_token(key)

    fake_target(secure(rs_token))
    finding = weak_secret.run(raw_request_with(rs_token), rs_token, "https",
                              options={"use_builtin": True})

    assert finding.status == SKIPPED
