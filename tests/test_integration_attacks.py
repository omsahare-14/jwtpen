"""INTEGRATION tests: each attack module driven end to end against a simulated server.

These wire together forging, request rebuilding, sending, and verdict classification. The only
thing replaced is the network boundary (`send`), so the real decision logic runs. See
tests/TEST-PLAN.md (IT-*).
"""

import pytest

from jwtpen.attacks import (
    algorithm_confusion, jku_injection, jwk_injection, kid_path_traversal,
    none_algorithm, unverified_signature, weak_secret,
)
from jwtpen.attacks.base import INCONCLUSIVE, NOT_VULNERABLE, SKIPPED, VULNERABLE
from jwtpen.core import keys

from conftest import (
    WEAK_SECRET, accepts_alg_none, accepts_any_signature, accepts_everything,
    accepts_hmac_signed_with, hs256_token, raw_request_with, rs256_token, secure,
)


# --- IT-01..03: alg:none ---------------------------------------------------------------------
def test_none_algorithm_flags_a_server_that_accepts_unsigned_tokens(fake_target):
    token = hs256_token()
    target = fake_target(accepts_alg_none(token))

    finding = none_algorithm.run(raw_request_with(token), token, "https")

    assert finding.status == VULNERABLE
    assert "Accepted Variant" in finding.evidence
    assert finding.evidence["Forged Token"].endswith(".")   # empty signature kept the trailing dot
    # Baselines plus at least one forged attempt were actually sent.
    assert len(target.tokens_seen) >= 3


def test_none_algorithm_clears_a_server_that_rejects_unsigned_tokens(fake_target):
    token = hs256_token()
    target = fake_target(secure(token))

    finding = none_algorithm.run(raw_request_with(token), token, "https")

    assert finding.status == NOT_VULNERABLE
    # All 16 casings tried, on top of the two baselines.
    assert len(target.tokens_seen) == 18


def test_none_algorithm_reports_inconclusive_when_baselines_match(fake_target):
    """A page that renders the same logged in or out cannot yield a trustworthy verdict."""
    token = hs256_token()
    fake_target(accepts_everything())

    finding = none_algorithm.run(raw_request_with(token), token, "https")

    assert finding.status == INCONCLUSIVE


def test_none_algorithm_tries_mixed_case_spellings(fake_target):
    """Case-sensitive filters are bypassed by casing, so every spelling must be attempted."""
    token = hs256_token()
    fake_target(secure(token))
    algs = {alg for alg, _ in none_algorithm.forge_variants(token)}
    assert {"none", "None", "NONE", "nOnE"} <= algs
    assert len(algs) == 16


# --- IT-05..06: unverified signature -----------------------------------------------------------
def test_unverified_signature_flags_a_server_that_never_checks_the_signature(fake_target):
    token = hs256_token()
    fake_target(accepts_any_signature(token))

    finding = unverified_signature.run(raw_request_with(token), token, "https")

    assert finding.status == VULNERABLE
    assert finding.evidence["Forged Token"] != token


def test_unverified_signature_clears_a_server_that_verifies(fake_target):
    token = hs256_token()
    fake_target(secure(token))

    finding = unverified_signature.run(raw_request_with(token), token, "https")

    assert finding.status == NOT_VULNERABLE


# --- IT-07..10: weak secret --------------------------------------------------------------------
def test_weak_secret_cracks_a_token_signed_with_a_wordlist_entry(fake_target):
    token = hs256_token(secret=WEAK_SECRET)
    fake_target(accepts_hmac_signed_with(WEAK_SECRET))

    finding = weak_secret.run(raw_request_with(token), token, "https",
                              options={"use_builtin": True})

    assert finding.status == VULNERABLE
    assert WEAK_SECRET in str(finding.evidence) + " ".join(finding.methodology)


def test_weak_secret_clears_a_strong_secret(fake_target):
    token = hs256_token(secret="S6nY2!q8Xv4xT0pLb9_zW3rKfJhGdA1c")
    fake_target(secure(token))

    finding = weak_secret.run(raw_request_with(token), token, "https",
                              options={"use_builtin": True})

    assert finding.status == NOT_VULNERABLE


def test_weak_secret_skips_a_token_that_is_not_hmac_signed(fake_target):
    """An RS256 token has no shared secret to guess, so the check must skip, not fail."""
    token = rs256_token(keys.generate_rsa_keypair())
    fake_target(secure(token))

    finding = weak_secret.run(raw_request_with(token), token, "https",
                              options={"use_builtin": True})

    assert finding.status == SKIPPED


def test_weak_secret_accepts_a_user_supplied_wordlist(fake_target):
    """A secret absent from the built-in list is still found when the tester supplies it."""
    custom = "Zq7-correct-horse-battery"
    token = hs256_token(secret=custom)
    fake_target(accepts_hmac_signed_with(custom))

    finding = weak_secret.run(
        raw_request_with(token), token, "https",
        options={"use_builtin": False, "wordlist": f"# a comment\n\n{custom}\n"},
    )

    assert finding.status == VULNERABLE


def test_weak_secret_is_inconclusive_with_no_secrets_to_try(fake_target):
    token = hs256_token()
    fake_target(secure(token))

    finding = weak_secret.run(raw_request_with(token), token, "https",
                              options={"use_builtin": False, "wordlist": ""})

    assert finding.status == INCONCLUSIVE


# --- IT-11..12: jwk injection -------------------------------------------------------------------
def test_jwk_injection_clears_a_server_that_ignores_the_embedded_key(fake_target):
    token = rs256_token(keys.generate_rsa_keypair())
    fake_target(secure(token))

    finding = jwk_injection.run(raw_request_with(token), token, "https")

    assert finding.status == NOT_VULNERABLE


def test_jwk_injection_flags_a_server_that_trusts_the_embedded_key(fake_target):
    """Simulate a server that verifies against whatever key the token carries in its jwk header."""
    from jwtpen.core import jwt_utils

    token = rs256_token(keys.generate_rsa_keypair())

    def trusts_embedded_jwk(candidate):
        if candidate == token:
            return True
        header, _, signature = jwt_utils.decode(candidate)
        if "jwk" not in header:
            return False
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        public_key = keys.jwk_to_public_key(header["jwk"])
        public_key.verify(
            jwt_utils._b64url_decode(signature),
            candidate.rsplit(".", 1)[0].encode("ascii"),
            padding.PKCS1v15(), hashes.SHA256(),
        )
        return True

    fake_target(trusts_embedded_jwk)
    finding = jwk_injection.run(raw_request_with(token), token, "https")

    assert finding.status == VULNERABLE


# --- IT-13: jku injection -------------------------------------------------------------------
def test_jku_injection_without_hosting_details_does_not_send_anything(fake_target):
    """Without a hosted key set the check must stop before touching the target."""
    token = rs256_token(keys.generate_rsa_keypair())
    target = fake_target(secure(token))

    finding = jku_injection.run(raw_request_with(token), token, "https", options={})

    assert finding.status == INCONCLUSIVE
    assert target.tokens_seen == []


# --- IT-14: kid path traversal ----------------------------------------------------------------
def test_kid_path_traversal_clears_a_server_that_rejects_traversal(fake_target):
    token = hs256_token()
    fake_target(secure(token))

    finding = kid_path_traversal.run(raw_request_with(token), token, "https", options=None)

    assert finding.status in (NOT_VULNERABLE, INCONCLUSIVE, SKIPPED)


# --- IT-15..16: algorithm confusion -------------------------------------------------------------
def test_algorithm_confusion_flags_a_server_that_verifies_rs256_as_hs256(fake_target, monkeypatch):
    """The classic RS256 -> HS256 confusion, with the public key supplied by the tester."""
    private_key = keys.generate_rsa_keypair()
    public_pem = keys.public_key_pem(private_key)
    token = rs256_token(private_key)

    # No key discovery over the network: the pasted PEM is the only candidate.
    monkeypatch.setattr(algorithm_confusion, "_http_get", lambda url: None)
    fake_target(accepts_hmac_signed_with(public_pem, valid_token=token))

    finding = algorithm_confusion.run(
        raw_request_with(token), token, "https",
        options={"public_key_pem": public_pem.decode()},
    )

    assert finding.status == VULNERABLE


def test_algorithm_confusion_is_inconclusive_with_no_key_available(fake_target, monkeypatch):
    token = rs256_token(keys.generate_rsa_keypair())
    monkeypatch.setattr(algorithm_confusion, "_http_get", lambda url: None)
    fake_target(secure(token))

    finding = algorithm_confusion.run(raw_request_with(token), token, "https", options={})

    assert finding.status == INCONCLUSIVE


# --- IT-17: every attack fills the report contract ----------------------------------------------
@pytest.mark.parametrize("module", [
    none_algorithm, unverified_signature, weak_secret, jwk_injection, kid_path_traversal,
])
def test_every_finding_carries_what_the_report_needs(fake_target, module):
    """A Finding must always name the attack, a status, a severity and a one-line summary."""
    token = hs256_token()
    fake_target(secure(token))

    finding = module.run(raw_request_with(token), token, "https", options={"use_builtin": True})

    assert finding.attack and isinstance(finding.attack, str)
    assert finding.status in (VULNERABLE, NOT_VULNERABLE, INCONCLUSIVE, SKIPPED)
    assert finding.severity in ("High", "Medium", "Low")
    assert finding.summary
