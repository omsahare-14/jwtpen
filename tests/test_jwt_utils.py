"""Offline tests for core/jwt_utils.py (no network)."""

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from jwtpen.core import jwt_utils, keys


def test_sign_rsa_signature_verifies_with_the_public_key():
    """A real server accepts the signature iff the matching public key verifies it."""
    private_key = keys.generate_rsa_keypair()
    signing_input = jwt_utils.encode({"alg": "RS256"}, {"sub": "administrator"})

    signature_b64 = jwt_utils.sign_rsa(signing_input, private_key, "RS256")

    # Re-decode the base64url signature and verify it the way a server would: no exception
    # means the public key accepts it.
    signature = jwt_utils._b64url_decode(signature_b64)
    private_key.public_key().verify(
        signature, signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
    )


def test_sign_rsa_rejects_signature_from_a_different_key():
    """Sanity check the verification above can actually fail (not a no-op)."""
    signing_input = jwt_utils.encode({"alg": "RS256"}, {"sub": "administrator"})
    signature = jwt_utils._b64url_decode(jwt_utils.sign_rsa(signing_input, keys.generate_rsa_keypair()))

    other_key = keys.generate_rsa_keypair()
    with pytest.raises(InvalidSignature):
        other_key.public_key().verify(
            signature, signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
        )


def test_sign_rsa_rejects_non_rsa_algorithm():
    with pytest.raises(ValueError):
        jwt_utils.sign_rsa("a.b", keys.generate_rsa_keypair(), "HS256")
