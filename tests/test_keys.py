"""Offline tests for core/keys.py, PEM <-> JWK round-trips, etc. (no network)."""

import pytest

from jwtpen.core import keys

# Generate one keypair for the whole module: RSA keygen is the slow part, and every test here
# only reads from the key, never mutates it.
PRIVATE_KEY = keys.generate_rsa_keypair()
PUBLIC_KEY = PRIVATE_KEY.public_key()


def test_jwk_has_expected_rsa_shape():
    jwk = keys.public_key_to_jwk(PUBLIC_KEY)
    assert jwk["kty"] == "RSA"
    # 65537 (the exponent we generate with) is "AQAB" in JWK's base64url-of-bytes encoding.
    assert jwk["e"] == "AQAB"
    assert jwk["n"]  # modulus present and non-empty


def test_pem_jwk_round_trip_is_identical():
    """public key -> JWK -> public key reproduces the same key, byte-for-byte in PEM."""
    jwk = keys.public_key_to_jwk(PUBLIC_KEY)
    rebuilt = keys.jwk_to_public_key(jwk)
    assert keys.public_key_pem(rebuilt) == keys.public_key_pem(PUBLIC_KEY)


def test_optional_jwk_fields_included_only_when_given():
    bare = keys.public_key_to_jwk(PUBLIC_KEY, alg=None, use=None)
    assert "kid" not in bare and "alg" not in bare and "use" not in bare

    tagged = keys.public_key_to_jwk(PUBLIC_KEY, kid="abc", alg="RS256", use="sig")
    assert tagged["kid"] == "abc" and tagged["alg"] == "RS256" and tagged["use"] == "sig"


def test_jwk_to_public_key_rejects_non_rsa():
    with pytest.raises(ValueError):
        keys.jwk_to_public_key({"kty": "EC", "n": "x", "e": "y"})


def test_public_key_pem_accepts_private_or_public():
    """Passing a private key yields its public half, same PEM either way."""
    assert keys.public_key_pem(PRIVATE_KEY) == keys.public_key_pem(PUBLIC_KEY)
    assert keys.public_key_pem(PUBLIC_KEY).startswith(b"-----BEGIN PUBLIC KEY-----")


def test_private_key_pem_is_unencrypted_pkcs8():
    assert keys.private_key_pem(PRIVATE_KEY).startswith(b"-----BEGIN PRIVATE KEY-----")


def test_hmac_bytes_from_key_is_the_public_pem():
    """The confusion attack's HMAC secret must be exactly the server's public-key PEM."""
    assert keys.public_key_as_hmac_bytes(PUBLIC_KEY) == keys.public_key_pem(PUBLIC_KEY)


def test_hmac_bytes_passes_through_literal_pem_unchanged():
    """Given the server's literal PEM text, we use its exact bytes (layout matters)."""
    pem_str = keys.public_key_pem(PUBLIC_KEY).decode()
    assert keys.public_key_as_hmac_bytes(pem_str) == pem_str.encode()
    assert keys.public_key_as_hmac_bytes(pem_str.encode()) == pem_str.encode()


def test_pkcs1_pem_is_the_rsa_public_key_form():
    """The second canonical form the confusion attack tries is the PKCS#1 'RSA PUBLIC KEY' PEM."""
    pkcs1 = keys.public_key_pkcs1_pem(PUBLIC_KEY)
    assert pkcs1.startswith(b"-----BEGIN RSA PUBLIC KEY-----")
    assert pkcs1 != keys.public_key_pem(PUBLIC_KEY)


def test_load_public_key_flexible_accepts_spki_pkcs1_and_certificate():
    """A pasted key may be SPKI PEM, PKCS#1 PEM, or an X.509 cert; all yield the same key."""
    import datetime

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization

    spki = keys.public_key_pem(PUBLIC_KEY)
    pkcs1 = keys.public_key_pkcs1_pem(PUBLIC_KEY)

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(PUBLIC_KEY)
            .serial_number(1)
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2035, 1, 1))
            .sign(PRIVATE_KEY, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    for form in (spki, pkcs1, cert_pem):
        loaded = keys.load_public_key_flexible(form)
        assert keys.public_key_pem(loaded) == spki


def test_load_public_key_flexible_rejects_garbage():
    with pytest.raises(ValueError):
        keys.load_public_key_flexible("not a key")