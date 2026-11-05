"""Key handling for the RSA-based attacks: keygen, PEM <-> JWK, public-key-as-HMAC bytes.

Attacks 4-8 all turn on asymmetric keys:
  * jwk_injection / jku_injection embed or host an ATTACKER public key, then sign with the
    matching private key, so we need to generate a keypair and express its public half as a
    JWK (the JSON shape a `jwk` header or a `jku` key set uses).
  * algorithm_confusion feeds the server's RSA *public* key back as an HMAC secret; the trick
    only works if we use the EXACT same bytes the server would (its PEM text), which is what
    `public_key_as_hmac_bytes` pins down.

This module only moves keys between representations. Signing a token with a private key is a
JWT concern and lives in jwt_utils; this module has no JWT knowledge beyond the JWK shape.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Reuse the ONE base64url implementation (padding-stripping, URL-safe) the project already has,
# rather than writing a second one that could drift. JWKs encode `n` and `e` the same way a
# JWT encodes its parts, so the same helpers apply.
from jwtpen.core.jwt_utils import _b64url_decode, _b64url_encode


def generate_rsa_keypair(bits=2048):
    """Generate a fresh RSA private key (its public half comes from `.public_key()`).

    2048 bits is the usual floor for RS256 and is plenty for a test forgery; the public
    exponent 65537 is the standard choice every JWT library expects.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def public_key_pem(public_key):
    """Return the public key as SubjectPublicKeyInfo PEM bytes (the ``-----BEGIN PUBLIC KEY-----`` form).

    This is the representation servers publish and that JWT tooling hands you, so it's what we
    show in reproduction steps and, crucially, what algorithm confusion feeds back as the
    HMAC secret. Accepts a public key or a private key (we take its public half) for convenience.
    """
    if isinstance(public_key, rsa.RSAPrivateKey):
        public_key = public_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_pkcs1_pem(public_key):
    """Return the public key as PKCS#1 PEM bytes (the ``-----BEGIN RSA PUBLIC KEY-----`` form).

    Some stacks publish and verify against the PKCS#1 ("RSA PUBLIC KEY") encoding rather than the
    SubjectPublicKeyInfo one. Algorithm confusion only works if the HMAC key is byte-for-byte what
    the server uses, so we offer this second canonical form to try alongside the SPKI PEM. Accepts
    a public or private key.
    """
    if isinstance(public_key, rsa.RSAPrivateKey):
        public_key = public_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1,
    )


def load_public_key_flexible(text):
    """Load an RSA public key from pasted text: SPKI PEM, PKCS#1 PEM, or an X.509 certificate PEM.

    A tester may paste any of these when the key is known but not auto-discoverable. We try each
    form in turn and return the RSA public key, or raise ValueError if none parse. Accepts str or
    bytes.
    """
    if isinstance(text, str):
        text = text.encode()

    # A SubjectPublicKeyInfo or PKCS#1 public key PEM loads directly.
    try:
        key = serialization.load_pem_public_key(text)
        if isinstance(key, rsa.RSAPublicKey):
            return key
    except (ValueError, TypeError):
        pass

    # An X.509 certificate PEM carries the public key inside it.
    try:
        from cryptography.x509 import load_pem_x509_certificate

        public_key = load_pem_x509_certificate(text).public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            return public_key
    except (ValueError, TypeError):
        pass

    raise ValueError("Could not read an RSA public key from the pasted text "
                     "(expected an SPKI PEM, a PKCS#1 PEM, or an X.509 certificate).")


def private_key_pem(private_key):
    """Return the private key as unencrypted PKCS#8 PEM bytes.

    Only used for evidence / reproduction so the tester can re-sign the forged token by hand;
    we never transmit it. Unencrypted because there is no secret to protect in a throwaway
    attacker key and it keeps the reproduction steps copy-pasteable.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key_pem(pem):
    """Load an RSA private key back from unencrypted PKCS#8 PEM (the inverse of `private_key_pem`).

    The jku attack generates its keypair in a prepare step so the tester can host the matching
    JWKS; the private key then travels (as PEM) with the scan request and comes back here to sign
    the forged token, so the same key that's hosted is the one that signs. Accepts str or bytes.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    if isinstance(pem, str):
        pem = pem.encode()
    return load_pem_private_key(pem, password=None)


def _int_to_b64url(value):
    """base64url-encode a non-negative integer the way a JWK encodes `n` and `e`.

    JWK stores big numbers as their minimal big-endian byte string, base64url'd. `bit_length`
    rounded up to whole bytes gives that minimal length (and 0 still needs one byte).
    """
    length = max(1, (value.bit_length() + 7) // 8)
    return _b64url_encode(value.to_bytes(length, "big"))


def public_key_to_jwk(public_key, kid=None, alg="RS256", use="sig"):
    """Express an RSA public key as a JWK dict: ``{"kty": "RSA", "n": ..., "e": ...}``.

    This is the exact object an attacker drops into a `jwk` header or serves at a `jku` URL.
    `kid`, `alg`, and `use` are optional hints; we include `kid` only when given so the forged
    token's header `kid` can point at this key in a hosted set. Accepts a private key too.
    """
    if isinstance(public_key, rsa.RSAPrivateKey):
        public_key = public_key.public_key()
    numbers = public_key.public_numbers()
    jwk = {
        "kty": "RSA",
        "n": _int_to_b64url(numbers.n),
        "e": _int_to_b64url(numbers.e),
    }
    if alg:
        jwk["alg"] = alg
    if use:
        jwk["use"] = use
    if kid is not None:
        jwk["kid"] = kid
    return jwk


def public_key_to_jwks(public_key, kid=None, alg="RS256", use="sig"):
    """Wrap one public key as a JWK Set: ``{"keys": [<jwk>]}``, the exact JSON a `jku` URL serves.

    jku injection points the token's `jku` header at a URL the attacker controls; what lives at
    that URL is a JWK Set, not a bare JWK. This is that file's content, built from the same
    `public_key_to_jwk` so the hosted key matches the one the forged token's `kid` names.
    """
    return {"keys": [public_key_to_jwk(public_key, kid=kid, alg=alg, use=use)]}


def jwk_to_public_key(jwk):
    """Rebuild an RSA public key from a JWK's `n` and `e` (the inverse of `public_key_to_jwk`).

    Used to turn an attacker-supplied or published JWK back into a key object we can verify or
    re-serialize to PEM (e.g. a key read from a JWKS endpoint during algorithm confusion).
    """
    if jwk.get("kty") != "RSA":
        raise ValueError(f"Not an RSA JWK: kty={jwk.get('kty')!r} (expected 'RSA').")
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    return rsa.RSAPublicNumbers(e, n).public_key()


def public_key_as_hmac_bytes(key_or_pem):
    """Return the exact bytes to use as the HMAC secret in an RS256 -> HS256 confusion attack.

    The attack signs the token with HMAC using the server's PUBLIC key as the key. It only
    succeeds if we use byte-for-byte what the server treats as its "key", in practice the
    SubjectPublicKeyInfo PEM *text*, trailing newline included (that's what you get from reading
    the published .pem and what JWT libraries verify against). So:
      * given a key object, we serialize to that canonical PEM;
      * given PEM text (str or bytes), we pass it through unchanged, the caller may have the
        server's literal file and its byte layout is what matters.
    """
    if isinstance(key_or_pem, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return public_key_pem(key_or_pem)
    if isinstance(key_or_pem, str):
        return key_or_pem.encode()
    return key_or_pem
