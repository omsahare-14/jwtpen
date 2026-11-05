"""JWT primitives: decode a token into its parts, build a signing input, and sign one."""

import base64
import hashlib
import hmac
import json


def _b64url_decode(segment):
    """Base64url-decode one part of a JWT, re-adding the padding JWTs strip off."""
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode(token):
    """Split a JWT and return its header (dict), payload (dict), and signature (str).

    The header and payload are base64url-encoded JSON and are parsed into dicts; the signature
    is returned as its original string.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Not a valid JWT: expected 3 parts separated by dots, got {len(parts)}.")
    header_part, payload_part, signature_part = parts

    header = json.loads(_b64url_decode(header_part))
    payload = json.loads(_b64url_decode(payload_part))
    return header, payload, signature_part


def _b64url_encode(raw_bytes):
    """Base64url-encode bytes and strip the padding, the way JWTs do."""
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")


def encode(header, payload):
    """Return the signing input base64url(header) + "." + base64url(payload).

    This is the string a signature is computed over and the first two parts of the final token.
    JSON is written compactly (no spaces), as real JWTs are.
    """
    encoded_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return encoded_header + "." + encoded_payload


def construct_jwt(signing_input, signature):
    """Join the signing input and the signature into a full JWT string."""
    return signing_input + "." + signature


_HMAC_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def sign_hmac(signing_input, secret, alg="HS256"):
    """Return the base64url HMAC signature for `signing_input` under `secret`.

    Used both to forge a token and to test a candidate secret (sign the original signing input
    and compare with the token's signature). `secret` may be str or bytes.
    """
    if alg not in _HMAC_HASHES:
        raise ValueError(f"Not an HMAC algorithm: {alg!r}. Expected one of {', '.join(_HMAC_HASHES)}.")
    if isinstance(secret, str):
        secret = secret.encode()
    digest = hmac.new(secret, signing_input.encode("ascii"), _HMAC_HASHES[alg]).digest()
    return _b64url_encode(digest)


_RSA_HASHES = {"RS256": "sha256", "RS384": "sha384", "RS512": "sha512"}


def sign_rsa(signing_input, private_key, alg="RS256"):
    """Return the base64url RSA (PKCS#1 v1.5) signature for `signing_input`.

    `cryptography` is imported lazily so the HMAC-only attacks and their tests don't need it.
    `private_key` is a cryptography RSA private key (e.g. from core.keys.generate_rsa_keypair()).
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    if alg not in _RSA_HASHES:
        raise ValueError(f"Not an RSA algorithm: {alg!r}. Expected one of {', '.join(_RSA_HASHES)}.")
    hash_algorithm = getattr(hashes, _RSA_HASHES[alg].upper())()
    signature = private_key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hash_algorithm)
    return _b64url_encode(signature)
