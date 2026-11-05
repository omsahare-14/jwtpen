"""Attack 1: unverified signature. The server never checks that the signature matches the header
and payload, so it accepts a token whose signature has been tampered with.

The header and payload are kept byte-for-byte identical and only the signature is changed, so the
one thing under test is whether the server verifies the signature.
"""

from jwtpen.core.jwt_utils import construct_jwt
from jwtpen.core.raw_request import parse_request, swap_token
from jwtpen.core.checker import send, classify, ACCEPTED, REJECTED
from jwtpen.attacks.base import Finding, VULNERABLE, NOT_VULNERABLE, INCONCLUSIVE, HIGH


def forge(token):
    """Return a copy of `token` whose signature has been tampered so it no longer matches."""
    signing_input, _, signature = token.rpartition(".")

    if signature == "":
        raise ValueError("Token has no signature to tamper with.")

    # Flip the first character to a guaranteed-different one. The first character always maps to
    # real signature bytes, whereas the last can carry spare bits a decoder ignores.
    new_first = "B" if signature[0] == "A" else "A"
    tampered_signature = new_first + signature[1:]
    return construct_jwt(signing_input, tampered_signature)


# NAME and DESCRIPTION are the single source of truth for how this check is labelled; the registry
# reads them so the UI, report and engine never drift apart.
NAME = "JWT Signature Not Verified"
DESCRIPTION = "Checks whether the server accepts a token after its signature is tampered with."

_SUMMARY = {
    VULNERABLE: ("The server accepted a token whose signature had been altered. Because the "
                 "signature is not verified, an attacker can change any claim (such as the "
                 "username) and still be trusted, bypassing authentication."),
    NOT_VULNERABLE: ("The server rejected a token whose signature had been altered, which "
                     "indicates the signature is being verified correctly."),
    INCONCLUSIVE: ("The result could not be judged automatically: the endpoint responded the "
                   "same way with and without a valid token, so accepted and rejected tokens "
                   "could not be told apart."),
}

_REPRODUCTION = [
    "Log in and capture your session JWT from the request.",
    "Change one character in the signature (the third dot-separated part), leaving the header and payload unchanged, then resend the request.",
    "If you remain logged in or receive the same authorized response, the signature is not being verified. That is the vulnerability.",
    'To demonstrate impact, now also edit a claim in the payload, for example change "sub" to another user or an administrator, and resend.',
    "If the server grants that account's access, you have escalated privileges with a forged token. Re-test other authenticated endpoints too, since verification can differ per route.",
]

_REMEDIATION = (
    "Always verify the JWT signature on the server with a vetted library, and reject any token "
    "whose signature is missing or invalid. Verify with the algorithm and key you expect rather "
    'than trusting the token\'s own "alg" header, and prefer a maintained library that enables '
    "signature verification by default."
)

_REFERENCES = [
    {"label": "OWASP Top 10: Identification and Authentication Failures",
     "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"},
    {"label": "RFC 7519: JSON Web Token (JWT)",
     "url": "https://datatracker.ietf.org/doc/html/rfc7519"},
]

# Map the checker's verdict (about the token) to the Finding's status (about the vulnerability).
_STATUS_BY_VERDICT = {
    ACCEPTED: VULNERABLE,
    REJECTED: NOT_VULNERABLE,
    INCONCLUSIVE: INCONCLUSIVE,
}


def run(raw_request, token, scheme, options=None):
    """Run the unverified-signature check end to end and return a Finding (no options used).

    The same request is sent three times, swapping only the token: the original (logged-in
    baseline), an unparseable token (rejected baseline), and the tampered-signature token. The
    server is vulnerable if it accepts the tampered token.
    """
    parsed = parse_request(raw_request)
    good = send(parsed, scheme)
    bad = send(parse_request(swap_token(raw_request, token, "INVALID")), scheme)

    forged_token = forge(token)
    forged = send(parse_request(swap_token(raw_request, token, forged_token)), scheme)

    verdict = classify(good, bad, forged)
    status = _STATUS_BY_VERDICT[verdict]

    url = scheme + "://" + parsed["headers"]["Host"] + parsed["path"]
    methodology = [
        "Kept the token's header and payload unchanged and replaced its signature with an invalid one.",
        "Resent your original request with this tampered token.",
    ]
    if status == VULNERABLE:
        methodology.append("The server accepted the tampered token, so it is not verifying the signature.")
    elif status == NOT_VULNERABLE:
        methodology.append("The server rejected the tampered token, so it is verifying the signature.")
    else:
        methodology.append("The endpoint responded the same way with and without a valid token, so the result could not be judged automatically.")

    evidence = {
        "Target URL": url,
        "Expected Response (Valid Token)": f"HTTP {good.status_code}",
        "Received Response (Forged Token)": f"HTTP {forged.status_code}",
        "Forged Token": forged_token,
    }

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
