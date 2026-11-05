"""Send a parsed request (with a token swapped in) to the target and classify whether the attack
worked, by comparing the response to the known-good (original token) and known-bad (unparseable
token) baselines."""

from difflib import SequenceMatcher

import requests

# Give up on a target that doesn't answer within this many seconds, so a hung host can't freeze
# the whole scan.
TIMEOUT_SECONDS = 10

# How alike two response bodies must be (0.0 = totally different, 1.0 = identical) to count as the
# same outcome. Volatile noise (a CSRF token, a timestamp) nudges this only slightly, while a
# logged-in page vs a rejected page differ far more, so 0.95 cleanly separates them.
SIMILARITY_THRESHOLD = 0.95


def resembles(response_a, response_b):
    """Return True if the two responses look like the same outcome (both accepted, or both rejected).

    Compares the HTTP status code first, then the body similarity ratio against SIMILARITY_THRESHOLD.
    """
    if response_a.status_code != response_b.status_code:
        return False
    # autojunk=False disables difflib's heuristic that ignores very common characters on long
    # inputs; HTML is full of them, and ignoring them made near-identical pages look different.
    similarity = SequenceMatcher(None, response_a.text, response_b.text, autojunk=False).ratio()
    return similarity >= SIMILARITY_THRESHOLD


# Verdicts for a forged token. Each attack decides what ACCEPTED means for it (for
# unverified_signature, accepted = vulnerable).
ACCEPTED = "ACCEPTED"
REJECTED = "REJECTED"
INCONCLUSIVE = "INCONCLUSIVE"


def classify(good, bad, forged):
    """Decide what the server did with the forged token by comparing it to both baselines.

    good   = response to the original (valid) token     -> what "logged in" looks like
    bad    = response to an unparseable token           -> what "rejected" looks like
    forged = response to the token under test

    Returns ACCEPTED, REJECTED, or INCONCLUSIVE, committing to a verdict only when the forged
    response clearly matches one baseline and not the other.
    """
    # If the app answers the same whether or not you're authenticated, the baselines are
    # indistinguishable and no verdict can be trusted.
    if resembles(good, bad):
        return INCONCLUSIVE

    looks_good = resembles(forged, good)
    looks_bad = resembles(forged, bad)

    if looks_good and not looks_bad:
        return ACCEPTED
    if looks_bad and not looks_good:
        return REJECTED
    return INCONCLUSIVE


def send(parsed, scheme):
    """Send a parsed request (with whatever token is currently in it) and return the response.

    `parsed` is the dict from raw_request.parse_request(); `scheme` is "http" or "https".
    """
    url = scheme + "://" + parsed["headers"]["Host"] + parsed["path"]

    # Drop Content-Length: requests recomputes it from the body, so a stale value would conflict.
    headers = {name: value for name, value in parsed["headers"].items()
               if name.lower() != "content-length"}

    return requests.request(
        parsed["method"],
        url,
        headers=headers,
        data=parsed["body"],
        allow_redirects=False,  # we want the response to our request, not the page it redirects to
        verify=True,
        timeout=TIMEOUT_SECONDS,
    )
