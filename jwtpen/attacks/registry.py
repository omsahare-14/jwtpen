"""Registry mapping a short check name to that attack's module.

This is the one place that knows which attacks exist. The web app (and any future CLI) list and
run checks by name through here, so they never import individual attack modules or hard-code the
list. Adding a new attack is a one-line entry below.

Every attack's run() has the same shape:
    run(raw_request, token, scheme, options=None) -> Finding
`options` is a per-check settings dict (e.g. weak_secret's wordlist); attacks that need nothing
extra ignore it.
"""

from jwtpen.attacks import (
    unverified_signature, none_algorithm, weak_secret, jwk_injection, jku_injection,
    kid_path_traversal, algorithm_confusion,
)

# name (stable id used in the API) -> the attack module. Each module exposes NAME, DESCRIPTION and
# run(); the dict order fixes the order checks appear in.
_REGISTRY = {
    "unverified_signature": unverified_signature,
    "none_algorithm": none_algorithm,
    "weak_secret": weak_secret,
    "jwk_injection": jwk_injection,
    "jku_injection": jku_injection,
    "kid_path_traversal": kid_path_traversal,
    "algorithm_confusion": algorithm_confusion,
}


def list_checks():
    """Return [{'name', 'title', 'description', ...}, ...] in registry order.

    Each entry also carries the per-check UI flags (wordlist required, hosted JWKS required,
    optional kid-file control, optional public-key control) that the frontend reads to attach the
    right control to each check.
    """
    checks = []
    for name, module in _REGISTRY.items():
        entry = {
            "name": name,
            "title": module.NAME,
            "description": module.DESCRIPTION,
            "requires_wordlist": getattr(module, "REQUIRES_WORDLIST", False),
        }
        if entry["requires_wordlist"]:
            entry["builtin_wordlist_count"] = getattr(module, "BUILTIN_COUNT", 0)
        entry["requires_hosted_jwks"] = getattr(module, "REQUIRES_HOSTED_JWKS", False)
        if entry["requires_hosted_jwks"]:
            entry["hosted_jwks_badge"] = getattr(module, "HOSTED_JWKS_BADGE", "Hosting required")
            entry["hosted_jwks_hint"] = getattr(module, "HOSTED_JWKS_HINT", "")
        entry["kid_file_option"] = getattr(module, "KID_FILE_OPTION", False)
        if entry["kid_file_option"]:
            entry["kid_file_hint"] = getattr(module, "KID_FILE_HINT", "")
        entry["pubkey_option"] = getattr(module, "PUBKEY_OPTION", False)
        if entry["pubkey_option"]:
            entry["pubkey_hint"] = getattr(module, "PUBKEY_HINT", "")
        checks.append(entry)
    return checks


def get(name):
    """Return the attack module for `name`, or raise KeyError listing the known names."""
    if name not in _REGISTRY:
        known = ", ".join(_REGISTRY)
        raise KeyError(f"Unknown check '{name}'. Known checks: {known}.")
    return _REGISTRY[name]


def run_check(name, raw_request, token, scheme, options=None):
    """Look up `name` and run that attack, returning its Finding."""
    return get(name).run(raw_request, token, scheme, options)
