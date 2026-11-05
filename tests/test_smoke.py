"""SMOKE tests: is the build fundamentally alive?

Fast, shallow checks meant to run first and fail loudly. If these break, nothing else is worth
running. See tests/TEST-PLAN.md (SM-*).
"""

import importlib

import pytest

from jwtpen.attacks import registry

MODULES = [
    "jwtpen.core.jwt_utils", "jwtpen.core.keys", "jwtpen.core.raw_request", "jwtpen.core.checker",
    "jwtpen.attacks.base", "jwtpen.attacks.registry", "jwtpen.report.html", "jwtpen.report.pdf",
    "jwtpen.webapp.server",
]

CHECK_NAMES = [
    "unverified_signature", "none_algorithm", "weak_secret", "jwk_injection",
    "jku_injection", "kid_path_traversal", "algorithm_confusion",
]


@pytest.mark.parametrize("module_path", MODULES)
def test_every_module_imports(module_path):
    assert importlib.import_module(module_path) is not None


def test_the_app_object_exists():
    from jwtpen.webapp.server import app
    assert app.title == "jwtpen"


def test_all_seven_checks_are_registered():
    assert [c["name"] for c in registry.list_checks()] == CHECK_NAMES


@pytest.mark.parametrize("name", CHECK_NAMES)
def test_every_check_exposes_the_engine_contract(name):
    """Each attack module must present NAME, DESCRIPTION and a callable run()."""
    module = registry.get(name)
    assert isinstance(module.NAME, str) and module.NAME
    assert isinstance(module.DESCRIPTION, str) and module.DESCRIPTION
    assert callable(module.run)


def test_the_builtin_wordlist_loads_and_is_not_empty():
    from jwtpen.attacks import weak_secret
    assert weak_secret.BUILTIN_COUNT > 0
    assert len(weak_secret.load_wordlist()) == weak_secret.BUILTIN_COUNT


def test_an_rsa_keypair_can_be_generated_and_round_tripped():
    from jwtpen.core import keys
    key = keys.generate_rsa_keypair()
    jwk = keys.public_key_to_jwk(key.public_key())
    assert keys.public_key_pem(keys.jwk_to_public_key(jwk)) == keys.public_key_pem(key)


def test_a_report_renders():
    from jwtpen.report.html import render_report
    assert "<!doctype html" in render_report([], target="smoke.test").lower()


def test_unknown_check_names_are_rejected_clearly():
    with pytest.raises(KeyError, match="Unknown check"):
        registry.get("does_not_exist")
