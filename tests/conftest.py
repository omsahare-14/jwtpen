"""Shared fixtures for the jwtpen suite.

Two things matter here:

* **Nothing touches the network.** `no_network` is autouse, so any test that tries to open a
  real connection fails loudly instead of reaching a live host. A tool that forges credentials
  must never have a test suite that can fire at something real by accident.
* **A fake target stands in for the server under test.** Attacks import `send` directly, so the
  fake is installed on each attack module rather than on `core.checker`.
"""

import pytest
import requests

from jwtpen.attacks import registry
from jwtpen.core import jwt_utils

TARGET_HOST = "target.test"
TARGET_PATH = "/my-account"

# What a logged-in page and a rejected page look like. They differ in both status and body, well
# past checker.SIMILARITY_THRESHOLD, so the engine can tell "accepted" from "rejected".
ACCEPTED_BODY = (
    "<html><body><h1>Your account</h1>"
    "<p>Signed in as alice. Update your email below.</p></body></html>"
)
REJECTED_BODY = "<html><body><h1>Unauthorized</h1><p>Please log in to continue.</p></body></html>"

WEAK_SECRET = "secret123"  # present in wordlists/common-secrets.txt


def raw_request_with(token):
    """Build a Burp-style raw request carrying `token` as the session cookie."""
    return (
        f"GET {TARGET_PATH} HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        "User-Agent: jwtpen-tests/1.0\r\n"
        "Accept: text/html\r\n"
        f"Cookie: session={token}\r\n"
        "\r\n"
    )


def hs256_token(secret=WEAK_SECRET, payload=None, header=None):
    """Mint a real HS256 token signed with `secret`."""
    header = header or {"alg": "HS256", "typ": "JWT"}
    payload = payload or {"sub": "alice", "role": "user", "iss": "acme-api"}
    signing_input = jwt_utils.encode(header, payload)
    return jwt_utils.construct_jwt(signing_input, jwt_utils.sign_hmac(signing_input, secret))


def rs256_token(private_key, payload=None, header=None):
    """Mint a real RS256 token signed with `private_key`."""
    header = header or {"alg": "RS256", "kid": "server-key-1"}
    payload = payload or {"sub": "alice", "role": "user", "iss": "acme-api"}
    signing_input = jwt_utils.encode(header, payload)
    return jwt_utils.construct_jwt(signing_input, jwt_utils.sign_rsa(signing_input, private_key))


class FakeResponse:
    """The minimum of requests.Response that core.checker reads."""

    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class FakeTarget:
    """A stand-in server. `policy(token) -> bool` decides whether a token is accepted.

    Records every token it was sent, so tests can assert what the engine actually tried.
    """

    def __init__(self, policy):
        self.policy = policy
        self.tokens_seen = []

    def __call__(self, parsed, scheme):
        token = _token_from(parsed)
        self.tokens_seen.append(token)
        accepted = False
        try:
            accepted = self.policy(token)
        except Exception:
            accepted = False  # an unparseable token is simply rejected, as a real server would
        return FakeResponse(200, ACCEPTED_BODY) if accepted else FakeResponse(401, REJECTED_BODY)


def _token_from(parsed):
    """Pull the session token back out of a parsed request's Cookie header."""
    cookie = parsed["headers"].get("Cookie", "")
    for part in cookie.split(";"):
        name, _, value = part.strip().partition("=")
        if name == "session":
            return value
    return ""


# --- acceptance policies, one per server behaviour we want to simulate ---------------------
def secure(valid_token):
    """A correctly implemented server: only the genuine token works."""
    return lambda token: token == valid_token


def accepts_alg_none(valid_token):
    """Vulnerable: honours "alg": "none" with an empty signature, in any casing."""
    def policy(token):
        if token == valid_token:
            return True
        header, _, signature = jwt_utils.decode(token)
        return header.get("alg", "").lower() == "none" and signature == ""
    return policy


def accepts_any_signature(valid_token):
    """Vulnerable: parses the token but never verifies the signature."""
    def policy(token):
        jwt_utils.decode(token)   # raises for genuinely malformed tokens -> rejected
        return True
    return policy


def accepts_hmac_signed_with(secret, valid_token=None):
    """Vulnerable: verifies HS256 against `secret` (bytes or str), so any token signed with it works.

    `valid_token` keeps the genuine session token working as well. That matters when the real
    token is not itself HMAC-signed (an RS256 token in the algorithm-confusion case): without it
    the logged-in baseline would also be rejected and no verdict could be reached.
    """
    def policy(token):
        if valid_token is not None and token == valid_token:
            return True
        header, _, signature = jwt_utils.decode(token)
        if header.get("alg") != "HS256":
            return False
        signing_input = token.rsplit(".", 1)[0]
        return jwt_utils.sign_hmac(signing_input, secret) == signature
    return policy


def accepts_everything(_valid_token=None):
    """A page that renders the same logged in or not, so no verdict can be trusted."""
    return lambda token: True


# --- fixtures ------------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Fail any test that attempts a real outbound request.

    Autouse, so this guard applies to the whole suite including tests that forget to install a
    fake target. TestClient talks to the ASGI app in-process and never goes through requests.
    """
    def blocked(*args, **kwargs):
        raise AssertionError(
            "This test tried to make a real network request. The suite must stay offline: "
            "install the fake_target fixture instead."
        )

    monkeypatch.setattr(requests, "request", blocked)
    monkeypatch.setattr(requests, "get", blocked)
    monkeypatch.setattr(requests.Session, "request", blocked)


@pytest.fixture
def fake_target(monkeypatch):
    """Install a FakeTarget as `send` on every attack module. Returns the installer.

    Usage:  target = fake_target(accepts_alg_none(valid_token))
    """
    def install(policy):
        target = FakeTarget(policy)
        for entry in registry.list_checks():
            module = registry.get(entry["name"])
            if hasattr(module, "send"):
                monkeypatch.setattr(module, "send", target)
        return target

    return install


@pytest.fixture
def api():
    """A TestClient for the FastAPI app: in-process ASGI, no socket, no port bound."""
    from fastapi.testclient import TestClient
    from jwtpen.webapp import server

    server._last_report = None      # each test starts with no stored report
    with TestClient(server.app) as client:
        yield client
    server._last_report = None      # and leaves none behind
