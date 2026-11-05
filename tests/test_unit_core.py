"""UNIT tests for the core engine: request parsing, token swapping, and verdict classification.

These exercise one function at a time with no target involved. See tests/TEST-PLAN.md (UT-*).
"""

import pytest

from jwtpen.core import checker
from jwtpen.core.checker import ACCEPTED, INCONCLUSIVE, REJECTED, classify, resembles
from jwtpen.core.jwt_utils import decode
from jwtpen.core.raw_request import find_jwts, parse_request, swap_token

from conftest import ACCEPTED_BODY, REJECTED_BODY, FakeResponse, hs256_token, raw_request_with


# --- UT-01..05: parse_request ---------------------------------------------------------------
def test_parse_request_splits_method_path_and_headers():
    parsed = parse_request(raw_request_with("a.b.c"))
    assert parsed["method"] == "GET"
    assert parsed["path"] == "/my-account"
    assert parsed["headers"]["Host"] == "target.test"
    assert parsed["headers"]["Accept"] == "text/html"


def test_parse_request_keeps_colons_inside_header_values():
    """Only the first colon separates name from value, so URLs in values survive intact."""
    raw = "GET / HTTP/1.1\r\nHost: x\r\nReferer: https://example.test/a:b\r\n\r\n"
    assert parse_request(raw)["headers"]["Referer"] == "https://example.test/a:b"


def test_parse_request_extracts_the_body_after_the_blank_line():
    raw = "POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{\"u\":\"alice\"}"
    parsed = parse_request(raw)
    assert parsed["method"] == "POST"
    assert parsed["body"] == '{"u":"alice"}'


def test_parse_request_handles_a_request_with_no_body():
    assert parse_request(raw_request_with("a.b.c"))["body"] == ""


def test_parse_request_normalises_crlf_and_lf_identically():
    crlf = "GET /p HTTP/1.1\r\nHost: x\r\n\r\nbody"
    lf = "GET /p HTTP/1.1\nHost: x\n\nbody"
    assert parse_request(crlf) == parse_request(lf)


# --- UT-06..09: find_jwts -------------------------------------------------------------------
def test_find_jwts_locates_the_session_token():
    token = hs256_token()
    assert find_jwts(raw_request_with(token)) == [token]


def test_find_jwts_ignores_dotted_text_that_is_not_a_jwt():
    """Version strings and IPs are dotted but do not start with the 'eyJ' JSON marker."""
    assert find_jwts("version 15.14.13 and 10.0.0.1 and not.a.token") == []


def test_find_jwts_matches_an_unsigned_token_with_an_empty_signature():
    """alg:none tokens end in a bare dot; the detector must still see them."""
    unsigned = hs256_token().rsplit(".", 1)[0] + "."
    assert unsigned in find_jwts(f"Cookie: session={unsigned}")


def test_find_jwts_returns_every_occurrence_in_order():
    first, second = hs256_token(payload={"sub": "a"}), hs256_token(payload={"sub": "b"})
    found = find_jwts(f"Cookie: s={first}\r\nAuthorization: Bearer {second}")
    assert found == [first, second]


# --- UT-10..11: swap_token ------------------------------------------------------------------
def test_swap_token_replaces_every_occurrence():
    old, new = hs256_token(), "FORGED.TOKEN.HERE"
    raw = f"Cookie: session={old}\r\nAuthorization: Bearer {old}"
    swapped = swap_token(raw, old, new)
    assert old not in swapped
    assert swapped.count(new) == 2


def test_swap_token_leaves_the_rest_of_the_request_byte_identical():
    old = hs256_token()
    raw = raw_request_with(old)
    swapped = swap_token(raw, old, "X.Y.Z")
    assert swapped.replace("X.Y.Z", old) == raw


# --- UT-12..16: resembles / classify --------------------------------------------------------
def test_resembles_is_true_for_identical_responses():
    assert resembles(FakeResponse(200, ACCEPTED_BODY), FakeResponse(200, ACCEPTED_BODY))


def test_resembles_is_false_when_the_status_differs():
    assert not resembles(FakeResponse(200, ACCEPTED_BODY), FakeResponse(401, ACCEPTED_BODY))


def test_resembles_tolerates_small_volatile_differences():
    """A CSRF token or timestamp changing must not flip the verdict on a real-sized page."""
    page = ACCEPTED_BODY + "<p>filler copy for a realistically sized account page.</p>" * 10
    a = FakeResponse(200, page + "<input name=csrf value=aaaaaaaa>")
    b = FakeResponse(200, page + "<input name=csrf value=bbbbbbbb>")
    assert resembles(a, b)


def test_resembles_separates_a_logged_in_page_from_a_rejected_one():
    """The case that matters: the two baselines must never look alike."""
    assert not resembles(FakeResponse(200, ACCEPTED_BODY), FakeResponse(401, REJECTED_BODY))


def test_classify_returns_accepted_rejected_and_inconclusive():
    good = FakeResponse(200, ACCEPTED_BODY)
    bad = FakeResponse(401, REJECTED_BODY)
    assert classify(good, bad, FakeResponse(200, ACCEPTED_BODY)) == ACCEPTED
    assert classify(good, bad, FakeResponse(401, REJECTED_BODY)) == REJECTED
    # Matches neither baseline (a 500 is its own outcome).
    assert classify(good, bad, FakeResponse(500, "Server error")) == INCONCLUSIVE


def test_classify_is_inconclusive_when_the_baselines_are_indistinguishable():
    """If the page looks the same logged in or out, no verdict can be trusted."""
    same = FakeResponse(200, ACCEPTED_BODY)
    assert classify(same, FakeResponse(200, ACCEPTED_BODY), same) == INCONCLUSIVE


def test_similarity_threshold_is_a_sane_ratio():
    assert 0.5 < checker.SIMILARITY_THRESHOLD <= 1.0


# --- UT-17..19: jwt_utils.decode ------------------------------------------------------------
def test_decode_returns_header_payload_and_signature():
    header, payload, signature = decode(hs256_token())
    assert header["alg"] == "HS256"
    assert payload["sub"] == "alice"
    assert signature


@pytest.mark.parametrize("bad_token", ["a.b", "a", "a.b.c.d", ""])
def test_decode_rejects_anything_that_is_not_three_parts(bad_token):
    with pytest.raises(ValueError):
        decode(bad_token)
