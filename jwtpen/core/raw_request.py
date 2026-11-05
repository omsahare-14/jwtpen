"""Parse a raw HTTP request pasted from Burp, find JWT candidates in it, and rebuild it with a
chosen token swapped in."""

import re

# A JWT is header.payload.signature (three base64url parts). A real header is JSON starting with
# {", which base64url-encodes to "eyJ", so we anchor on that to skip unrelated dotted text like
# "15.14.13". The signature part may be empty (alg:none tokens).
JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")


def find_jwts(raw_request):
    """Return every JWT string found anywhere in the request."""
    return JWT_PATTERN.findall(raw_request)


def swap_token(raw_request, old_token, new_token):
    """Return a copy of the request with `old_token` replaced by `new_token` everywhere.

    A JWT is a long, unique blob, so it won't collide with anything else in the request; every
    other header, cookie, and byte stays as Burp sent it. If the token appears more than once
    (e.g. a cookie and an Authorization header), all occurrences are swapped.
    """
    return raw_request.replace(old_token, new_token)


def parse_request(raw_request):
    """Parse a raw HTTP request into {method, path, headers, body}.

    The scheme (http/https) is not part of the request; it is supplied separately when sending.
    """
    # Normalize Burp's CRLF line endings and strip blank lines around the pasted block.
    text = raw_request.replace("\r\n", "\n").strip()

    # Headers and body are separated by one blank line (two newlines).
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")

    # Request line: "METHOD PATH VERSION"; keep method and path.
    parts = lines[0].split()
    method, path = parts[0], parts[1]

    # Each remaining line is "Name: Value". Split on the first ":" only, since values can contain
    # colons (e.g. "Referer: https://...").
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip()] = value.strip()

    return {"method": method, "path": path, "headers": headers, "body": body}
