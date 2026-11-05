# Changelog

All notable changes to jwtpen are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## What counts as a breaking change

jwtpen is a tool rather than a library, so "the public surface" means the things another person
or script can depend on:

- the HTTP endpoints the local app exposes (`/detect`, `/scan`, `/report`, `/report.pdf`,
  `/prepare/{name}`, `/checks`) and the shape of their request and response bodies,
- the stable check names (`none_algorithm`, `weak_secret`, and so on), since those are what a
  scan request selects,
- the structure of a `Finding` as the report consumes it.

Renaming a check, removing an endpoint, or changing a response shape is a major-version change.
Adding a new check or a new optional field is a minor one.

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-11-06

First release. A local, single-user tool that tests JSON Web Tokens for seven vulnerability
classes, forges the proof-of-concept tokens, and generates a reproducible HTML/PDF report.

### Added

- **Seven checks**, one module each, selected by name through a registry:
  - unverified signature (the server never checks the signature)
  - `alg: none`, trying all 16 case spellings to defeat case-sensitive filters
  - weak HMAC secret, cracked from a built-in or supplied wordlist, then re-signed
  - JWK injection (attacker key embedded in the token header)
  - JKU injection (header points at an attacker-hosted key set)
  - KID path traversal (`kid` abused as a file path)
  - algorithm confusion (RS256 verified as HS256 using the public key as the HMAC secret)
- **Burp-style input.** Paste a raw HTTP request; jwtpen finds the JWT candidates, validates
  that each really is a token, and lets you confirm which one authenticates the request. A
  manual paste fallback is always available.
- **Automatic baselines.** The original token shows what "accepted" looks like and a
  deliberately broken one shows "rejected", so each forged token is judged against both. When
  the two baselines are indistinguishable the result is reported as inconclusive rather than
  guessed.
- **Byte-identical resends.** Only the token is swapped; every other cookie, header and body
  byte stays as captured.
- **Report** with methodology, evidence, manual reproduction steps, remediation and references,
  exportable to PDF through headless Chromium so the PDF matches the HTML exactly.
- **Local FastAPI web app** on loopback. All requests are made by the backend, so there are no
  browser CORS or cookie limits.

### Security

- The report escapes all target-derived content; the only markup its inline-code filter can
  emit is a `<code>` wrapper.
- TLS verification is on for every outbound request, and redirects are not followed, so the
  response judged is the one for the request actually sent.
- `Content-Length` is recalculated on resend, so a forged token of a different length cannot
  truncate the body and produce a false verdict.
- The frontend renders server error text as text, never as markup.
- `SECURITY.md` documents the authorized-use rule, the private disclosure process, and the fact
  that reports hold live credentials and are kept in memory only.

### Tests

- 173 cases across smoke, unit, functional, integration, system, UAT, security, regression and
  UI layers, catalogued in `tests/TEST-PLAN.md`.
- The suite is offline by construction: an autouse guard fails any test that attempts a real
  outbound request, and API tests drive the ASGI app in-process without binding a port.

[Unreleased]: https://github.com/omsahare-14/jwtpen/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/omsahare-14/jwtpen/releases/tag/v0.1.0
