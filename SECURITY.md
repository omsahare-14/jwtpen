# Security Policy

## Authorized use only

jwtpen forges authentication tokens and sends them to a target. Use it **only** against
systems you own or are **explicitly authorized in writing** to test. Unauthorized testing is
illegal in most jurisdictions. You are responsible for how you use this tool.

## Handling of sensitive data

jwtpen is a local, single-user tool. Understand what it holds while it runs:

- **Reports contain live credentials.** A generated report can include the captured session
  JWT, any cracked HMAC secret, generated private keys, and raw response bodies from the
  target. Treat a saved report or exported PDF as a credential store: store it with the
  engagement evidence and delete it when the engagement closes.
- **Reports are kept in memory only.** The most recent report is held in the server process
  and is lost when you stop it. jwtpen does not write reports to disk unless you export a PDF.
- **Nothing is sent anywhere else.** Requests go only to the target you supply, and to a JWKS
  URL if you provide one. There is no telemetry, no analytics, and no third-party service.
- **Bind to loopback.** The documented run command listens on `127.0.0.1` only. Do not serve
  it on `0.0.0.0` or a routable address: the report endpoint has no authentication, so anyone
  who can reach the port can read the credentials in your last scan.
- **Do not commit captured material.** Raw requests, tokens, and reports are engagement data.
  The repository's `.gitignore` excludes generated reports; keep it that way.

## Supported versions

Security fixes are applied to the latest released version on the default branch. Older
versions are not patched.

## Reporting a vulnerability

Please report security issues **privately**. Do not open a public issue, and do not post
details on social media or a blog before a fix is available.

Use GitHub's private vulnerability reporting on this repository:
**Security → Report a vulnerability**. That channel is private to the maintainer.

Please include:

- the affected version or commit,
- a description of the issue and the trust boundary it crosses,
- steps to reproduce, ideally against a local fixture rather than a third-party host,
- the impact you believe it has.

### What to expect

- Acknowledgement within 7 days.
- An initial assessment, including whether the report is accepted, within 14 days.
- Credit in the release notes once a fix ships, unless you prefer to stay anonymous.

This is a maintained side project, not a commercial product. There is no bug bounty.

## Scope

In scope: anything that lets a party other than the operator read the operator's captured
tokens, reports, or keys; anything that causes jwtpen to send requests to a host the operator
did not select; and any flaw that causes a check to report a wrong verdict.

Out of scope: vulnerabilities in the targets you point jwtpen at (report those to the target's
owner), findings that require an attacker to already have local code execution or an account
on the operator's machine, and the deliberate behaviour of the tool itself, which is to forge
tokens and send them to a target you nominate.
