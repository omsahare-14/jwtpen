# 🔑 jwtpen

> A local web app that tests JSON Web Tokens for seven common vulnerability classes, forges the proof-of-concept tokens, and generates a reproducible HTML/PDF report.

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)
![Built with FastAPI](https://img.shields.io/badge/Built%20with-FastAPI-009688.svg)

Paste a raw HTTP request from Burp, confirm the session JWT, pick your checks, and jwtpen rebuilds your exact request with each forged token swapped in. Every request is sent from the backend, so there are no CORS or cookie limits.

## 📑 Table of Contents

- [⚠️ Authorized Use Only](#-authorized-use-only)
- [✨ Features](#-features)
- [⚙️ How It Works](#-how-it-works)
- [🚀 Setup](#-setup)
- [▶️ Running](#-running)
- [📸 Screenshots](#-screenshots)
- [📄 License](#-license)

## ⚠️ Authorized Use Only

This is a penetration-testing tool. Use it **only** against systems you own or are **explicitly authorized in writing** to test. Unauthorized testing is illegal, and you are responsible for how you use it.

## ✨ Features

| Check | What it detects |
| :--- | :--- |
| 🔏 Unverified signature | Server accepts a token after its signature is tampered with |
| 🚫 `alg: none` | Server accepts an unsigned token (all case variants tried) |
| 🔑 Weak HMAC secret | Guessable signing secret cracked from a wordlist, then reused |
| 🧩 JWK injection | Attacker key embedded in the token's `jwk` header is trusted |
| 🌐 JKU injection | Token's `jku` points at an attacker-hosted key set |
| 📁 KID path traversal | `kid` abused as a file path (e.g. an empty file) |
| 🔁 Algorithm confusion | RSA public key used as an HMAC secret (RS256 to HS256) |

Each finding ships with 🧪 methodology, 🧾 evidence, 📝 reproduction steps, and 🛡️ remediation, exportable to PDF.

## ⚙️ How It Works

- 📋 **Paste a raw request** and jwtpen auto-detects the JWT, with a manual-paste fallback.
- ⚖️ **Baselines, learned automatically**: your valid token shows what "accepted" looks like and a deliberately broken one shows "rejected", so each forged token is judged for you.
- 🎯 **Nothing else changes**: only the token is swapped, so every other cookie, header, and body byte stays exactly as captured.

Checks that need input ask for it when selected: weak-secret takes a wordlist (built-in or your own), JKU injection hands you a key set to host and takes its URL back, KID traversal takes an optional file path, and algorithm confusion auto-discovers the public key or takes a PEM/JWKS URL.

## 🚀 Setup

Requires 🐍 Python 3.11+.

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1      # Windows PowerShell
# source .venv/bin/activate     # macOS / Linux
pip install -r requirements.txt
playwright install chromium     # one-time, for PDF export
```

<details>
<summary>🔒 <strong>Reproducible install (recommended for engagement work)</strong></summary>

`requirements.txt` states the minimum versions jwtpen needs and lets pip pick the newest that
fit, so two people installing a week apart can end up with different builds.
`requirements.lock.txt` pins every package to an exact version with a SHA-256 hash:

```bash
pip install --require-hashes -r requirements.lock.txt
```

`--require-hashes` makes pip refuse any package whose contents do not match the recorded hash,
so a tampered or substituted release fails to install instead of running. Use this when the
tool is going anywhere near a real engagement.

The lock file is generated on Python 3.14. On older supported versions install from
`requirements.txt` instead. Regenerate it after changing a dependency with:

```bash
pip-compile --generate-hashes --output-file=requirements.lock.txt requirements.txt
```

</details>

## ✅ Running the tests

```bash
pytest                  # all 173 tests
pytest -m "not slow"    # skip the PDF render
```

The suite never touches the network and never binds a port: a guard fails any test that
attempts a real request, so running it can't reach a live host by accident. See
[tests/TEST-PLAN.md](tests/TEST-PLAN.md).

## ▶️ Running

```bash
python -m uvicorn jwtpen.webapp.server:app
```

Open 👉 **http://127.0.0.1:8000** (loopback only). Then: 1️⃣ paste the request, 2️⃣ confirm the token, 3️⃣ pick checks, 4️⃣ run and read the report.

## 📸 Screenshots

<p align="center">
  <img src="screenshots/token.png" alt="Token selection" width="85%"><br>
  <em>🔎 Auto-detected JWT candidates, decoded for you to confirm.</em>
</p>

<p align="center">
  <img src="screenshots/checks.png" alt="Check selection" width="85%"><br>
  <em>✅ Pick the checks to run; each shows what setup it needs.</em>
</p>

<p align="center">
  <img src="screenshots/report.png" alt="HTML report" width="85%"><br>
  <em>📊 The report: methodology, evidence, reproduction, and remediation.</em>
</p>

## 📄 License

Released under the [MIT License](LICENSE). 🆓
