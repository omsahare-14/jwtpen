# jwtpen Test Plan

How this project is tested, what each layer is responsible for, and which cases are automated
versus checked by hand.

## Ground rules

1. **The suite never touches the network.** `conftest.py` installs an autouse guard that fails
   any test attempting a real outbound request. A tool that forges credentials must not be able
   to fire at a live host because someone ran `pytest`. `SEC-12` proves the guard works.
2. **No port is ever bound.** API tests drive the ASGI app in-process through `TestClient`.
3. **The target is simulated, the logic is real.** Only `send` is replaced. Forging, request
   rebuilding, baseline comparison and classification all execute for real.
4. **Tests are additive.** The suite does not modify application code or behaviour.

## Running

```bash
pytest                      # everything
pytest tests/test_smoke.py  # fastest signal, run this first
pytest -m "not slow"        # skip the PDF render
```

## Layers

| Layer | File | Question it answers |
| :--- | :--- | :--- |
| Smoke | `test_smoke.py` | Is the build alive at all? |
| Unit | `test_unit_core.py`, `test_jwt_utils.py`, `test_keys.py`, `test_attacks.py` | Is each function correct in isolation? |
| Functional | `test_functional.py` | Does it do what the product promises? |
| Integration | `test_integration_attacks.py` | Do the parts work together against a server? |
| System | `test_system_api.py` | Does the assembled app work through its API? |
| UAT | `test_uat.py` | Can a pentester actually do their job? |
| Security | `test_security.py` | Do the safety properties hold? |
| Regression | `test_regression.py` | Have fixed defects stayed fixed? |
| UI | `test_ui_static.py` | Is the interface wired up and accessible? |
| Usability | `test_ui_static.py` + manual | Is it understandable and safe to operate? |

---

## SM: Smoke

| ID | Case | Expected |
| :--- | :--- | :--- |
| SM-01 | Import every module | No import error |
| SM-02 | FastAPI app object exists | Title is `jwtpen` |
| SM-03 | Registry lists all seven checks | Exact expected order |
| SM-04 | Each check exposes `NAME`, `DESCRIPTION`, `run()` | Contract satisfied |
| SM-05 | Built-in wordlist loads | Non-empty, count matches |
| SM-06 | RSA keypair generates and round-trips | PEM identical |
| SM-07 | Report renders | Valid HTML document |
| SM-08 | Unknown check name | `KeyError` naming the known checks |

## UT: Unit

| ID | Case | Expected |
| :--- | :--- | :--- |
| UT-01 | Parse method, path, headers | Fields extracted |
| UT-02 | Header value containing a colon | Only first colon splits |
| UT-03 | Body after the blank line | Body preserved |
| UT-04 | Request with no body | Empty body |
| UT-05 | CRLF and LF input | Parse identically |
| UT-06 | Detect session token | Token found |
| UT-07 | Dotted non-tokens (`15.14.13`) | Not matched |
| UT-08 | Unsigned token with trailing dot | Still detected |
| UT-09 | Multiple tokens | All, in order |
| UT-10 | Swap every occurrence | All replaced |
| UT-11 | Swap leaves rest byte-identical | Reversible |
| UT-12 | Identical responses | `resembles` true |
| UT-13 | Differing status | `resembles` false |
| UT-14 | Small volatile diff (CSRF token) | Still resembles |
| UT-15 | Logged-in vs rejected page | Never resemble |
| UT-16 | Classify accepted / rejected / neither | Correct verdict |
| UT-17 | Indistinguishable baselines | `INCONCLUSIVE` |
| UT-18 | Decode a valid token | Header, payload, signature |
| UT-19 | Malformed tokens | `ValueError` |

## FT: Functional

| ID | Case | Expected |
| :--- | :--- | :--- |
| FT-01 | Seven distinct checks offered | All present, unique titles |
| FT-02 | Detection validates, not just dot-matching | Lookalikes rejected |
| FT-03 | Forging preserves the payload | Claims unchanged |
| FT-04 | Only the token changes on resend | Rest of request identical |
| FT-05 | http and https both supported | Correct target URL |
| FT-06 | Confirmed finding is complete | Methodology, reproduction, remediation, references, evidence |
| FT-07 | References are OWASP or IETF only | No third-party write-ups |
| FT-08 | Hosted key material is fresh each time | New kid and key per preparation |
| FT-09 | Inapplicable check on an RS256 token | `SKIPPED`, not failed |

## IT: Integration

| ID | Case | Expected |
| :--- | :--- | :--- |
| IT-01 | alg:none against a vulnerable server | `VULNERABLE`, variant recorded |
| IT-02 | alg:none against a secure server | `NOT_VULNERABLE`, 16 casings tried |
| IT-03 | alg:none with identical baselines | `INCONCLUSIVE` |
| IT-04 | All 16 case spellings generated | none/None/NONE/nOnE present |
| IT-05 | Unverified signature, vulnerable | `VULNERABLE` |
| IT-06 | Unverified signature, secure | `NOT_VULNERABLE` |
| IT-07 | Weak secret in built-in list | Cracked, `VULNERABLE` |
| IT-08 | Strong secret | `NOT_VULNERABLE` |
| IT-09 | RS256 token | `SKIPPED` |
| IT-10 | User-supplied wordlist | Cracked |
| IT-11 | No secrets available | `INCONCLUSIVE` |
| IT-12 | JWK injection, secure server | `NOT_VULNERABLE` |
| IT-13 | JWK injection, server trusts embedded key | `VULNERABLE` |
| IT-14 | JKU with no hosted URL | `INCONCLUSIVE`, nothing sent |
| IT-15 | KID traversal, secure server | No false positive |
| IT-16 | RS256 to HS256 confusion, vulnerable | `VULNERABLE` |
| IT-17 | Algorithm confusion with no key | `INCONCLUSIVE` |
| IT-18 | Every finding satisfies the report contract | Attack, status, severity, summary |

## ST: System (through the HTTP API)

| ID | Case | Expected |
| :--- | :--- | :--- |
| ST-01 | `GET /` | 200 HTML |
| ST-02 | Static assets | 200 |
| ST-03 | `GET /checks` | All seven, titled |
| ST-04 | Per-check UI flags | Wordlist, hosted JWKS, pubkey flags correct |
| ST-05 | `POST /detect` | Token found and decoded |
| ST-06 | Detect with no token | Empty list |
| ST-07 | Detect duplicates | De-duplicated, order kept |
| ST-08 | Detect empty request | 422 |
| ST-09 | `POST /scan` vulnerable | Verdict returned, report stored |
| ST-10 | Multi-check scan | One finding per check |
| ST-11 | Summary carries no detail | Only attack and status |
| ST-12 | Unknown check name | `INCONCLUSIVE`, not a 500 |
| ST-13 | weak_secret with no wordlist | 422 |
| ST-14 | Invalid scheme / empty fields | 422 |
| ST-15 | `/report` before a scan | Friendly placeholder |
| ST-16 | `/report.pdf` before a scan | 404 |
| ST-17 | `POST /prepare/jku_injection` | kid, JWKS text, private key |
| ST-18 | Prepare a check with nothing to prepare | 404 |
| ST-19 | PDF export after a scan | `%PDF-` bytes, attachment header |

## UAT: User acceptance

| ID | Scenario | Expected |
| :--- | :--- | :--- |
| UAT-01 | Find a flaw and produce a client-ready report | Verdict plus reproduction and remediation |
| UAT-02 | Scan a hardened target | All clean |
| UAT-03 | Ambiguous endpoint | Told plainly that no verdict is trustworthy |
| UAT-04 | Recover a guessable secret | Secret shown as proof |
| UAT-05 | Bring your own wordlist | Cracked |
| UAT-06 | Prepare hosted material for JKU | Hostable key set and matching private key |
| UAT-07 | Run all checks at once | One finding each, no crash |
| UAT-08 | Reporting order | Confirmed problems first |

## SEC: Security

| ID | Case | Expected |
| :--- | :--- | :--- |
| SEC-01 | Target response containing `<script>` | Escaped in the report |
| SEC-02 | Hostile target name | Escaped |
| SEC-03 | Backtick code spans | Only `<code>` emitted |
| SEC-04 | Script inside backticks | Escaped |
| SEC-05 | Unbalanced backtick | No dangling tag |
| SEC-06 | TLS verification | `verify=True` |
| SEC-07 | Content-Length stripped | Body cannot be truncated |
| SEC-08 | Redirects not followed | Our response is judged |
| SEC-09 | Import does not disable TLS warnings | Global state untouched |
| SEC-10 | Frontend error rendering | Text, never markup |
| SEC-11 | Wordlist is text, not a path | No file is opened |
| SEC-12 | No report before a scan | Nothing served |
| SEC-13 | Scan response carries no credentials | No token or private key |
| SEC-14 | Network guard active | Offline guarantee proven |

## RG: Regression

| ID | Original defect | Guard |
| :--- | :--- | :--- |
| RG-01 | `public_key_to_jwk` emitted `alg`/`use` when unset | Omitted when `None` |
| RG-02 | `checker.py` disabled TLS warnings process-wide on import | No `urllib3` reference |
| RG-03 | `requirements.txt` listed `urllib3`, filed `cryptography` as unused | Reflects real imports |
| RG-04 | Error text spliced into HTML and `document.write`n | `writeErrorTab` only |
| RG-05 | Docstring claimed warnings were silenced elsewhere | Phrase absent repo-wide |
| RG-06 | Stale `Content-Length` after token swap | Still stripped |

## UI and US: Interface and usability

| ID | Case | Expected |
| :--- | :--- | :--- |
| UI-01 | Every id `app.js` looks up exists in `index.html` | Contract holds |
| UI-02 | Page loads its own script and stylesheet | Referenced |
| UI-03 | Referenced static files exist | Present on disk |
| UI-04 | Scheme toggle present | http and https |
| UI-05 | `lang` and charset declared | Present |
| UI-06 | Viewport meta | Responsive |
| UI-07 | Document title | Non-empty |
| UI-08 | Reduced-motion respected | Media query present |
| UI-09 | Report is standalone | Doctype to `</html>` |
| UI-10 | Report shows findings and verdicts | Plain-language status |
| UI-11 | Report section headings | Reader-facing wording |
| UI-12 | Report has no external dependencies | Renders offline |
| UI-13 | PDF export control present | `export-pdf` |
| UI-14 | Report with zero findings | Still readable |
| US-01 | Authorized-use rule on screen | Stated in the UI |
| US-02 | Numbered step flow | Request, Token, Checks, Report |
| US-03 | Manual token fallback | Always available |

---

## Manual test cases

These need a human and an **authorized** target. Do not run them against anything you lack
written permission to test.

| ID | Case | How to verify |
| :--- | :--- | :--- |
| M-01 | Burp paste round-trip | Copy a real request from Burp, confirm the JWT is detected and correctly identified |
| M-02 | Detection fallback | Paste a request whose token is non-standard, confirm manual entry works |
| M-03 | PDF fidelity | Export the PDF, confirm it matches the on-screen report and all findings are expanded |
| M-04 | Copy buttons | Click each evidence copy control, confirm the exact value including PEM newlines |
| M-05 | Real lab confirmation | Run against an authorized vulnerable lab, confirm the reproduction steps work by hand |
| M-06 | Long scan feedback | Confirm the report tab shows the loading state and never a blank tab |
| M-07 | Error presentation | Stop the target mid-scan, confirm the failure is readable and the tool recovers |
| M-08 | Keyboard navigation | Tab through the whole flow without a mouse |
| M-09 | Screen reader pass | Confirm step changes and verdicts are announced |
| M-10 | Self-signed target | Confirm the TLS failure is explained rather than silently inconclusive |
