"""Local FastAPI app: serves the UI and calls the engine (backend makes requests, no CORS).

The browser is only the UI. Every network request to the target is made HERE, on the backend,
so there are no browser CORS or cookie restrictions. The split of work:

    GET  /            -> the single-page UI (runs scans, shows a pass/fail summary)
    POST /detect      -> find JWT candidates in a pasted request and decode each one
    POST /scan        -> run the selected checks; return the summary findings (no detail)
    GET  /report      -> the full, detailed HTML report of the most recent scan
    GET  /report.pdf  -> that same report rendered to a downloadable PDF

The webapp is "run it and see what's vulnerable"; the detailed write-up (methodology,
evidence, reproduction, references) lives only in the report, opened same-origin from /report.

Run it from the project root with:
    uvicorn jwtpen.webapp.server:app --reload
then open http://127.0.0.1:8000
"""

from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from jwtpen.core.jwt_utils import decode
from jwtpen.core.raw_request import find_jwts, parse_request
from jwtpen.attacks import registry
from jwtpen.attacks.base import Finding, INCONCLUSIVE, MEDIUM, sort_findings
from jwtpen.report.html import render_report
from jwtpen.report.pdf import html_to_pdf

_HERE = Path(__file__).parent
_INDEX = _HERE / "templates" / "index.html"

app = FastAPI(title="jwtpen", description="Local JWT penetration-testing tool.")

# Serve app.js / styles.css under /static/ (referenced by index.html).
app.mount("/static", StaticFiles(directory=_HERE / "static"), name="static")

# The most recent scan's full report HTML, so /report can serve it same-origin and its PDF
# export (later) can reach the backend. Single-user local tool, so one in-memory slot is enough.
_last_report = None


# --- Request bodies. FastAPI validates these from the posted JSON automatically. ---
class DetectRequest(BaseModel):
    raw_request: str = Field(min_length=1)


class ScanRequest(BaseModel):
    raw_request: str = Field(min_length=1)
    token: str = Field(min_length=1)          # the token the user confirmed is the session JWT
    scheme: Literal["http", "https"] = "https"
    checks: list[str] = Field(min_length=1)   # registry names to run, e.g. ["none_algorithm"]
    # Wordlist settings for the weak_secret check: an uploaded/pasted list, plus whether to
    # include the built-in one. Ignored by checks that don't use a wordlist.
    wordlist: str | None = None
    use_builtin_wordlist: bool = True
    # Per-check settings keyed by check name, for checks that need their own inputs: e.g.
    # jku_injection: {"jku_url", "private_key_pem", "kid"} from the /prepare step. weak_secret
    # keeps its top-level wordlist fields above; checks that need nothing extra have no entry.
    check_options: dict[str, dict] = Field(default_factory=dict)


@app.get("/")
def index():
    """Serve the UI page."""
    return FileResponse(_INDEX)


@app.get("/checks")
def checks():
    """List the available checks (name + title), so the UI builds its list from the engine."""
    return {"checks": registry.list_checks()}


@app.post("/detect")
def detect(req: DetectRequest):
    """Find every JWT in the pasted request and decode each, so the user can pick the real one.

    We keep the raw token string AND its decoded header/payload. A candidate that fails to
    decode (malformed payload) is still listed with an error, so the user can fall back to
    choosing it manually.
    """
    candidates = []
    for token in _unique_preserving_order(find_jwts(req.raw_request)):
        entry = {"token": token}
        try:
            header, payload, signature = decode(token)
            entry["header"] = header
            entry["payload"] = payload
            entry["has_signature"] = signature != ""
        except Exception as exc:  # malformed but regex-shaped; let the UI still offer it
            entry["error"] = str(exc)
        candidates.append(entry)
    return {"candidates": candidates}


@app.post("/prepare/{name}")
def prepare(name: str):
    """Generate the material a check needs the tester to host before it can run (jku_injection).

    jku injection can't forge a token until there's a key set hosted at a URL the target can
    reach, and only the tester knows where that is. So here the backend generates the keypair
    and returns the JWK Set text to host plus the private key (which rides back in the scan's
    check_options so the forged token is signed by the key that matches the hosted public half).
    """
    try:
        module = registry.get(name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    generate = getattr(module, "generate_material", None)
    if generate is None:
        raise HTTPException(status_code=404, detail=f"Check '{name}' has nothing to prepare.")
    material = generate()
    # Only what the UI needs: the text to host, the kid it names, and the private key to send back.
    return {k: material[k] for k in ("kid", "jwks_text", "private_key_pem")}


@app.post("/scan")
def scan(req: ScanRequest):
    """Run each selected check and return a summary (status + name) for the UI.

    The full detail is rendered into the report once and stashed for /report to serve; the
    UI only needs enough to show which checks are vulnerable.
    """
    global _last_report

    # weak_secret needs candidate secrets: reject a run that selects it with no source at all
    # (built-in list turned off and nothing supplied), matching the UI's own guard.
    if "weak_secret" in req.checks and not req.use_builtin_wordlist and not (req.wordlist or "").strip():
        raise HTTPException(
            status_code=422,
            detail="The weak_secret check needs a wordlist: enable the built-in list or supply one.",
        )

    findings = []
    for name in req.checks:
        findings.append(_run_one(name, req, _options_for(name, req)))
    findings = sort_findings(findings)   # confirmed problems first, so the reader sees them first

    target = _target_host(req.raw_request)
    _last_report = render_report(findings, target=target)
    return {
        "target": target,
        "findings": [{"attack": f.attack, "status": f.status} for f in findings],
    }


@app.get("/report", response_class=HTMLResponse)
def report():
    """Serve the full report for the most recent scan (same-origin, so PDF export can reach us)."""
    if _last_report is None:
        return HTMLResponse(
            "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<title>jwtpen report</title></head><body style='font-family:system-ui;"
            "max-width:40rem;margin:4rem auto;padding:0 1.25rem;color:#181b21'>"
            "<h1 style='font-size:1.3rem'>No report yet</h1>"
            "<p>Run a scan in jwtpen, then open the detailed report from the Findings panel.</p>"
            "</body></html>"
        )
    return HTMLResponse(_last_report)


@app.get("/report.pdf")
def report_pdf():
    """Render the most recent report to PDF and return it as a download.

    Same single source as /report: we hand the stored report HTML to the Playwright renderer,
    so the PDF is identical to the on-screen report's print form. This is a sync endpoint, so
    FastAPI runs it in a worker thread where Playwright's sync API is free to spin its own loop.
    """
    if _last_report is None:
        raise HTTPException(status_code=404, detail="No report yet. Run a scan first.")
    pdf_bytes = html_to_pdf(_last_report)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="jwtpen-report.pdf"'},
    )


# --- small helpers ---------------------------------------------------------
def _options_for(name, req):
    """Pick the settings dict to pass to one check's run().

    weak_secret reads its wordlist from the top-level fields (kept for back-compat with the UI);
    every other check that needs inputs reads them from check_options[name] (jku_injection's
    hosted-key-set URL and key). Checks that need nothing get None and ignore it.
    """
    if name == "weak_secret":
        return {"wordlist": req.wordlist, "use_builtin": req.use_builtin_wordlist}
    return req.check_options.get(name)


def _run_one(name, req, options):
    """Run a single check, turning any failure into an INCONCLUSIVE finding.

    One check hitting a network error (target down, timeout) shouldn't abort the whole scan,
    and an unknown check name shouldn't 500 the request, both come back as a finding the
    report can show honestly. `options` carries per-check settings (e.g. the wordlist).
    """
    try:
        return registry.run_check(name, req.raw_request, req.token, req.scheme, options)
    except Exception as exc:
        title = _title_for(name)
        return Finding(
            attack=title,
            status=INCONCLUSIVE,
            severity=MEDIUM,
            summary=f"This check could not be completed: {exc}",
            methodology=[f"Attempted to run '{title}' but it raised: {type(exc).__name__}: {exc}"],
        )


def _title_for(name):
    """Best-effort display title for a check name (falls back to the raw name)."""
    for check in registry.list_checks():
        if check["name"] == name:
            return check["title"]
    return name


def _target_host(raw_request):
    """Pull the Host header out of the request for the report header; '(unknown)' if absent."""
    try:
        return parse_request(raw_request)["headers"].get("Host", "(unknown)")
    except Exception:
        return "(unknown)"


def _unique_preserving_order(items):
    """De-duplicate while keeping first-seen order (a token may appear in several headers)."""
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
