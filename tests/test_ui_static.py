"""USER INTERFACE and USABILITY tests against the shipped frontend and the rendered report.

These cannot click buttons, but they pin the things that silently break a UI: the contract
between app.js and index.html, accessibility basics, and the safety wording a tool like this
must always show. See tests/TEST-PLAN.md (UI-* and US-*).
"""

import re
from pathlib import Path

import pytest

from jwtpen.report.html import render_report
from jwtpen.attacks.base import Finding, HIGH, NOT_VULNERABLE, VULNERABLE

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEBAPP = PROJECT_ROOT / "jwtpen" / "webapp"
INDEX_HTML = (WEBAPP / "templates" / "index.html").read_text(encoding="utf-8")
APP_JS = (WEBAPP / "static" / "app.js").read_text(encoding="utf-8")
STYLES_CSS = (WEBAPP / "static" / "styles.css").read_text(encoding="utf-8")


# --- UI-01..03: the JS/HTML contract --------------------------------------------------------
def test_every_element_app_js_looks_up_exists_in_the_page():
    """A renamed id would break the UI at runtime with no error until a user clicks."""
    needed = set(re.findall(r'getElementById\("([^"]+)"\)', APP_JS))
    present = set(re.findall(r'id="([^"]+)"', INDEX_HTML))
    assert needed <= present, f"app.js looks up ids that index.html does not define: {needed - present}"


def test_the_page_loads_the_scripts_and_styles_it_ships():
    assert "/static/app.js" in INDEX_HTML
    assert "/static/styles.css" in INDEX_HTML


@pytest.mark.parametrize("asset", ["app.js", "styles.css"])
def test_referenced_static_files_exist_on_disk(asset):
    assert (WEBAPP / "static" / asset).is_file()


def test_the_scheme_toggle_offers_http_and_https():
    assert 'id="scheme-http"' in INDEX_HTML
    assert 'id="scheme-https"' in INDEX_HTML


# --- UI-04..07: accessibility and document basics -------------------------------------------
def test_the_page_declares_a_language_and_character_set():
    assert re.search(r'<html[^>]*\blang="[a-z]{2}', INDEX_HTML)
    assert re.search(r'charset=["\']?utf-8', INDEX_HTML, re.I)


def test_the_page_is_responsive():
    assert re.search(r'name="viewport"', INDEX_HTML)


def test_the_page_has_a_title():
    assert re.search(r"<title>\s*\S", INDEX_HTML)


def test_the_interface_respects_reduced_motion():
    """Animation must be optional: a spinner that cannot be stopped is an accessibility failure."""
    assert "prefers-reduced-motion" in STYLES_CSS or "prefers-reduced-motion" in APP_JS


# --- US-01..03: usability and safety wording ------------------------------------------------
def test_the_ui_states_the_authorized_use_rule():
    """A tool that forges credentials must say so on screen, not only in the README."""
    assert re.search(r"authori[sz]ed", INDEX_HTML, re.I)


def test_the_ui_guides_the_user_through_numbered_steps():
    for label in ("Request", "Token", "Checks", "Report"):
        assert label in INDEX_HTML


def test_the_ui_offers_a_manual_token_fallback():
    """Detection can fail; the user must always be able to paste the token by hand."""
    assert 'id="manual-token"' in INDEX_HTML
    assert 'id="btn-manual"' in INDEX_HTML


# --- UI-08..12: the rendered report ---------------------------------------------------------
def _sample_findings():
    return [
        Finding(attack="Unsigned Token Accepted (alg: none)", status=VULNERABLE, severity=HIGH,
                summary="The server accepted an unsigned token.",
                methodology=["Set alg to none."], reproduction=["Decode the token."],
                evidence={"Target URL": "https://target.test/my-account"},
                remediation="Reject the none algorithm.",
                references=[{"label": "RFC 7519", "url": "https://example.test/rfc7519"}]),
        Finding(attack="Signature Not Verified", status=NOT_VULNERABLE, severity=HIGH,
                summary="The server rejected the tampered token."),
    ]


def test_the_report_is_a_complete_standalone_document():
    html = render_report(_sample_findings(), target="target.test")
    assert html.lstrip().lower().startswith("<!doctype html")
    assert "</html>" in html.strip()[-20:]


def test_the_report_shows_every_finding_and_its_verdict():
    html = render_report(_sample_findings(), target="target.test")
    assert "Unsigned Token Accepted" in html
    assert "Signature Not Verified" in html
    # Verdicts are shown in plain language rather than the internal constant.
    assert "Vulnerable" in html
    assert "Not vulnerable" in html


def test_the_report_presents_the_sections_a_tester_needs():
    """Section headings are written for a reader, so assert the wording the report actually uses."""
    html = render_report(_sample_findings(), target="target.test").lower()
    for section in ("what the tool did", "how to reproduce", "evidence", "remediation"):
        assert section in html


def test_the_report_leads_with_a_count_of_what_was_found():
    html = render_report(_sample_findings(), target="target.test")
    assert "1 Vulnerability Found" in html


def test_the_report_carries_no_external_dependencies():
    """It must render identically offline and in the PDF export, so nothing may be fetched."""
    html = render_report(_sample_findings(), target="target.test")
    body = re.sub(r'href="https?://[^"]+"[^>]*>', "", html)   # reference links are allowed
    assert not re.search(r'<(script|link|img)[^>]+(src|href)="https?://', body)


def test_the_report_offers_pdf_export():
    html = render_report(_sample_findings(), target="target.test")
    assert "export-pdf" in html


def test_the_report_renders_with_no_findings_at_all():
    """An empty scan must still produce a readable document, not a broken page."""
    html = render_report([], target="target.test")
    assert "<!doctype html" in html.lower()
    assert "target.test" in html
