"""Render the HTML report from a list of Findings, using a Jinja2 template.

Pure rendering: it takes Finding objects (produced by the attacks) plus a little context and
returns a complete, SELF-CONTAINED HTML string (all CSS inline, no external calls) so the
report opens anywhere and converts to a pixel-identical PDF later (via report/pdf.py).
"""

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup, escape

from jwtpen.attacks.base import (
    VULNERABLE, NOT_VULNERABLE, INCONCLUSIVE, SKIPPED, HIGH, MEDIUM, LOW, sort_findings,
)

_TEMPLATE_DIR = Path(__file__).parent / "templates"

# autoescape is important: findings contain live response data and forged tokens, so we must
# HTML-escape every value to keep the layout safe and intact.
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def _inline_code(text):
    """Render `backtick`-wrapped spans in a string as <code>, escaping everything else.

    Findings write shell commands between backticks (e.g. `hashcat -m 16500 ...`); this turns
    those into real inline code in the report. Everything is HTML-escaped, so it stays safe for
    live response data. An unbalanced backtick is left as literal text rather than risking a
    dangling tag.
    """
    text = str(text)
    if text.count("`") % 2 != 0:
        return escape(text)
    # split() on the backtick alternates plain / code / plain / code ...; odd pieces are code.
    pieces = [f"<code>{escape(part)}</code>" if i % 2 else str(escape(part))
              for i, part in enumerate(text.split("`"))]
    return Markup("".join(pieces))


_env.filters["inline_code"] = _inline_code


def _summary(findings):
    """Count findings by status, for the at-a-glance section. Returns display-ready rows."""
    counts = {
        VULNERABLE: sum(1 for f in findings if f.status == VULNERABLE),
        NOT_VULNERABLE: sum(1 for f in findings if f.status == NOT_VULNERABLE),
        INCONCLUSIVE: sum(1 for f in findings if f.status == INCONCLUSIVE),
        SKIPPED: sum(1 for f in findings if f.status == SKIPPED),
    }
    # (label, count, css-key): css-key matches the status classes in the template.
    return {
        "total": len(findings),
        "rows": [
            ("Vulnerable", counts[VULNERABLE], "vulnerable"),
            ("Not vulnerable", counts[NOT_VULNERABLE], "not-vulnerable"),
            ("Inconclusive", counts[INCONCLUSIVE], "inconclusive"),
            ("Skipped", counts[SKIPPED], "skipped"),
        ],
    }


def _verdict(findings):
    """Compute the headline risk verdict for the overview panel."""
    vulnerable = [f for f in findings if f.status == VULNERABLE]
    if vulnerable:
        rank = {HIGH: 3, MEDIUM: 2, LOW: 1}
        worst = max(vulnerable, key=lambda f: rank.get(f.severity, 0)).severity
        n = len(vulnerable)
        return {
            "level": "vulnerable",
            "headline": f"{n} Vulnerability Found" if n == 1 else f"{n} Vulnerabilities Found",
            "detail": f"Highest severity: {worst}. Review and remediate the findings below.",
        }
    if any(f.status == INCONCLUSIVE for f in findings):
        return {
            "level": "inconclusive",
            "headline": "No Confirmed Vulnerabilities",
            "detail": "Some checks were inconclusive and need manual verification.",
        }
    return {
        "level": "not-vulnerable",
        "headline": "No Vulnerabilities Found",
        "detail": "Every check passed against the tested endpoint.",
    }


def render_report(findings, target, scan_time=None):
    """Return the complete HTML report as a string."""
    if scan_time is None:
        scan_time = datetime.now()
    findings = sort_findings(findings)   # confirmed problems first, so the reader sees them first
    template = _env.get_template("report.html")
    return template.render(
        findings=findings,
        target=target,
        scan_time=scan_time,
        summary=_summary(findings),
        verdict=_verdict(findings),
    )
