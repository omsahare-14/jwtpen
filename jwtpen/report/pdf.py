"""Export the HTML report to PDF via headless Chrome (Playwright).

The PDF is produced from the SAME self-contained HTML string that render_report() returns
(report/html.py), not from a browser's print dialog. We drive headless Chromium, emulate
PRINT media so the template's own `@media print` block applies (white paper, collapsed
findings forced open, toolbar/markers hidden, `@page` margins), and let the page's CSS
decide the paper size. One HTML source in, a matching PDF out.

Requires the Chromium browser binary, installed once with:  playwright install chromium
"""

from pathlib import Path

from playwright.sync_api import sync_playwright


def html_to_pdf(html: str) -> bytes:
    """Render a self-contained HTML report string to PDF bytes."""
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            page = browser.new_page()
            # The HTML is fully inline (no external CSS/fonts/images), so set_content needs no
            # network; "load" is enough to know rendering is complete.
            page.set_content(html, wait_until="load")
            # On screen the findings are collapsible <details>; on paper every finding must be
            # fully visible. Chromium keeps closed <details> content out of the PDF regardless of
            # CSS, so open them for real before rendering rather than relying on a print rule.
            page.eval_on_selector_all("details", "els => els.forEach(d => (d.open = true))")
            # Apply the template's @media print rules, so the PDF matches the report's paper form.
            page.emulate_media(media="print")
            return page.pdf(
                print_background=True,      # keep the colored verdict/status panels
                prefer_css_page_size=True,  # honour the template's @page size + margins
            )
        finally:
            browser.close()


def write_pdf(html: str, out_path) -> Path:
    """Render the report HTML to a .pdf file and return its path."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(html_to_pdf(html))
    return out_path
