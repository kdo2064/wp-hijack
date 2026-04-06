"""
HTML → PDF conversion via Playwright (headless Chromium).

Falls back to reportlab-based PDF if Playwright is not installed.
"""

from __future__ import annotations

import asyncio
import pathlib
import logging

log = logging.getLogger("wp_hijack.telegram.pdf")


async def html_to_pdf_playwright(
    html_path: pathlib.Path,
    pdf_path: pathlib.Path | None = None,
) -> pathlib.Path:
    """
    Render *html_path* to PDF using Playwright (headless Chromium).

    Returns the path of the generated PDF.
    Raises RuntimeError if playwright is not installed.
    """
    html_path = pathlib.Path(html_path)
    if pdf_path is None:
        pdf_path = html_path.with_suffix(".pdf")
    pdf_path = pathlib.Path(pdf_path)
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        from playwright.async_api import async_playwright  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "playwright is not installed. Run: pip install playwright && playwright install chromium"
        ) from exc

    log.info("Rendering %s → %s via Playwright", html_path, pdf_path)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        page = await browser.new_page()

        # Load the HTML file (file:// URI ensures local assets work)
        file_uri = html_path.resolve().as_uri()
        await page.goto(file_uri, wait_until="networkidle", timeout=60_000)

        # Inject print-friendly CSS overrides
        await page.add_style_tag(content=_PRINT_CSS)

        await page.pdf(
            path=str(pdf_path),
            format="A4",
            print_background=True,
            margin={"top": "15mm", "bottom": "15mm", "left": "12mm", "right": "12mm"},
        )
        await browser.close()

    log.info("PDF generated: %s (%.1f KB)", pdf_path, pdf_path.stat().st_size / 1024)
    return pdf_path


# ──────────────────────────────────────────────────────────────────────────────
# Extra CSS injected before printing (improves page breaks, removes nav chrome)
# ──────────────────────────────────────────────────────────────────────────────
_PRINT_CSS = """
@media print {
    nav, .navbar, .sidebar, .toc-float,
    button, .no-print, .toc-fixed { display: none !important; }

    body   { font-size: 11pt; line-height: 1.45; color: #111; background: #fff; }
    h1     { page-break-before: always; font-size: 18pt; }
    h2     { font-size: 14pt; color: #CC2200; }
    h3     { font-size: 12pt; }
    pre, code { font-size: 9pt; background: #f5f5f5; }
    table  { width: 100%; border-collapse: collapse; }
    th, td { border: 1px solid #ccc; padding: 4px 8px; font-size: 9pt; }
    .finding-card, .card { page-break-inside: avoid; }
    a { color: #1a0dab; }
}
/* Make dark themes readable in PDF */
body { background: #fff !important; color: #111 !important; }
.finding-card { border: 1px solid #ddd; margin: 8px 0; padding: 10px; }
"""
