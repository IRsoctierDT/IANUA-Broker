# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Self-contained HTML renderer (ticket T-303).

Emits a single ``.html`` string with **inline** CSS and **no external resource
references** (no CDN, no web fonts, no remote images) — so opening it offline
makes zero network calls (ADR-8, NFR-SEC1). Semantic markup + AA-contrast colors
(NFR-A11Y); core content is readable with no JavaScript.
"""

from __future__ import annotations

from html import escape

from ..domain import Report, Severity
from . import RenderOptions, inert_text
from .common import acceptance_str, location_str, ordered_findings, secret_str, server_grade

# AA-contrast severity colors on a white background.
_SEV_COLOR = {
    Severity.CRITICAL: "#b00020",
    Severity.HIGH: "#a85400",
    Severity.MEDIUM: "#7a5b00",
    Severity.LOW: "#15607a",
    Severity.INFO: "#444444",
}

_STYLE = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
       margin: 0; padding: 2rem; color: #111; background: #fff; line-height: 1.5; }
h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
.grade { display: inline-block; min-width: 2.2rem; padding: .15rem .55rem;
         border-radius: .4rem; font-weight: 700; color: #fff; text-align: center; }
.grade-A { background: #1b7a3d; } .grade-B { background: #3a7a1b; }
.grade-C { background: #7a5b00; } .grade-D { background: #a85400; }
.grade-F { background: #b00020; }
.dims { color: #333; margin: .25rem 0 1.25rem; }
.dims span { margin-right: 1rem; }
.server { border: 1px solid #ddd; border-radius: .5rem; margin: 1rem 0; padding: 1rem; }
.server h2 { font-size: 1.05rem; margin: 0 0 .5rem; word-break: break-all; }
.finding { border-top: 1px solid #eee; padding: .75rem 0; }
.sev { font-weight: 700; }
.meta { color: #333; font-size: .92rem; margin: .15rem 0; }
.meta code { background: #f3f3f3; padding: .05rem .3rem; border-radius: .25rem; }
.empty { color: #1b7a3d; font-weight: 600; }
footer { margin-top: 2rem; color: #555; font-size: .85rem; }
"""


def _safe(text: str) -> str:
    """Escape markup **and** defang invisible controls in an untrusted string.

    ``html.escape`` neutralizes markup, which stops script injection — but it
    leaves bidirectional and zero-width characters intact, and a browser honours
    those. A server name carrying U+202E therefore still reorders what a reviewer
    reads, in the artifact most likely to be forwarded to one. Escaping alone is
    the wrong boundary for a value the scanner does not own; every such value goes
    through :func:`~mcpscan.report.inert_text` first, exactly as it does on the
    terminal, so the two renderers cannot disagree about what "inert" means.
    """
    return escape(inert_text(text))


def _grade_badge(grade: str) -> str:
    g = escape(grade)
    return f'<span class="grade grade-{g}">{g}</span>'


def render_html(report: Report, opts: RenderOptions | None = None) -> str:
    """Render a Report as a single self-contained HTML document."""
    opts = opts or RenderOptions()
    parts: list[str] = []
    parts.append("<!doctype html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append("<title>IANUA-Broker report</title>")
    parts.append(f"<style>{_STYLE}</style></head><body>")
    parts.append("<h1>IANUA-Broker</h1>")
    parts.append(f"<p>Overall posture: {_grade_badge(report.overall_grade)}</p>")

    if report.dimension_grades:
        dims = "".join(
            f"<span>{escape(dim.value)}: {_grade_badge(grade)}</span>"
            for dim, grade in sorted(report.dimension_grades.items(), key=lambda kv: kv[0].value)
        )
        parts.append(f'<div class="dims">{dims}</div>')

    if not any(s.findings for s in report.servers):
        parts.append('<p class="empty">No findings. Your scanned MCP setup looks clean.</p>')

    for server in report.servers:
        if not server.findings:
            continue
        flag = " — inspection incomplete" if server.inspection_incomplete else ""
        parts.append('<section class="server">')
        parts.append(
            f"<h2>{_grade_badge(server_grade(server))} {_safe(server.id)}{escape(flag)}</h2>"
        )
        for finding in ordered_findings(server):
            color = _SEV_COLOR[finding.severity]
            parts.append('<div class="finding">')
            parts.append(
                f'<div class="sev" style="color:{color}">'
                f"{escape(finding.severity.value.upper())} — {_safe(finding.title)}</div>"
            )
            if finding.acceptance is not None:
                parts.append(
                    f'<div class="meta">accept: {_safe(acceptance_str(finding.acceptance))}</div>'
                )
            parts.append(
                f'<div class="meta">where: <code>{_safe(location_str(finding, opts))}</code></div>'
            )
            secret = secret_str(finding.secret, opts)
            if secret is not None:
                parts.append(f'<div class="meta">secret: <code>{_safe(secret)}</code></div>')
            parts.append(f'<div class="meta">why: {_safe(finding.rationale)}</div>')
            parts.append(f'<div class="meta">fix: {_safe(finding.remediation)}</div>')
            parts.append("</div>")
        parts.append("</section>")

    parts.append(
        "<footer>Generated locally and offline by IANUA-Broker. No data left this machine.</footer>"
    )
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"
