"""Report renderers: turn a list of Findings into JSON, SARIF 2.1.0, or self-contained HTML."""

from dastcore.report.html import render_html
from dastcore.report.json import render_json
from dastcore.report.sarif import render_sarif

__all__ = ["render_json", "render_sarif", "render_html"]
