"""Report renderers: turn a list of Findings into JSON, SARIF 2.1.0, HTML, or Markdown."""

from dastcore.report.html import render_html
from dastcore.report.json import render_json
from dastcore.report.markdown import render_markdown, render_markdown_diff
from dastcore.report.sarif import render_sarif

__all__ = ["render_json", "render_sarif", "render_html", "render_markdown", "render_markdown_diff"]
