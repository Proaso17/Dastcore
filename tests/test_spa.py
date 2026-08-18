"""C6: SPA / JS-framework awareness — detect a browser-rendered frontend and advise headless."""

from __future__ import annotations

from dastcore.core.models import HttpResponse
from dastcore.detectors.spa import detect_js_framework, run_spa_check


def _resp(text: str = "", headers: dict[str, str] | None = None) -> HttpResponse:
    return HttpResponse(method="GET", status_code=200, headers=headers or {}, text=text, url="http://t/")


def test_detects_nextjs_from_body() -> None:
    assert detect_js_framework(_resp('<div id="__next"></div><script>__NEXT_DATA__={}</script>')) == "Next.js"


def test_detects_nextjs_from_header() -> None:
    assert detect_js_framework(_resp(headers={"X-Powered-By": "Next.js"})) == "Next.js"


def test_detects_generic_spa_shell() -> None:
    body = '<div id="root"></div><script type="module" src="/assets/index.js"></script>'
    assert detect_js_framework(_resp(body)) == "SPA (JavaScript)"


def test_plain_server_rendered_html_is_not_a_spa() -> None:
    assert detect_js_framework(_resp("<html><body><h1>Hola</h1><p>contenido real</p></body></html>")) is None


class _FakeClient:
    def __init__(self, response: HttpResponse) -> None:
        self._response = response

    def is_in_scope(self, url: str) -> bool:
        return True

    async def get(self, url: str) -> HttpResponse:
        return self._response


async def test_advises_headless_when_scanning_static_only() -> None:
    client = _FakeClient(_resp('<div id="__next"></div>'))
    findings = await run_spa_check(client, "http://app.test/", "http")  # type: ignore[arg-type]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "spa-detected" and finding.severity == "info"
    assert "--engine headless" in finding.remediation  # the advisory tells the user what to do
    assert "limitada" in finding.name  # flagged as a coverage gap


async def test_no_headless_advisory_when_already_using_headless() -> None:
    client = _FakeClient(_resp('<div id="__next"></div>'))
    findings = await run_spa_check(client, "http://app.test/", "both")  # type: ignore[arg-type]
    assert len(findings) == 1
    assert "Vuelve a escanear" not in findings[0].remediation  # already covered, no re-scan advice
