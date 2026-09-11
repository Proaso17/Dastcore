"""Optional LLM report polishing: improves the prose of an already-confirmed draft, never the facts, and
is fail-open — any error, refusal, or degenerate result returns the deterministic draft byte-for-byte, so
the layer is never on the critical path. The client is faked (no network)."""

from __future__ import annotations

from dastcore.bugbounty.ai_report import AiReportWriter, build_report_writer

_DRAFT = (
    "# SQL Injection on api.acme.com\n\n## Summary\nSe identificó SQL Injection en `id`.\n\n"
    "## Steps To Reproduce\n```bash\ncurl -i 'https://api.acme.com/p?id=1%27'\n```\n\n## Impact\nLectura de datos.\n"
)


class _Block:
    def __init__(self, text: str) -> None:
        self.type = "text"
        self.text = text


class _Resp:
    def __init__(self, text: str, stop_reason: str | None = None) -> None:
        self.content = [_Block(text)]
        self.stop_reason = stop_reason


class _FakeClient:
    """Exposes the Anthropic ``messages.create`` shape; returns a fixed response or raises."""

    def __init__(self, resp: _Resp | None = None, exc: Exception | None = None) -> None:
        self._resp = resp
        self._exc = exc
        self.calls: list[dict] = []

    @property
    def messages(self) -> _FakeClient:
        return self

    def create(self, **kwargs: object) -> _Resp:
        self.calls.append(kwargs)
        if self._exc is not None:
            raise self._exc
        assert self._resp is not None
        return self._resp


async def test_polish_returns_the_llm_prose_when_valid() -> None:
    polished = _DRAFT.replace("Lectura de datos.", "Un atacante puede leer datos arbitrarios de la base de datos.")
    writer = AiReportWriter(_FakeClient(_Resp(polished)))
    out = await writer.polish_draft(_DRAFT)
    assert out == polished.strip()  # polish_draft strips surrounding whitespace
    assert writer._client.calls[0]["system"].startswith("You are an editor")  # noqa: SLF001
    assert _DRAFT in writer._client.calls[0]["messages"][0]["content"]  # noqa: SLF001 — draft handed to the LLM


async def test_polish_is_fail_open_on_error() -> None:
    writer = AiReportWriter(_FakeClient(exc=RuntimeError("network down")))
    assert await writer.polish_draft(_DRAFT) == _DRAFT  # facts survive: the deterministic draft is returned


async def test_polish_rejects_a_degenerate_short_result() -> None:
    writer = AiReportWriter(_FakeClient(_Resp("oops")))  # far shorter than the draft → not trusted
    assert await writer.polish_draft(_DRAFT) == _DRAFT


async def test_polish_returns_draft_on_refusal() -> None:
    writer = AiReportWriter(_FakeClient(_Resp("irrelevant", stop_reason="refusal")))
    assert await writer.polish_draft(_DRAFT) == _DRAFT


def test_build_report_writer_is_none_without_a_key(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert build_report_writer(None) is None  # gated: no key, no LLM layer
