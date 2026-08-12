"""AI-assisted payload generation (module 15 extension). The AI proposes context-aware payloads
when input reflects but the declared payloads don't fire; the rule's ORACLE still confirms every
one — the AI never confirms. Covered: the generator's parsing/dedup + graceful no-key path, and
the scanner path (an AI payload confirmed by the oracle is flagged; an inert AI payload is not;
without a generator there is no AI path)."""

from __future__ import annotations

from types import SimpleNamespace

from dastcore.ai.payload_gen import AiPayloadGenerator, build_payload_generator
from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.engine.rule_engine import Rule
from dastcore.engine.scanner import Scanner
from dastcore.validation.oracles import OracleCheck, OracleSpec

_AI_MARKER = "AI_ORACLE_MARKER"
_MAGIC = "MAGIC-AI-PAYLOAD"


# --- generator (fake Anthropic client, no network) -------------------------------------


class _FakeClient:
    def __init__(self, payloads: list[str], *, stop_reason: str = "end_turn") -> None:
        import json

        self._text = json.dumps({"payloads": payloads})
        self._stop_reason = stop_reason
        self.messages = SimpleNamespace(create=lambda **kw: self._resp())

    def _resp(self):
        return SimpleNamespace(stop_reason=self._stop_reason, content=[SimpleNamespace(type="text", text=self._text)])


async def test_generator_parses_and_drops_already_tried() -> None:
    gen = AiPayloadGenerator(_FakeClient(['"><svg onload=alert(1)>', "x", '"><img src=x onerror=alert(1)>']))
    out = await gen.suggest("xss", "attribute", '<input value="dc123">', tried=["x"])
    assert "x" not in out  # already tried → dropped
    assert '"><svg onload=alert(1)>' in out


async def test_generator_refusal_yields_no_payloads() -> None:
    gen = AiPayloadGenerator(_FakeClient(["whatever"], stop_reason="refusal"))
    assert await gen.suggest("xss", "attribute", "snippet", tried=[]) == []


def test_build_generator_without_key_is_none(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert build_payload_generator() is None


# --- scanner AI path (reflecting fake client, stub generator) --------------------------


class _ReflectingClient:
    """Echoes the injected query value into an HTML body; only the magic AI payload also
    produces the oracle marker — so the declared payload never fires but the AI one does."""

    def __init__(self) -> None:
        self.seen_values: list[str] = []

    async def request(self, method: str, url: str, *, params=None, **kwargs) -> HttpResponse:
        value = (params or {}).get("q", "")
        self.seen_values.append(value)
        body = f"<div>{value}</div>"
        if value == _MAGIC:
            body += f"<!-- {_AI_MARKER} -->"
        return HttpResponse(status_code=200, headers={}, text=body, elapsed_ms=1.0, url=url)


class _StubGenerator:
    def __init__(self, payloads: list[str]) -> None:
        self._payloads = payloads
        self.calls = 0

    async def suggest(self, family: str, context: str, excerpt: str, tried: list[str]) -> list[str]:
        self.calls += 1
        return list(self._payloads)


def _reflect_rule() -> Rule:
    return Rule(
        id="ai-xss",
        name="Reflected marker",
        family="xss",
        severity="high",
        cwe="CWE-79",
        owasp="WSTG-INPV-01",
        inject_into=["query"],
        payloads=["harmless"],  # declared payload never produces the oracle marker
        oracle=OracleSpec(type="any_of", checks=[OracleCheck(type="response_match", part="body", patterns=[_AI_MARKER])]),
        confirm_reproducible=True,
        remediation="n/a",
    )


def _request() -> HttpRequest:
    return HttpRequest(method="GET", url="http://x/test", params={"q": "1"})


def _xss(findings) -> list:  # scan_request also runs passive header checks; keep only our rule
    return [f for f in findings if f.rule_id == "ai-xss"]


async def test_ai_payload_confirmed_by_oracle_is_flagged() -> None:
    client = _ReflectingClient()
    generator = _StubGenerator([_MAGIC])
    scanner = Scanner(client, [_reflect_rule()], active_checks=False, ai_payloads=generator)  # type: ignore[arg-type]
    findings = _xss(await scanner.scan_request(_request()))
    assert len(findings) == 1
    assert generator.calls == 1  # the AI was consulted once (input reflected, declared payload failed)
    # the finding carries the "AI proposed, oracle confirmed" note
    assert any("la IA no confirma" in e.data for e in findings[0].evidence)


async def test_inert_ai_payload_is_not_flagged() -> None:
    # the AI proposes something the oracle does NOT confirm → no finding (the AI can't confirm)
    scanner = Scanner(_ReflectingClient(), [_reflect_rule()], active_checks=False, ai_payloads=_StubGenerator(["inert"]))  # type: ignore[arg-type]
    assert _xss(await scanner.scan_request(_request())) == []


async def test_no_generator_means_no_ai_path() -> None:
    client = _ReflectingClient()
    scanner = Scanner(client, [_reflect_rule()], active_checks=False)  # no ai_payloads
    assert _xss(await scanner.scan_request(_request())) == []
    # the magic payload was never tried and no canary probe was sent
    assert _MAGIC not in client.seen_values
    assert not any(v.startswith("dcaix") for v in client.seen_values)
