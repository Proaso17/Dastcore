"""AI / LLM security testing (OWASP LLM Top 10) against a simulated vulnerable chatbot."""
from __future__ import annotations

from typer.testing import CliRunner

from dastcore.ai.client import AiChatClient, extract_response_text
from dastcore.ai.engine import AiScanner, load_ai_rules
from dastcore.cli import app
from dastcore.config import ScopeConfig
from dastcore.core.http_client import HttpClient

runner = CliRunner()
_SCOPE = ScopeConfig(allow_domains=["127.0.0.1"])


# --- response extraction ---------------------------------------------------------------

def test_extract_response_auto_detects_common_fields() -> None:
    assert extract_response_text({"reply": "hi"}, None) == "hi"
    assert extract_response_text({"choices": [{"message": {"content": "yo"}}]}, None) == "yo"
    assert extract_response_text({"nope": 1}, None) is None


def test_extract_response_explicit_path() -> None:
    payload = {"data": {"items": [{"text": "found"}]}}
    assert extract_response_text(payload, "data.items.0.text") == "found"


# --- rules -----------------------------------------------------------------------------

def test_ai_rules_load() -> None:
    ids = {r.id for r in load_ai_rules()}
    assert ids == {
        "llm-prompt-injection",
        "llm-jailbreak",
        "llm-system-prompt-leak",
        "llm-sensitive-disclosure",
        "llm-insecure-output",
        "llm-indirect-injection",
        "llm-crescendo-jailbreak",
        "llm-excessive-agency",
        "llm-pii-disclosure",
        "llm-denial-of-wallet",
    }


def test_pii_and_luhn_helpers() -> None:
    from dastcore.ai.engine import _find_pii, _luhn_ok

    assert _luhn_ok("4111 1111 1111 1111") is True
    assert _luhn_ok("1234 5678 9012 3456") is False
    assert _find_pii("contact jane.doe@example.com please").startswith("email")
    assert _find_pii("no personal data here") is None


# --- detection against the vulnerable bot ----------------------------------------------

async def _scan(url: str):
    async with HttpClient(_SCOPE) as client:
        chat = AiChatClient(client, url)
        return await AiScanner(chat, load_ai_rules()).scan()


async def test_all_llm_attacks_detected_on_vulnerable_bot(vuln_app_url: str) -> None:
    findings = await _scan(f"{vuln_app_url}/ai/chat")
    ids = {f.rule_id for f in findings}
    # Single-turn classes reachable on the main chat endpoint.
    for expected in (
        "llm-prompt-injection",
        "llm-jailbreak",
        "llm-system-prompt-leak",
        "llm-sensitive-disclosure",
        "llm-insecure-output",
        "llm-pii-disclosure",
        "llm-denial-of-wallet",
        "llm-crescendo-jailbreak",  # multi-turn via conversation_id state
    ):
        assert expected in ids, (expected, ids)


async def test_indirect_prompt_injection_via_context(vuln_app_url: str) -> None:
    """The malicious instruction rides in the `context` field, not the user message."""
    findings = await _scan(f"{vuln_app_url}/ai/rag")
    assert any(f.rule_id == "llm-indirect-injection" for f in findings), [f.rule_id for f in findings]


async def test_excessive_agency_detected(vuln_app_url: str) -> None:
    findings = await _scan(f"{vuln_app_url}/ai/agent")
    assert any(f.rule_id == "llm-excessive-agency" for f in findings), [f.rule_id for f in findings]


async def test_crescendo_needs_multiple_turns(vuln_app_url: str) -> None:
    """The crescendo payload alone (single-turn) is refused; the rule's priming turns make it work."""
    from dastcore.ai.engine import AiRule

    async with HttpClient(_SCOPE) as client:
        chat = AiChatClient(client, f"{vuln_app_url}/ai/chat")
        crescendo = next(r for r in load_ai_rules() if r.id == "llm-crescendo-jailbreak")
        # Same payload with no priming conversation -> should NOT fire.
        single_turn = AiRule(**{**crescendo.model_dump(), "conversation": []})
        assert await AiScanner(chat, [single_turn]).scan() == []
        # With the priming turns -> fires.
        assert any(f.rule_id == "llm-crescendo-jailbreak" for f in await AiScanner(chat, [crescendo]).scan())


async def test_sensitive_disclosure_reveals_secret(vuln_app_url: str) -> None:
    findings = await _scan(f"{vuln_app_url}/ai/chat")
    disclosure = next(f for f in findings if f.rule_id == "llm-sensitive-disclosure")
    assert "sk-DASTCORE" in disclosure.evidence[0].data


async def test_no_llm_findings_on_secure_bot(vuln_app_url: str) -> None:
    """The hardened bot refuses every probe — zero findings (no false positives)."""
    findings = await _scan(f"{vuln_app_url}/ai/chat-secure")
    assert findings == []


async def test_openai_style_shape_via_template_and_path(vuln_app_url: str) -> None:
    async with HttpClient(_SCOPE) as client:
        chat = AiChatClient(
            client,
            f"{vuln_app_url}/ai/chat-openai",
            template='{"messages":[{"role":"user","content":"{{prompt}}"}]}',
            response_path="choices.0.message.content",
        )
        findings = await AiScanner(chat, load_ai_rules()).scan()
    assert any(f.rule_id == "llm-prompt-injection" for f in findings)


# --- CLI -------------------------------------------------------------------------------

def test_ai_command_requires_authorization(vuln_app_url: str) -> None:
    result = runner.invoke(app, ["ai", f"{vuln_app_url}/ai/chat"])
    assert result.exit_code == 1
    assert "ABORTADO" in result.stdout


def test_ai_command_scans_and_reports(vuln_app_url: str) -> None:
    result = runner.invoke(
        app, ["ai", f"{vuln_app_url}/ai/chat", "--i-have-authorization", "--rps", "50", "--fail-on", "none"]
    )
    assert result.exit_code == 0
    assert "Prompt Injection" in result.stdout


def test_ai_command_fail_on_high_exits_2(vuln_app_url: str) -> None:
    result = runner.invoke(
        app, ["ai", f"{vuln_app_url}/ai/chat", "--i-have-authorization", "--rps", "50", "--fail-on", "high"]
    )
    assert result.exit_code == 2  # prompt injection / disclosure are high
