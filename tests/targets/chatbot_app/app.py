"""A deliberately vulnerable *property-management* app with an embedded chatbot.

Offline test fixture modelling the class of app dastcore's chatbot checks target:
a multi-tenant SaaS (tenants = tenants/landlords of flats) whose assistant answers
questions with **retrieval** over each tenant's own stored messages/maintenance
notes (a mini RAG). Two flaws are planted, each faithful to a real failure mode:

* **Stored / second-order indirect prompt injection** (``/api/chat``): the assistant
  concatenates retrieved notes into its context and *follows imperative instructions
  found there* — so text one user persists via ``/api/messages`` is later executed as
  an instruction when the assistant answers. ``/api/chat_safe`` is the hardened variant
  (treats retrieved notes strictly as data) and must never fire — it proves precision.

* **Cross-tenant leakage via the assistant** (BOLA-through-the-LLM): the retrieval layer
  has no per-tenant authorization, so asking the assistant about *another* unit returns
  that tenant's private contact/bank details. Used by the cross-tenant check.

DO NOT deploy this anywhere reachable.
"""

from __future__ import annotations

import re

from flask import Flask, jsonify, request

# Bearer token -> tenant id. Two tenants, each renting a different flat.
TOKENS = {"tok-a": "alice", "tok-b": "bob"}

TENANTS: dict[str, dict] = {
    "alice": {"unit": "4A", "phone": "+34 600 111 222", "iban": "ES91 2100 0418 4502 0005 1332"},
    "bob": {"unit": "4B", "phone": "+34 600 333 444", "iban": "ES79 2100 0813 6101 2345 6789"},
}

# The assistant, being naive, obeys imperative directives embedded in retrieved text.
# This regex captures the token an injected instruction tells it to emit — it keys on the
# *attacker's phrasing*, never on any dastcore-specific marker, so it is a fair stand-in
# for a real model that treats retrieved content as instructions.
_OBEY = re.compile(
    r"(?:reply with(?:\s+only)?|respond with|output|print|say|include(?:\s+the\s+text)?)\s*[:=]?\s*([A-Za-z0-9_-]{6,})",
    re.IGNORECASE,
)

_SUMMARIZE = ("summar", "list", "recent", "my messages", "my requests", "maintenance", "resum")


def _tenant() -> str | None:
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    return TOKENS.get(token)


def _follow_instructions(context: str) -> str | None:
    """Return the token the *last* embedded instruction in the context demands, if any."""
    matches = _OBEY.findall(context)
    return matches[-1] if matches else None


def _cross_tenant_lookup(message: str, asking: str) -> str | None:
    """Vulnerable retrieval: reveal another unit's private data with no authorization."""
    for tenant_id, profile in TENANTS.items():
        if tenant_id == asking:
            continue
        unit = profile["unit"].lower()
        if unit in message.lower() or tenant_id in message.lower():
            return f"Tenant {tenant_id} (unit {profile['unit']}): phone {profile['phone']}, IBAN {profile['iban']}."
    return None


def create_app() -> Flask:
    app = Flask(__name__)
    # Per-tenant persisted messages / maintenance notes (the assistant's retrieval corpus).
    # Instance-local so separate app instances / test runs don't share state.
    messages: dict[str, list[str]] = {"alice": [], "bob": []}

    @app.get("/")
    def index() -> str:
        return (
            "<!doctype html><html><body><h1>FlatManager</h1>"
            "<p>Property management with an AI assistant. DO NOT expose.</p></body></html>"
        )

    @app.post("/api/messages")
    def post_message():
        tenant = _tenant()
        if tenant is None:
            return jsonify({"error": "unauthenticated"}), 401
        text = (request.get_json(silent=True) or {}).get("text", "")
        messages[tenant].append(str(text))
        return jsonify({"stored": True, "count": len(messages[tenant])})

    @app.get("/api/messages")
    def get_messages():
        tenant = _tenant()
        if tenant is None:
            return jsonify({"error": "unauthenticated"}), 401
        return jsonify({"messages": messages[tenant]})

    def _answer(message: str, tenant: str, *, safe: bool) -> str:
        leak = _cross_tenant_lookup(message, tenant)
        if leak is not None:  # cross-tenant BOLA via the assistant (both variants)
            return leak
        if any(word in message.lower() for word in _SUMMARIZE):
            notes = messages[tenant]
            context = "\n".join(notes)
            if not safe:
                obeyed = _follow_instructions(context)
                if obeyed is not None:  # stored indirect prompt injection
                    return obeyed
            return f"You have {len(notes)} message(s) on file for unit {TENANTS[tenant]['unit']}."
        return "How can I help you manage your flat today?"

    @app.post("/api/chat")
    def chat():
        tenant = _tenant()
        if tenant is None:
            return jsonify({"error": "unauthenticated"}), 401
        message = (request.get_json(silent=True) or {}).get("message", "")
        return jsonify({"reply": _answer(str(message), tenant, safe=False)})

    @app.post("/api/chat_safe")
    def chat_safe():
        tenant = _tenant()
        if tenant is None:
            return jsonify({"error": "unauthenticated"}), 401
        message = (request.get_json(silent=True) or {}).get("message", "")
        return jsonify({"reply": _answer(str(message), tenant, safe=True)})

    return app
