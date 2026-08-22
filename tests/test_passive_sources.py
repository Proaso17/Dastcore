"""Passive subdomain sources: parsing, domain-scoped normalisation, fail-open behaviour, and the
concurrent gather. Fully offline — the HTTP getter is monkeypatched, so no source is ever contacted."""

from __future__ import annotations

from dastcore.discovery import passive_sources as ps


class _Resp:
    def __init__(self, *, payload: object = None, text: str = "") -> None:
        self._payload = payload
        self.text = text

    def json(self) -> object:
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


def test_norm_and_keep_for_domain() -> None:
    assert ps._norm("*.Example.com.") == "example.com"
    kept = ps._keep_for_domain(
        {"API.example.com", "*.example.com", "evil.com", "bad host", "a.b.example.com", "example.com", ""},
        "example.com",
    )
    assert kept == {"api.example.com", "a.b.example.com", "example.com"}


async def test_crtsh_parses_name_values(monkeypatch) -> None:
    async def fake_get(url: str, **kw: object) -> _Resp:
        return _Resp(payload=[{"name_value": "a.example.com\n*.example.com"}, {"name_value": "b.example.com"}])

    monkeypatch.setattr(ps, "_get", fake_get)
    hosts = await ps.crtsh("example.com")
    assert "a.example.com" in hosts and "b.example.com" in hosts


async def test_hackertarget_respects_rate_limit_message(monkeypatch) -> None:
    async def limited(url: str, **kw: object) -> _Resp:
        return _Resp(text="API count exceeded - Increase Quota with Membership")

    monkeypatch.setattr(ps, "_get", limited)
    assert await ps.hackertarget("example.com") == set()


async def test_sources_fail_open_when_request_fails(monkeypatch) -> None:
    async def none_get(url: str, **kw: object) -> None:
        return None

    monkeypatch.setattr(ps, "_get", none_get)
    assert await ps.alienvault_otx("example.com") == set()
    assert await ps.anubis("example.com") == set()
    assert await ps.urlscan("example.com") == set()


async def test_premium_sources_noop_without_keys(monkeypatch) -> None:
    for var in ("SECURITYTRAILS_API_KEY", "SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "VT_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    assert await ps.securitytrails("example.com") == set()
    assert await ps.shodan("example.com") == set()
    assert await ps.virustotal("example.com") == set()


async def test_gather_unions_scopes_and_survives_a_failing_source() -> None:
    async def s1(domain: str) -> set[str]:
        return {"api.example.com", "evil.com"}  # evil.com is out of the domain -> dropped

    async def s2(domain: str) -> set[str]:
        return {"DEV.example.com"}  # case-normalised

    async def down(domain: str) -> set[str]:
        raise RuntimeError("source down")  # must not break the gather

    hosts = await ps.gather_passive_subdomains("example.com", sources=[s1, s2, down])
    assert hosts == {"api.example.com", "dev.example.com"}
