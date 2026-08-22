"""Hidden parameter discovery (Arjun-style): canary reflection finds params the server processes,
with an echo-calibration guard so a query-reflecting server never yields false params."""

from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.discovery.params import ParamMiner, load_param_wordlist, mine_hidden_params


class _ReflectsOne:
    """A server that reflects the value of exactly one parameter (and nothing else)."""

    def __init__(self, name: str) -> None:
        self.name = name

    def is_in_scope(self, url: str) -> bool:
        return True

    async def get(self, url: str, *, params: dict[str, str] | None = None, **_kw: object) -> HttpResponse:
        value = (params or {}).get(self.name, "")
        return HttpResponse(status_code=200, text=f"welcome {value} end", url=url)


class _EchoesEverything:
    def is_in_scope(self, url: str) -> bool:
        return True

    async def get(self, url: str, *, params: dict[str, str] | None = None, **_kw: object) -> HttpResponse:
        return HttpResponse(status_code=200, text=" ".join((params or {}).values()), url=url)


async def test_mine_finds_a_reflected_hidden_param() -> None:
    miner = ParamMiner(_ReflectsOne("debug"), wordlist=["id", "debug", "page"])  # type: ignore[arg-type]
    found = await miner.mine(HttpRequest(method="GET", url="http://t.test/x"))
    assert found == ["debug"]


async def test_mine_skips_a_query_echoing_server() -> None:
    # a server that echoes any parameter would reflect every canary -> calibration must bail out
    miner = ParamMiner(_EchoesEverything(), wordlist=["id", "debug"])  # type: ignore[arg-type]
    assert await miner.mine(HttpRequest(method="GET", url="http://t.test/x")) == []


async def test_mine_hidden_params_enriches_the_request() -> None:
    enriched = await mine_hidden_params(
        _ReflectsOne("admin"),  # type: ignore[arg-type]
        [HttpRequest(method="GET", url="http://t.test/a")],
        ["id", "admin", "page"],
    )
    assert len(enriched) == 1
    assert "admin" in enriched[0].params  # the discovered param is now an injection point


def test_param_wordlist_depth_slicing() -> None:
    light = load_param_wordlist("light")
    aggressive = load_param_wordlist("aggressive")
    assert 0 < len(light) <= 100 < len(aggressive)
    assert light == aggressive[: len(light)]
