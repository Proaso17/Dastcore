"""Hidden parameter discovery (Arjun-style): find query parameters the server actually uses but
that appear nowhere in the HTML, forms, JS or history — undocumented ``?debug=``, ``?admin=``,
``?redirect=`` and the like. Each one found is a fresh injection point for the existing detectors.

Detection is by **reflection of a unique canary**, in batches (many params per request, so it's fast):
send each candidate with its own unguessable token; a token that comes back in the response means the
server processed that parameter. A calibration probe first checks whether the server echoes *any*
parameter (a query-reflecting error page) — if so, reflection can't distinguish real params and mining
is skipped. Found params only *feed* the scanner (whose oracles validate), so this never adds a finding
on its own — the zero-FP guarantee is untouched.
"""

from __future__ import annotations

import hashlib
import secrets
from pathlib import Path

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import HttpRequest, HttpResponse

_WORDLISTS = Path(__file__).parent / "wordlists"
_DEPTH_LIMITS: dict[str, int | None] = {"light": 100, "balanced": 250, "aggressive": None}


def load_param_wordlist(depth: str = "balanced", path: str | Path | None = None) -> list[str]:
    from dastcore.discovery.seclists import resolve_wordlist

    resolved = resolve_wordlist("params", path)
    source = Path(resolved) if resolved else _WORDLISTS / "params.txt"
    seen: set[str] = set()
    words: list[str] = []
    for line in source.read_text(encoding="utf-8", errors="ignore").splitlines():
        entry = line.strip()
        if entry and not entry.startswith("#") and entry not in seen:
            seen.add(entry)
            words.append(entry)
    limit = _DEPTH_LIMITS.get(depth, None)
    return words if limit is None else words[:limit]


def _canary(name: str) -> str:
    """An unguessable token unique to a parameter name, so its reflection identifies exactly it."""
    return "dcp" + hashlib.sha1(name.encode("utf-8")).hexdigest()[:10]  # noqa: S324 — non-crypto marker


class ParamMiner:
    """Find hidden query parameters on a GET endpoint by canary reflection."""

    def __init__(self, client: HttpClient, *, wordlist: list[str], batch_size: int = 25, timeout: float = 6.0):
        self._client = client
        self._wordlist = wordlist
        self._batch_size = max(1, batch_size)
        self._timeout = timeout

    async def _get(self, url: str, params: dict[str, str]) -> HttpResponse | None:
        try:
            return await self._client.get(url, params=params, timeout=self._timeout, retries=0)
        except (OutOfScopeError, BudgetExceededError):
            return None
        except Exception:  # noqa: BLE001 — a dead probe must not abort mining
            return None

    async def mine(self, request: HttpRequest) -> list[str]:
        """The hidden parameter names the endpoint reacts to (reflects). Empty if it echoes everything."""
        if request.method != "GET" or not self._client.is_in_scope(request.url):
            return []
        base = dict(request.params or {})

        # Calibration: if the server reflects an arbitrary parameter, reflection can't tell real from noise.
        rand = "dcrand" + secrets.token_hex(6)
        cal = await self._get(request.url, {**base, rand: _canary(rand)})
        if cal is None or _canary(rand) in (cal.text or ""):
            return []

        found: list[str] = []
        for start in range(0, len(self._wordlist), self._batch_size):
            batch = [w for w in self._wordlist[start : start + self._batch_size] if w not in base]
            if not batch:
                continue
            resp = await self._get(request.url, {**base, **{name: _canary(name) for name in batch}})
            if resp is None:
                continue
            text = resp.text or ""
            found.extend(name for name in batch if _canary(name) in text)
        return found


async def mine_hidden_params(
    client: HttpClient, requests: list[HttpRequest], wordlist: list[str], *, max_endpoints: int = 30
) -> list[HttpRequest]:
    """Mine hidden params across up to ``max_endpoints`` GET endpoints; return enriched requests
    (original params + the discovered ones) for the scanner to test."""
    miner = ParamMiner(client, wordlist=wordlist)
    enriched: dict[str, HttpRequest] = {}
    seen_urls: set[str] = set()
    for request in requests:
        if request.method != "GET" or request.url in seen_urls:
            continue
        seen_urls.add(request.url)
        if len(seen_urls) > max_endpoints:
            break
        found = await miner.mine(request)
        if found:
            params = {**dict(request.params or {}), **dict.fromkeys(found, "1")}
            new = HttpRequest(method="GET", url=request.url, params=params)
            enriched.setdefault(new.signature(), new)
    return list(enriched.values())
