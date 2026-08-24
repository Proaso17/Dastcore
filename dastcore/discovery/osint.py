"""Organisational OSINT — the org's exposure *outside* its own web servers.

Two public-source checks that complement the on-target scanning, both derived **only from the scan's
own scope** (its registrable domains / labels), never from arbitrary names:

- **Public-code references** (GitHub code search) — source files in public repos that mention the
  target's domain. These are leads (leaked config, internal URLs, hard-coded hosts) worth a human look.
  Fully passive: it queries ``api.github.com``, never the target. Needs a ``GITHUB_TOKEN`` (the code
  search API requires auth); without one it contributes nothing.
- **Cloud storage buckets** — candidate S3/GCS/Azure bucket names permuted from the org's domain labels,
  checked for existence and, above all, **public listability**. A world-listable bucket is a data-
  exposure finding on its own. Candidates are built only from the scope's labels, so this looks for the
  organisation's *own* buckets, not third parties'.

These sources are third-party endpoints (like the CT-log / passive-DNS sources), so they use their own
HTTP client rather than the scope-enforced one — and they only ever *read public metadata*, never scan.
Everything is best-effort/fail-open and opt-in. The fetchers are injectable for offline tests.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from dastcore.core.models import Evidence, Finding, HttpRequest, HttpResponse, InjectionPoint

# Fetchers are injectable so the parsing/finding logic is unit-testable with no network.
# A JSON fetcher returns parsed JSON (dict) or None; a bucket prober returns (status, body) or None.
JsonFetcher = Callable[[str, dict[str, str]], Awaitable[dict | None]]
BucketProber = Callable[[str], Awaitable["tuple[int, str] | None"]]

# Common bucket-name affixes an org uses. Kept compact so a multi-label sweep stays small.
_BUCKET_AFFIXES = (
    "", "-dev", "-development", "-staging", "-stage", "-prod", "-production", "-test", "-qa",
    "-assets", "-static", "-media", "-uploads", "-files", "-data", "-backup", "-backups", "-logs",
    "-public", "-private", "-internal", "-cdn", "-images", "-img", "-www", "-app",
)


@dataclass(frozen=True)
class GithubHit:
    repo: str
    path: str
    url: str


@dataclass(frozen=True)
class BucketHit:
    provider: str
    url: str
    listable: bool  # world-readable listing (the data-exposure case) vs merely exists


def _point() -> InjectionPoint:
    request = HttpRequest(method="GET", url="https://osint.local/")
    return InjectionPoint(location="header", name="osint", base_value="", request_template=request)


def _osint_finding(rule: str, name: str, severity: str, cwe: str, url: str, detail: str, fix: str) -> Finding:
    request = HttpRequest(method="GET", url=url)
    return Finding(
        id=f"{rule}:{url}",
        rule_id=rule,
        name=name,
        severity=severity,
        cwe=cwe,
        owasp="WSTG-INFO-01",
        family="osint",
        injection_point=_point(),
        evidence=[Evidence(type="response_match", data=detail, confidence="high")],
        request=request,
        response=HttpResponse(status_code=0, url=url, text=detail),
        remediation=fix,
    )


# ── Public-code references (GitHub) ─────────────────────────────────────────────────────────────────


async def _default_json_fetcher(url: str, headers: dict[str, str]) -> dict | None:
    import httpx

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True, headers=headers) as client:
            resp = await client.get(url)
        if resp.status_code != 200:
            return None
        data = resp.json()
    except (httpx.HTTPError, OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


async def github_code_search(
    domain: str, *, token: str | None = None, fetcher: JsonFetcher | None = None, limit: int = 20
) -> list[GithubHit]:
    """Public source files that mention ``domain`` (GitHub code search). Needs a token; fail-open."""
    token = token if token is not None else os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        return []
    fetch = fetcher or _default_json_fetcher
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    data = await fetch(f"https://api.github.com/search/code?q=%22{domain.strip()}%22&per_page={limit}", headers)
    if not isinstance(data, dict):
        return []
    hits: list[GithubHit] = []
    for item in data.get("items", []):
        if not isinstance(item, dict):
            continue
        repo = str((item.get("repository") or {}).get("full_name", ""))
        path = str(item.get("path", ""))
        url = str(item.get("html_url", ""))
        if url:
            hits.append(GithubHit(repo=repo, path=path, url=url))
    return hits[:limit]


def github_findings(domain: str, hits: list[GithubHit]) -> list[Finding]:
    """One info finding per public-code reference to the org's domain (a lead to review)."""
    findings: list[Finding] = []
    for hit in hits:
        findings.append(
            _osint_finding(
                "osint-public-code", "Domain referenced in public code", "info", "CWE-200", hit.url,
                f"{domain} is referenced in public source at {hit.repo}/{hit.path}. Review it for leaked "
                "config, credentials, internal URLs or endpoints.",
                "Revisa la referencia; si expone secretos o infraestructura interna, rota las credenciales "
                "afectadas y solicita su retirada. Evita commitear dominios/secretos internos a repos públicos.",
            )
        )
    return findings


# ── Cloud storage buckets ───────────────────────────────────────────────────────────────────────────


def bucket_candidates(labels: list[str]) -> list[str]:
    """Candidate bucket names permuted from the org's domain labels (deduped, order-stable)."""
    names: list[str] = []
    seen: set[str] = set()
    for label in labels:
        base = label.strip().lower()
        if not base:
            continue
        for affix in _BUCKET_AFFIXES:
            name = f"{base}{affix}"
            if name not in seen:
                seen.add(name)
                names.append(name)
    return names


def bucket_urls(name: str) -> list[tuple[str, str]]:
    """The (provider, URL) endpoints to check for one candidate bucket name."""
    return [
        ("AWS S3", f"https://{name}.s3.amazonaws.com/"),
        ("Google Cloud Storage", f"https://storage.googleapis.com/{name}/"),
        ("Azure Blob", f"https://{name}.blob.core.windows.net/{name}?restype=container&comp=list"),
    ]


def _is_listable(provider: str, status: int, body: str) -> bool:
    """Whether a 200 response is a world-readable *listing* (the data-exposure case)."""
    if status != 200:
        return False
    low = body.lower()
    if provider == "AWS S3":
        return "<listbucketresult" in low
    if provider == "Google Cloud Storage":
        return "<listbucketresult" in low or '"items"' in low or "<contents>" in low
    if provider == "Azure Blob":
        return "<enumerationresults" in low
    return False


async def _default_bucket_prober(url: str) -> tuple[int, str] | None:
    import httpx

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(url)
    except (httpx.HTTPError, OSError):
        return None
    return resp.status_code, resp.text


async def check_buckets(
    labels: list[str], *, prober: BucketProber | None = None, max_candidates: int = 60
) -> list[BucketHit]:
    """Check candidate buckets for the org's labels; return the ones that exist, flagging listable ones."""
    probe = prober or _default_bucket_prober
    candidates = bucket_candidates(labels)[:max_candidates]
    targets = [(provider, url) for name in candidates for provider, url in bucket_urls(name)]
    semaphore = asyncio.Semaphore(20)

    async def _one(provider: str, url: str) -> BucketHit | None:
        async with semaphore:
            result = await probe(url)
        if result is None:
            return None
        status, body = result
        listable = _is_listable(provider, status, body)
        if listable:
            return BucketHit(provider=provider, url=url, listable=True)
        return None  # only report world-listable buckets — existence alone is too noisy / not a finding

    results = await asyncio.gather(*(_one(p, u) for p, u in targets))
    return [hit for hit in results if hit is not None]


def bucket_findings(hits: list[BucketHit]) -> list[Finding]:
    """A finding per world-listable bucket — public data exposure."""
    findings: list[Finding] = []
    for hit in hits:
        findings.append(
            _osint_finding(
                "osint-open-bucket", f"Publicly listable {hit.provider} bucket", "high", "CWE-200", hit.url,
                f"The {hit.provider} bucket at {hit.url} is world-listable — anyone can enumerate and "
                "download its contents.",
                "Restringe el acceso al bucket (deshabilita el listado público y revisa las ACL/políticas). "
                "Sirve los objetos públicos necesarios a través de una CDN con acceso controlado.",
            )
        )
    return findings
