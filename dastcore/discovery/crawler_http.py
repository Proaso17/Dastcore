"""Static HTTP crawler.

Breadth-first walk of a target following `<a href>` links and `<form>`
definitions found in HTML responses, staying strictly within scope (every
fetch goes through `HttpClient`, which enforces it). Each page and each form
becomes an `HttpRequest`; requests are deduplicated by "shape" (method + path
+ parameter names) so the same endpoint isn't scanned once per parameter
value seen.
"""

from __future__ import annotations

import re
from collections import deque
from urllib.parse import parse_qsl, urljoin, urlsplit

import httpx
from selectolax.parser import HTMLParser, Node

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import HttpRequest

_SITEMAP_LOC = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE | re.DOTALL)


class HttpCrawler:
    """Breadth-first static crawler bounded by scope and `max_pages`."""

    def __init__(self, http_client: HttpClient, max_pages: int = 200, use_robots: bool = True) -> None:
        self._http = http_client
        self._max_pages = max_pages
        self._use_robots = use_robots

    async def crawl(self, start_url: str) -> list[HttpRequest]:
        seen_urls: set[str] = set()
        seen_signatures: set[str] = set()
        discovered: list[HttpRequest] = []
        queue: deque[str] = deque([start_url])

        if self._use_robots:
            for seed in await self._seed_from_robots_and_sitemap(start_url):
                if self._http.is_in_scope(seed):
                    queue.append(seed)

        while queue and len(seen_urls) < self._max_pages:
            url = queue.popleft().split("#", 1)[0]
            if url in seen_urls:
                continue
            seen_urls.add(url)

            if not self._http.is_in_scope(url):
                continue

            try:
                response = await self._http.get(url)
            except OutOfScopeError:
                continue
            except BudgetExceededError:
                break  # budget spent: stop crawling, keep what we have
            except httpx.HTTPError:
                continue  # transient network error on this page — skip it, keep crawling the rest

            self._record(self._page_request(url), discovered, seen_signatures)

            if "html" not in response.headers.get("content-type", ""):
                continue

            tree = HTMLParser(response.text)

            for anchor in tree.css("a[href]"):
                href = anchor.attributes.get("href")
                if not href:
                    continue
                absolute = urljoin(url, href).split("#", 1)[0]
                if absolute not in seen_urls and self._http.is_in_scope(absolute):
                    queue.append(absolute)

            for form in tree.css("form"):
                form_request = self._form_request(url, form)
                if form_request is not None:
                    self._record(form_request, discovered, seen_signatures)

        return discovered

    async def _seed_from_robots_and_sitemap(self, start_url: str) -> list[str]:
        """Pull seed URLs from robots.txt (Disallow/Allow/Sitemap) and sitemap.xml (<loc>)."""
        parts = urlsplit(start_url)
        origin = f"{parts.scheme}://{parts.netloc}"
        seeds: list[str] = []
        sitemap_urls: list[str] = [f"{origin}/sitemap.xml"]

        try:
            robots = await self._http.get(f"{origin}/robots.txt")
        except (OutOfScopeError, BudgetExceededError):
            return []
        if robots.status_code == 200:
            for line in robots.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or ":" not in line:
                    continue
                directive, value = line.split(":", 1)
                directive, value = directive.strip().lower(), value.strip()
                if directive in ("disallow", "allow") and value not in ("", "/"):
                    seeds.append(urljoin(origin + "/", value.lstrip("/")))
                elif directive == "sitemap" and value:
                    sitemap_urls.append(urljoin(origin + "/", value))

        for sitemap_url in dict.fromkeys(sitemap_urls):
            try:
                sitemap = await self._http.get(sitemap_url)
            except (OutOfScopeError, BudgetExceededError):
                continue
            if sitemap.status_code == 200:
                for loc in _SITEMAP_LOC.findall(sitemap.text):
                    seeds.append(urljoin(origin + "/", loc.lstrip("/")))

        return seeds

    @staticmethod
    def _record(request: HttpRequest, discovered: list[HttpRequest], seen_signatures: set[str]) -> None:
        sig = request.signature()
        if sig not in seen_signatures:
            seen_signatures.add(sig)
            discovered.append(request)

    @staticmethod
    def _page_request(url: str) -> HttpRequest:
        parts = urlsplit(url)
        params = dict(parse_qsl(parts.query))
        base_url = url.split("?", 1)[0]
        return HttpRequest(method="GET", url=base_url, params=params)

    @staticmethod
    def _form_inputs(form: Node) -> dict[str, str]:
        inputs: dict[str, str] = {}
        for field in form.css("input, textarea, select"):
            name = field.attributes.get("name")
            if not name:
                continue
            if field.tag == "select":
                option = field.css_first("option[selected]") or field.css_first("option")
                value = (option.attributes.get("value") or option.text()) if option else ""
            else:
                value = field.attributes.get("value") or ""
            inputs[name] = value
        return inputs

    def _form_request(self, page_url: str, form: Node) -> HttpRequest | None:
        action = form.attributes.get("action") or ""
        method = (form.attributes.get("method") or "GET").upper()
        target_url = urljoin(page_url, action).split("#", 1)[0]

        inputs = self._form_inputs(form)
        if not inputs:
            return None

        if method == "GET":
            base_url = target_url.split("?", 1)[0]
            existing = dict(parse_qsl(urlsplit(target_url).query))
            existing.update(inputs)
            return HttpRequest(method="GET", url=base_url, params=existing)

        return HttpRequest(method=method, url=target_url.split("?", 1)[0], data=inputs)
