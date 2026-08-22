"""Technology-aware path discovery — probe the paths that *this* stack is known to expose.

A generic wordlist wastes requests: it tries ``/wp-admin`` on a Spring app and ``/actuator`` on
WordPress. This module fingerprints the stack from the homepage (headers, cookies, and body markers),
then probes only the high-signal paths that stack actually serves — admin panels, framework APIs,
debug/health endpoints, doc UIs. It generalises to any website: most real sites run a known stack, and
these are exactly the paths an attacker checks first.

Zero-FP: every probe is calibrated against a random-path baseline, so a catch-all/SPA that answers 200
for everything can't manufacture endpoints. Everything is scope-gated through the client. Live paths
are returned as GET requests for the scanner to test (injection points + passive checks), not as
findings — the sensitive-file/actuator detectors still own the "this is a leak" verdict.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin, urlsplit

from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpRequest, HttpResponse

# Per stack: a body/header regex that identifies it, and the paths it's worth probing when present.
# Keys are normalised stack ids; detection also consults response headers and cookie names below.
_STACKS: dict[str, dict[str, object]] = {
    "wordpress": {
        "body": re.compile(r"wp-content|wp-includes|/wp-json|name=\"generator\" content=\"WordPress", re.I),
        "paths": ["wp-login.php", "wp-json/", "wp-json/wp/v2/users", "wp-admin/", "xmlrpc.php",
                  "wp-content/debug.log", "?rest_route=/wp/v2/users"],
    },
    "drupal": {
        "body": re.compile(r"Drupal\.settings|sites/(?:all|default)/|drupal\.js", re.I),
        "paths": ["user/login", "CHANGELOG.txt", "core/CHANGELOG.txt", "admin", "jsonapi/",
                  "node?_format=json", "user/register"],
    },
    "joomla": {
        "body": re.compile(r"/media/jui/|com_content|Joomla!|/media/system/js/", re.I),
        "paths": ["administrator/", "api/index.php/v1/", "configuration.php-dist", "README.txt"],
    },
    "laravel": {
        "body": re.compile(r"laravel|csrf-token|/vendor/laravel", re.I),
        "cookies": {"laravel_session", "xsrf-token"},
        "paths": [".env", "telescope/requests", "horizon/api/stats/masters",
                  "_ignition/health-check", "storage/logs/laravel.log", "log/laravel.log"],
    },
    "django": {
        "body": re.compile(r"csrfmiddlewaretoken|__admin_media_prefix__|django", re.I),
        "cookies": {"csrftoken", "django_language"},
        "paths": ["admin/", "admin/login/", "static/admin/css/base.css", "api/", "__debug__/"],
    },
    "rails": {
        "body": re.compile(r'csrf-param|content="authenticity_token"|/assets/application-', re.I),
        "cookies": {"_rails_session"},
        "paths": ["rails/info/routes", "rails/info/properties", "assets/", "sidekiq"],
    },
    "spring": {
        "body": re.compile(r"Whitelabel Error Page|org\.springframework|spring-boot", re.I),
        "paths": ["actuator", "actuator/env", "actuator/health", "actuator/mappings", "actuator/beans",
                  "v3/api-docs", "swagger-ui/index.html", "swagger-ui.html"],
    },
    "express": {
        "cookies": {"connect.sid"},
        "paths": [".env", "api/", "status", "healthz"],
    },
    "aspnet": {
        "body": re.compile(r"__VIEWSTATE|asp\.net|\.aspx", re.I),
        "cookies": {"asp.net_sessionid", ".aspxauth"},
        "paths": ["elmah.axd", "trace.axd", "web.config", "glimpse.axd"],
    },
    "nextjs": {
        "body": re.compile(r"__NEXT_DATA__|/_next/static/|/_next/", re.I),
        "paths": ["_next/static/", "api/", "_next/data/", ".env", ".env.local"],
    },
    "php": {
        "cookies": {"phpsessid"},
        "paths": ["phpinfo.php", "info.php", "phpmyadmin/", "adminer.php", "server-status", ".env"],
    },
    "tomcat": {
        "server": re.compile(r"tomcat|coyote", re.I),
        "paths": ["manager/html", "host-manager/html", "manager/status", "examples/", "docs/"],
    },
    "jenkins": {
        "body": re.compile(r"Jenkins|jenkins-session|hudson", re.I),
        "paths": ["api/json", "script", "view/all/builds", "asynchPeople/", "whoAmI/"],
    },
    "gitlab": {
        "body": re.compile(r"GitLab|gitlab-session|/assets/webpack/", re.I),
        "paths": ["-/health", "-/readiness", "users/sign_in", "explore", "api/v4/projects"],
    },
    "grafana": {
        "body": re.compile(r"grafana", re.I),
        "paths": ["login", "api/health", "api/datasources", "api/org"],
    },
}


def detect_stacks(headers: dict[str, str], cookies: set[str], body: str, server: str = "") -> set[str]:
    """Normalised stack ids inferred from a homepage's headers, cookie names and body."""
    lowered_cookies = {c.lower() for c in cookies}
    powered = (headers.get("x-powered-by", "") + " " + headers.get("x-generator", "")).lower()
    found: set[str] = set()
    for key, spec in _STACKS.items():
        server_re = spec.get("server")
        body_re = spec.get("body")
        cookie_set = spec.get("cookies")
        if isinstance(server_re, re.Pattern) and server_re.search(server):
            found.add(key)
        elif isinstance(cookie_set, set) and (lowered_cookies & cookie_set):
            found.add(key)
        elif isinstance(body_re, re.Pattern) and body_re.search(body):
            found.add(key)
        elif key in powered:
            found.add(key)
    return found


def paths_for_stacks(stacks: set[str], *, limit: int = 80) -> list[str]:
    """The deduped union of probe paths for the detected stacks, order-stable, capped."""
    ordered: list[str] = []
    seen: set[str] = set()
    for key in _STACKS:  # iterate in a stable order
        if key not in stacks:
            continue
        for path in _STACKS[key].get("paths", []):  # type: ignore[union-attr]
            if path not in seen:
                seen.add(path)
                ordered.append(path)
    return ordered[:limit]


def _distinct(resp: HttpResponse, baseline: HttpResponse | None) -> bool:
    """Whether ``resp`` is a real, distinct page — not the catch-all/404 baseline."""
    if resp.status_code in (404, 410):
        return False
    if baseline is None:
        return resp.status_code < 500  # no catch-all: any non-5xx answer counts
    if resp.status_code != baseline.status_code:
        return True  # a different status than "anything" -> a real, distinct endpoint
    # Same status as the catch-all baseline: only distinct if the body clearly differs in size.
    la, lb = len(resp.text or ""), len(baseline.text or "")
    return abs(la - lb) > max(64, int(0.05 * max(la, lb, 1)))


async def discover_tech_paths(client: HttpClient, root: str, *, timeout: float = 8.0) -> list[HttpRequest]:
    """Fingerprint ``root``'s stack and probe its known paths; return the live ones as GET requests."""
    try:
        home = await client.get(root, timeout=timeout, retries=0)
    except Exception:  # noqa: BLE001 — unreachable/out-of-scope root: nothing to do
        return []
    if home is None:
        return []

    headers = {name.lower(): value for name, value in home.headers.items()}
    cookie_names = {name.lower() for name in home.cookies}
    for part in headers.get("set-cookie", "").split(","):
        name = part.split("=", 1)[0].strip().lower()
        if name:
            cookie_names.add(name)
    server = headers.get("server", "")

    stacks = detect_stacks(headers, cookie_names, home.text or "", server)
    paths = paths_for_stacks(stacks)
    if not paths:
        return []

    base = f"{root.rstrip('/')}/"
    try:
        baseline = await client.get(urljoin(base, f"dc{secrets.token_hex(8)}"), timeout=timeout, retries=0)
    except Exception:  # noqa: BLE001
        baseline = None

    discovered: dict[str, HttpRequest] = {}
    for path in paths:
        url = urljoin(base, path.lstrip("/"))
        if not client.is_in_scope(url):
            continue
        try:
            resp = await client.get(url, timeout=timeout, retries=0)
        except Exception:  # noqa: BLE001 — a dead/out-of-scope path is simply skipped
            continue
        if resp is not None and _distinct(resp, baseline):
            # Preserve any query string in the probe path (e.g. ?rest_route=…) as real params.
            parts = urlsplit(url)
            req = HttpRequest(method="GET", url=f"{parts.scheme}://{parts.netloc}{parts.path}")
            if parts.query:
                from urllib.parse import parse_qsl

                req = req.model_copy(update={"params": dict(parse_qsl(parts.query))})
            discovered.setdefault(req.signature(), req)
    return list(discovered.values())
