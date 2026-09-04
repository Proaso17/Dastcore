"""Technology fingerprint + WAF detection."""

from __future__ import annotations

from dastcore.config import RateLimitConfig, ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.core.models import HttpResponse
from dastcore.detectors.fingerprint import build_profile, fingerprint_and_waf, looks_blocked


def _resp(headers=None, cookies=None, status=200, text="") -> HttpResponse:
    return HttpResponse(status_code=status, headers=headers or {}, cookies=cookies or {}, text=text, url="http://x/")


# --- fingerprint -------------------------------------------------------------------------


def test_profile_from_headers_and_cookies() -> None:
    profile = build_profile(
        _resp(headers={"Server": "nginx/1.25", "X-Powered-By": "PHP/8.2"}, cookies={"PHPSESSID": "abc"})
    )
    assert profile.server == "nginx/1.25"
    assert profile.powered_by == "PHP/8.2"
    assert "nginx/1.25" in profile.technologies
    assert "PHP/8.2" in profile.technologies
    assert "PHP" in profile.technologies  # from the PHPSESSID cookie


def test_profile_detects_framework_cookies() -> None:
    assert "Java (JSP/Servlet)" in build_profile(_resp(cookies={"JSESSIONID": "x"})).technologies
    assert "Django (Python)" in build_profile(_resp(cookies={"csrftoken": "x"})).technologies


def test_profile_detects_waf_from_headers() -> None:
    assert build_profile(_resp(headers={"CF-RAY": "abc-LHR"})).waf == "Cloudflare"
    assert build_profile(_resp(headers={"X-Sucuri-ID": "1"})).waf == "Sucuri"
    assert build_profile(_resp(headers={"Server": "nginx"})).waf is None


# --- block detection ---------------------------------------------------------------------


def test_looks_blocked_by_status_and_body() -> None:
    assert looks_blocked(_resp(status=403)) is not None
    assert looks_blocked(_resp(status=200, text="Access Denied - request blocked")) is not None
    assert looks_blocked(_resp(status=200, text="normal page")) is None


# --- active WAF probe (fake client) ------------------------------------------------------


class _WafClient:
    """Blocks any request whose query looks malicious (a stand-in WAF)."""

    async def get(self, url: str, **kwargs) -> HttpResponse:
        if "dastcore_probe" in url or "script" in url.lower():
            return HttpResponse(status_code=403, text="Request blocked by WAF", url=url)
        return HttpResponse(status_code=200, headers={"Server": "nginx"}, text="<h1>ok</h1>", url=url)


async def test_active_probe_detects_waf() -> None:
    findings = await fingerprint_and_waf(_WafClient(), "http://target/")
    waf = [f for f in findings if f.rule_id == "waf-detected"]
    assert waf
    assert all(f.severity == "info" for f in findings)
    # The finding must name the host it was detected on (avoids attributing it to the wrong host).
    assert "target" in waf[0].name and "target" in waf[0].evidence[0].data


# --- integration against the vuln app ----------------------------------------------------


async def test_fingerprints_vuln_app_without_false_waf(vuln_app_url: str) -> None:
    async with HttpClient(
        ScopeConfig(allow_domains=["127.0.0.1"]), rate_limit=RateLimitConfig(requests_per_second=50)
    ) as client:
        findings = await fingerprint_and_waf(client, vuln_app_url)
    fp = [f for f in findings if f.rule_id == "tech-fingerprint"]
    assert fp, findings  # Werkzeug/Python server header is detected
    assert "Werkzeug" in fp[0].evidence[0].data or "Python" in fp[0].evidence[0].data
    assert not any(f.rule_id == "waf-detected" for f in findings)  # no WAF in front of the fixture
