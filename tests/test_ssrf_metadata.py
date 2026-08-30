"""SSRF to cloud metadata: a URL-ish sink that fetches the injected URL and returns the metadata is
flagged (AWS escalates to IAM creds); a sink that only echoes the URL, or a non-sink param, is not.
Offline — a fake server simulates the SSRF fetch."""

from __future__ import annotations

from dastcore.core.models import HttpRequest, HttpResponse
from dastcore.detectors.ssrf_metadata import run_cloud_ssrf_checks

_AWS_LIST = "ami-id\nhostname\niam/\ninstance-id\nlocal-ipv4\nplacement/\n"
_AWS_ROLE = "dastcore-ec2-role"
_AWS_CREDS = '{"Code":"Success","AccessKeyId":"ASIAEXAMPLE12345","SecretAccessKey":"s3cr3t","Token":"tok","Expiration":"2026-01-01"}'


class _SsrfServer:
    """A sink at param ``url`` that server-side-fetches the injected URL and returns its body.
    ``echo_only=True`` reflects the URL string instead of fetching (must NOT be flagged)."""

    def __init__(self, *, echo_only: bool = False) -> None:
        self.echo_only = echo_only

    async def request(self, method: str, url: str, *, params=None, json=None, data=None, **_kw) -> HttpResponse:
        # the sink fetches whatever injected value looks like a URL (any param name)
        values = list((params or {}).values()) + list((json or {}).values()) + list((data or {}).values())
        fetched = next((str(v) for v in values if str(v).startswith("http")), "")
        if self.echo_only:
            return HttpResponse(status_code=200, text=f"you asked for {fetched}", url=url)
        if fetched == "http://169.254.169.254/latest/meta-data/":
            return HttpResponse(status_code=200, text=_AWS_LIST, url=url)
        if fetched == "http://169.254.169.254/latest/meta-data/iam/security-credentials/":
            return HttpResponse(status_code=200, text=_AWS_ROLE, url=url)
        if fetched == f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{_AWS_ROLE}":
            return HttpResponse(status_code=200, text=_AWS_CREDS, url=url)
        return HttpResponse(status_code=200, text="nothing here", url=url)


async def test_flags_aws_ssrf_and_extracts_credentials() -> None:
    req = HttpRequest(method="GET", url="http://t.test/fetch", params={"url": "http://example.com/ok"})
    findings = await run_cloud_ssrf_checks(_SsrfServer(), [req])  # type: ignore[arg-type]
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "ssrf-cloud-metadata" and f.severity == "critical"  # creds extracted -> critical
    assert "IAM" in f.name or "credentials" in f.name.lower()
    assert "ASIAEXAM" in f.evidence[0].data and "s3cr3t" not in f.evidence[0].data  # key hinted, secret masked


async def test_echo_only_sink_is_not_flagged() -> None:
    req = HttpRequest(method="GET", url="http://t.test/fetch", params={"url": "http://example.com/ok"})
    findings = await run_cloud_ssrf_checks(_SsrfServer(echo_only=True), [req])  # type: ignore[arg-type]
    assert findings == []  # a mere reflection of the URL never carries the metadata signature -> zero-FP


async def test_non_sink_param_is_not_probed() -> None:
    req = HttpRequest(method="GET", url="http://t.test/search", params={"q": "hello"})
    findings = await run_cloud_ssrf_checks(_SsrfServer(), [req])  # type: ignore[arg-type]
    assert findings == []


async def test_urlish_value_is_treated_as_a_sink() -> None:
    # even a param not on the name list is probed if its value already looks like a URL
    req = HttpRequest(method="GET", url="http://t.test/x", params={"weird": "https://cdn.example.com/a.png"})
    findings = await run_cloud_ssrf_checks(_SsrfServer(), [req])  # type: ignore[arg-type]
    assert len(findings) == 1 and findings[0].injection_point.name == "weird"


class _FilteredSsrfServer:
    """A sink that *blocklists the literal link-local string* ``169.254.169.254`` but naively resolves
    an alternate IP encoding (decimal ``2852039166``) — the classic SSRF filter bypass."""

    async def request(self, method: str, url: str, *, params=None, json=None, data=None, **_kw) -> HttpResponse:
        values = list((params or {}).values()) + list((json or {}).values()) + list((data or {}).values())
        fetched = next((str(v) for v in values if str(v).startswith("http")), "")
        if "169.254.169.254" in fetched:  # literal is filtered
            return HttpResponse(status_code=403, text="blocked", url=url)
        canonical = fetched.replace("2852039166", "169.254.169.254")  # the parser resolves the encoding
        if canonical == "http://169.254.169.254/latest/meta-data/":
            return HttpResponse(status_code=200, text=_AWS_LIST, url=url)
        if canonical == "http://169.254.169.254/latest/meta-data/iam/security-credentials/":
            return HttpResponse(status_code=200, text=_AWS_ROLE, url=url)
        if canonical == f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{_AWS_ROLE}":
            return HttpResponse(status_code=200, text=_AWS_CREDS, url=url)
        return HttpResponse(status_code=200, text="nothing here", url=url)


async def test_ip_encoding_bypass_defeats_a_literal_blocklist() -> None:
    req = HttpRequest(method="GET", url="http://t.test/fetch", params={"url": "http://example.com/ok"})
    findings = await run_cloud_ssrf_checks(_FilteredSsrfServer(), [req])  # type: ignore[arg-type]
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "ssrf-cloud-metadata" and f.severity == "critical"
    assert "2852039166" in f.evidence[0].data  # the bypass encoding is recorded as evidence
    assert "ASIAEXAM" in f.evidence[0].data  # creds still extracted through the bypassed host
