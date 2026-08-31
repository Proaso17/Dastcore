"""Run the accuracy benchmark end-to-end: serve the labeled target, crawl + scan it, score the result.

Shippable so ``dastcore benchmark`` proves the precision/recall/F1 claim on any machine — the same
labeled target and scoring the test suite uses, exposed as a command. Fully offline (a local Flask
target + a local OAST collector); nothing leaves the machine.
"""

from __future__ import annotations

import logging
import socket
import threading

from werkzeug.serving import make_server

from dastcore.benchmark.app import EXPECTED, create_app
from dastcore.benchmark.scorer import BenchmarkResult, detected_from_findings, score
from dastcore.config import RateLimitConfig, ScopeConfig
from dastcore.core.http_client import HttpClient
from dastcore.discovery.crawler_http import HttpCrawler
from dastcore.engine.oast import LocalOastServer
from dastcore.engine.rule_engine import load_rules
from dastcore.engine.scanner import Scanner

logging.getLogger("werkzeug").setLevel(logging.ERROR)  # keep the scorecard clean of request logs


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def run_benchmark() -> BenchmarkResult:
    """Serve the labeled target, run a real crawl + scan, and return the scored result."""
    port = _free_port()
    server = make_server("127.0.0.1", port, create_app(), threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        scope = ScopeConfig(allow_domains=["127.0.0.1"])
        rate = RateLimitConfig(requests_per_second=100, max_concurrency=20)
        oast = LocalOastServer()
        await oast.start()
        try:
            async with HttpClient(scope, rate_limit=rate) as client:
                discovered = await HttpCrawler(client).crawl(f"http://127.0.0.1:{port}/")
                findings = await Scanner(client, load_rules(), oast=oast, oob_poll_attempts=6).scan(discovered)
        finally:
            await oast.stop()
    finally:
        server.shutdown()
        thread.join(timeout=5)
    return score(detected_from_findings(findings), EXPECTED)
