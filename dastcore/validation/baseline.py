"""Baseline profiling and volatile-region normalization.

Before judging whether a mutated response *differs* from the base one, the engine
needs to know what "the same request" naturally looks like — its timing spread and
which parts of the body change on their own (CSRF tokens, nonces, timestamps, ids).
A `BaselineProfile` samples the base request a few times to capture that, so an
oracle can separate a real signal (a time-based delay, a content change caused by
the payload) from the app's own noise instead of firing on jitter.

`normalize_body` masks the volatile bits so two "identical" responses compare equal.
It's used by the timing oracle now and by the content/reflection oracles next.
"""

from __future__ import annotations

import difflib
import re
import statistics
from collections.abc import Iterable
from dataclasses import dataclass

from dastcore.core.models import HttpResponse

# Global volatile patterns: things that change between two identical requests.
_MASKS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Hidden CSRF/token/nonce form fields — mask the *value*, keep the structure.
    (re.compile(r'(?i)(name="[^"]*(?:csrf|token|nonce|authenticity)[^"]*"\s+value=")[^"]*(")'), r"\1{TOKEN}\2"),
    (re.compile(r'(?i)("(?:csrf[_-]?token|_token|nonce|authenticity_token)"\s*:\s*")[^"]{6,}(")'), r"\1{TOKEN}\2"),
    # ISO-8601 timestamps.
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "{TS}"),
    # UUIDs.
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "{UUID}"),
    # Long hex blobs (session ids, nonces, ETags).
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "{HEX}"),
    # Long digit runs (unix timestamps, large ids).
    (re.compile(r"\b\d{9,}\b"), "{NUM}"),
)


def normalize_body(text: str, extra_masks: Iterable[str] = ()) -> str:
    """Mask volatile regions so two naturally-different-but-equivalent bodies match.

    ``extra_masks`` are request-specific volatile substrings discovered by diffing
    baseline samples (things the global patterns don't know about).
    """
    for pattern, repl in _MASKS:
        text = pattern.sub(repl, text)
    for token in extra_masks:
        if token:
            text = text.replace(token, "{VOL}")
    return text


# A per-request volatile mask must look like a *token* (an id/nonce), not a chunk of
# real content — no whitespace or markup — so discovery never masks legitimate text.
_TOKENISH = re.compile(r"^[^\s<>\"'{}]{3,40}$")


def _discover_masks(bodies: list[str]) -> tuple[str, ...]:
    """Residual volatile substrings: token-like spans that still differ between two
    samples after the global masks. These are app-specific ids the patterns missed."""
    if len(bodies) < 2:
        return ()
    a, b = normalize_body(bodies[0]), normalize_body(bodies[1])
    masks: list[str] = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag in ("replace", "delete"):
            masks.append(a[i1:i2].strip())
        if tag in ("replace", "insert"):
            masks.append(b[j1:j2].strip())
    tokens = [m for m in masks if _TOKENISH.match(m)]
    return tuple(dict.fromkeys(tokens))[:20]  # dedupe, cap


@dataclass
class BaselineProfile:
    """A few samples of the same base request, plus what varies between them."""

    responses: list[HttpResponse]
    expected_ms: float
    jitter_ms: float
    extra_masks: tuple[str, ...] = ()

    @property
    def primary(self) -> HttpResponse:
        return self.responses[0]

    def normalize(self, text: str) -> str:
        return normalize_body(text, self.extra_masks)

    @property
    def stable(self) -> bool:
        """Whether the app returns the same normalized body every time (no residual noise)."""
        return len({self.normalize(r.text) for r in self.responses}) == 1


def similarity_ratio(a_text: str, b_text: str, extra_masks: Iterable[str] = ()) -> float:
    """How similar two bodies are (0..1) after volatile normalization."""
    a, b = normalize_body(a_text, extra_masks), normalize_body(b_text, extra_masks)
    if a == b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def responses_similar(a: HttpResponse, b: HttpResponse, baseline: BaselineProfile, *, threshold: float = 0.95) -> bool:
    """Whether two responses are effectively the same page (same status + similar body).

    Used by boolean-based blind detection to tell a TRUE condition (behaves like the
    baseline) from a FALSE one (differs), ignoring the app's own volatile noise.
    """
    if a.status_code != b.status_code:
        return False
    return similarity_ratio(a.text, b.text, baseline.extra_masks) >= threshold


def build_baseline(responses: list[HttpResponse]) -> BaselineProfile:
    """Build a profile from one or more samples of the same base request."""
    times = [r.elapsed_ms for r in responses]
    expected = statistics.median(times) if times else 0.0
    jitter = (max(times) - min(times)) if len(times) > 1 else 0.0
    masks = _discover_masks([r.text for r in responses])
    return BaselineProfile(responses=responses, expected_ms=expected, jitter_ms=jitter, extra_masks=masks)
