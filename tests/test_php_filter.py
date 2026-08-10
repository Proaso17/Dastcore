"""php://filter LFI oracle: fires only when a php://filter payload made the app return
base64 that decodes to PHP source; a plain base64 blob or a non-wrapper payload is safe."""

from __future__ import annotations

import base64

from dastcore.core.models import HttpResponse
from dastcore.validation.oracles import check_php_filter

_WRAPPER = "php://filter/convert.base64-encode/resource=index.php"


def _resp(text: str) -> HttpResponse:
    return HttpResponse(status_code=200, text=text)


def test_flags_base64_php_source() -> None:
    blob = base64.b64encode(b"<?php $secret = 'x'; ?>").decode()
    ev = check_php_filter(_resp(blob), _WRAPPER)
    assert ev is not None and ev.type == "response_match"


def test_short_tag_variant_is_flagged() -> None:
    blob = base64.b64encode(b"<?= $config ?>\nmore php").decode()
    assert check_php_filter(_resp(blob), _WRAPPER) is not None


def test_plain_base64_is_not_flagged() -> None:
    # long base64 that decodes to non-PHP text must not fire
    blob = base64.b64encode(b"just some ordinary file contents, nothing executable here at all").decode()
    assert check_php_filter(_resp(blob), _WRAPPER) is None


def test_non_wrapper_payload_never_fires() -> None:
    blob = base64.b64encode(b"<?php echo 1; ?>").decode()
    assert check_php_filter(_resp(blob), "../../../etc/passwd") is None


def test_no_base64_in_body() -> None:
    assert check_php_filter(_resp("welcome to the file viewer"), _WRAPPER) is None
