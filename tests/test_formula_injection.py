"""CSV / Formula Injection oracle: fires only for an un-neutralized formula at a cell
boundary in a spreadsheet response, so the standard `'`-prefix mitigation is safe and a
plain HTML echo is not flagged."""

from __future__ import annotations

from dastcore.core.models import HttpResponse
from dastcore.validation.oracles import check_formula_injection

PAYLOAD = "=1+1"


def _csv(text: str) -> HttpResponse:
    return HttpResponse(status_code=200, headers={"Content-Type": "text/csv; charset=utf-8"}, text=text)


def test_formula_at_cell_boundary_is_flagged() -> None:
    ev = check_formula_injection(_csv(f"name,note\r\n{PAYLOAD},exported\r\n"), PAYLOAD)
    assert ev is not None and ev.type == "response_match"


def test_apostrophe_prefixed_cell_is_safe() -> None:
    # the OWASP mitigation: a leading ' means the trigger no longer starts the cell
    assert check_formula_injection(_csv(f"name,note\r\n'{PAYLOAD},exported\r\n"), PAYLOAD) is None


def test_non_spreadsheet_content_type_is_ignored() -> None:
    html = HttpResponse(status_code=200, headers={"Content-Type": "text/html"}, text=f"<p>{PAYLOAD}</p>")
    assert check_formula_injection(html, PAYLOAD) is None


def test_excel_content_type_is_covered() -> None:
    xls = HttpResponse(
        status_code=200,
        headers={"content-type": "application/vnd.ms-excel"},
        text=f"a,b\r\n{PAYLOAD},2\r\n",
    )
    assert check_formula_injection(xls, PAYLOAD) is not None


def test_non_formula_payload_never_fires() -> None:
    assert check_formula_injection(_csv("name,note\r\nplain,exported\r\n"), "plain") is None


def test_formula_not_at_boundary_is_not_flagged() -> None:
    # reflected mid-cell (a spreadsheet won't treat it as a formula there)
    assert check_formula_injection(_csv(f"name,note\r\nx{PAYLOAD},exported\r\n"), PAYLOAD) is None
