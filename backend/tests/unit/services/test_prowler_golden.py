"""US-13.09 — normalização do ProwlerService contra fixtures dourados.

A suíte histórica mockava o Prowler inteiro com strings simples, e os bugs
reais (Status/Severity (str, Enum) sem __str__ → 100% FAIL/MEDIUM) passaram
ilesos. Os fixtures em tests/fixtures/prowler/golden/ preservam a FORMA dos
OutputFinding reais (enum-like com .value, metadata aninhada, mixed-case) e
são a base destes testes de normalização. Recaptura: runbook de QA
(docs/qa/cspm-compliance.md) via scripts/capture_prowler_fixtures.py.
"""

import json
from types import SimpleNamespace
from typing import Any

import pytest

from app.models.finding import FindingStatus, SeverityLevel
from app.services.prowler_service import ProwlerService

pytestmark = pytest.mark.unit

_GOLDEN = __file__.rsplit("/tests/", 1)[0] + "/tests/fixtures/prowler/golden/aws_findings.json"

# _normalize precisa de tenant/account/job para montar o Finding
_NORM_KWARGS = {
    "cloud_provider": "aws",
    "tenant_id": "fixture-tenant",
    "account_id": "123456789012",
    "scan_job_id": "job-golden",
}


def _load_findings() -> list[dict[str, Any]]:
    with open(_GOLDEN) as fh:
        return json.load(fh)["findings"]


def _as_output_finding(d: dict[str, Any]) -> SimpleNamespace:
    """Reconstitui o duck-typing do OutputFinding: metadata com atributos,
    enums com .value onde o fixture marca string 'enum:' (schema real do
    Prowler — Status/Severity são (str, Enum) SEM __str__)."""

    def _wrap(value: Any) -> Any:
        if isinstance(value, dict):
            return SimpleNamespace(**{k: _wrap(v) for k, v in value.items()})
        if isinstance(value, list):
            return [_wrap(v) for v in value]
        return value

    d = {k: _wrap(v) for k, v in d.items()}
    # Status/Severity como pseudo-enum: str(x) != x, .value == x — a classe de
    # bug histórica que fixtures de string simples não capturavam.
    d["status"] = _EnumLike(d["status"])
    if isinstance(d.get("metadata"), SimpleNamespace) and hasattr(d["metadata"], "Severity"):
        d["metadata"].Severity = _EnumLike(d["metadata"].Severity)
    return SimpleNamespace(**d)


class _EnumLike:
    """(str, Enum) sem __str__: str(obj) == 'ClassName.value'."""

    def __init__(self, value: str) -> None:
        self.value = value
        self._cls_name = type(value).__name__ or "Status"

    def __str__(self) -> str:
        return f"{type(self).__name__}.{self.value}"


@pytest.mark.unit
def test_golden_fixture_exists_and_is_valid():
    findings = _load_findings()
    assert len(findings) >= 5, "golden fixture deve cobrir múltiplos cenários"
    severities = {f["metadata"]["Severity"].lower() for f in findings}
    assert {"critical", "high", "medium", "low", "informational"} <= severities
    statuses = {f["status"].lower() for f in findings}
    assert {"fail", "pass", "manual"} <= statuses


@pytest.mark.unit
def test_normalizes_all_golden_findings():
    service = ProwlerService()
    for raw in _load_findings():
        finding = service._normalize(_as_output_finding(raw), **_NORM_KWARGS)
        assert finding is not None
        assert finding.tenant_id == "fixture-tenant"


@pytest.mark.unit
def test_status_mapping_is_exact_not_fail_default():
    """Bug histórico: (str, Enum) sem __str__ → tudo virava FAIL."""
    service = ProwlerService()
    by_status = {}
    for raw in _load_findings():
        finding = service._normalize(_as_output_finding(raw), **_NORM_KWARGS)
        by_status.setdefault(raw["status"].lower(), finding.status)

    assert by_status["fail"] is FindingStatus.FAIL
    assert by_status["pass"] is FindingStatus.PASS_
    assert by_status["manual"] is FindingStatus.PASS_


@pytest.mark.unit
def test_severity_mapping_is_exact_not_medium_default():
    """Bug histórico: (str, Enum) sem __str__ → tudo virava MEDIUM."""
    service = ProwlerService()
    mapping = {}
    for raw in _load_findings():
        finding = service._normalize(_as_output_finding(raw), **_NORM_KWARGS)
        mapping[raw["metadata"]["Severity"].lower()] = finding.severity

    assert mapping["critical"] is SeverityLevel.CRITICAL
    assert mapping["high"] is SeverityLevel.HIGH
    assert mapping["medium"] is SeverityLevel.MEDIUM
    assert mapping["low"] is SeverityLevel.LOW
    assert mapping["informational"] is SeverityLevel.INFORMATIONAL


@pytest.mark.unit
def test_mixed_case_and_legacy_shapes_normalize():
    """Fixture 8: status 'fail' minúsculo + Severity 'High' capitalizado."""
    raw = _load_findings()[-1]
    assert raw["status"] == "fail" and raw["metadata"]["Severity"] == "High"
    finding = ProwlerService()._normalize(_as_output_finding(raw), **_NORM_KWARGS)
    assert finding.status is FindingStatus.FAIL
    assert finding.severity is SeverityLevel.HIGH


@pytest.mark.unit
def test_remediation_fields_extracted():
    raw = _load_findings()[0]
    finding = ProwlerService()._normalize(_as_output_finding(raw), **_NORM_KWARGS)
    assert finding.remediation == "Enable MFA for the IAM user."
    assert finding.remediation_code == "aws iam enable-mfa-device --user-name john"
