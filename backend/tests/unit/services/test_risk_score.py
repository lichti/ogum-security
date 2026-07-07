"""
Unit tests for risk_score.py — pure logic, no external dependencies.

All ArangoDB interactions are replaced with lightweight in-memory fakes.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from app.services.risk_score import (
    _SEVERITY_WEIGHTS,
    _count_reachable_data_assets,
    _fetch_severity_counts,
    calculate_path_risk_score,
    calculate_resource_risk_score,
    score_to_severity,
)

# ---------------------------------------------------------------------------
# Helpers / fakes
# ---------------------------------------------------------------------------


def _make_db(
    findings: list[dict[str, Any]] | None = None,
    resource_doc: dict[str, Any] | None = None,
    reachable_count: int = 0,
) -> MagicMock:
    """Build a minimal ArangoDB-compatible mock."""
    db = MagicMock()

    # _fetch_severity_counts via db.aql.execute
    severity_rows = []
    if findings:
        from collections import Counter

        counts = Counter(f["severity"] for f in findings if f.get("status") == "FAIL")
        severity_rows = [{"sev": sev, "cnt": cnt} for sev, cnt in counts.items()]
    db.aql.execute.return_value = iter(severity_rows)

    # _fetch_resource_doc via db.collection(col).get(key)
    col_mock = MagicMock()
    col_mock.get.return_value = resource_doc
    db.collection.return_value = col_mock

    return db


# ---------------------------------------------------------------------------
# _fetch_severity_counts
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_fetch_severity_counts_empty() -> None:
    db = MagicMock()
    db.aql.execute.return_value = iter([])
    counts = _fetch_severity_counts(db, "res-1", "tenant-1")
    assert counts == {}


@pytest.mark.unit
def test_fetch_severity_counts_mixed_severities() -> None:
    db = MagicMock()
    db.aql.execute.return_value = iter(
        [
            {"sev": "CRITICAL", "cnt": 2},
            {"sev": "HIGH", "cnt": 3},
            {"sev": "MEDIUM", "cnt": 1},
        ]
    )
    counts = _fetch_severity_counts(db, "res-1", "tenant-1")
    assert counts == {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 1}


@pytest.mark.unit
def test_fetch_severity_counts_ignores_non_dict_rows() -> None:
    db = MagicMock()
    db.aql.execute.return_value = iter(["bad-row", None, {"sev": "LOW", "cnt": 1}])
    counts = _fetch_severity_counts(db, "res-1", "tenant-1")
    assert counts == {"LOW": 1}


# ---------------------------------------------------------------------------
# _count_reachable_data_assets
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_count_reachable_returns_zero_on_exception() -> None:
    db = MagicMock()
    db.aql.execute.side_effect = Exception("AQL error")
    count = _count_reachable_data_assets(db, "res-1", "resources", "tenant-1")
    assert count == 0


@pytest.mark.unit
def test_count_reachable_returns_integer() -> None:
    db = MagicMock()
    db.aql.execute.return_value = iter([3])
    count = _count_reachable_data_assets(db, "res-1", "resources", "tenant-1")
    assert count == 3


@pytest.mark.unit
def test_count_reachable_empty_cursor_returns_zero() -> None:
    db = MagicMock()
    db.aql.execute.return_value = iter([])
    count = _count_reachable_data_assets(db, "res-1", "resources", "tenant-1")
    assert count == 0


# ---------------------------------------------------------------------------
# calculate_resource_risk_score — resource not found
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_risk_score_returns_zero_when_resource_not_found() -> None:
    db = MagicMock()
    db.collection.return_value.get.return_value = None
    score = calculate_resource_risk_score(db, "nonexistent", "tenant-1")
    assert score == 0.0


@pytest.mark.unit
def test_risk_score_returns_zero_when_no_findings() -> None:
    db = MagicMock()
    col_mock = MagicMock()
    col_mock.get.return_value = {"resource_id": "res-1", "is_public": False}
    db.collection.return_value = col_mock
    db.aql.execute.return_value = iter([])  # no findings
    score = calculate_resource_risk_score(db, "res-1", "tenant-1")
    assert score == 0.0


# ---------------------------------------------------------------------------
# calculate_resource_risk_score — basic severity_base
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_risk_score_single_critical_finding() -> None:
    db = MagicMock()
    col_mock = MagicMock()
    col_mock.get.return_value = {"resource_id": "res-1", "is_public": False}
    db.collection.return_value = col_mock

    # First call: severity counts — second call: blast radius
    db.aql.execute.side_effect = [
        iter([{"sev": "CRITICAL", "cnt": 1}]),
        iter([0]),  # 0 reachable data assets
    ]
    score = calculate_resource_risk_score(db, "res-1", "tenant-1")
    # severity_base = 10, exposure=1, blast_factor=1.0 → 10 * 1 * 1 = 10
    assert score == 10.0


@pytest.mark.unit
def test_risk_score_exposure_factor_doubles_score() -> None:
    db = MagicMock()
    col_mock = MagicMock()
    col_mock.get.return_value = {"resource_id": "res-1", "is_public": True}
    db.collection.return_value = col_mock
    db.aql.execute.side_effect = [
        iter([{"sev": "CRITICAL", "cnt": 1}]),
        iter([0]),
    ]
    score = calculate_resource_risk_score(db, "res-1", "tenant-1")
    # 10 * 2 * 1 = 20
    assert score == 20.0


@pytest.mark.unit
def test_risk_score_is_internet_facing_flag_triggers_exposure() -> None:
    db = MagicMock()
    col_mock = MagicMock()
    col_mock.get.return_value = {"resource_id": "res-1", "is_public": False, "is_internet_facing": True}
    db.collection.return_value = col_mock
    db.aql.execute.side_effect = [
        iter([{"sev": "HIGH", "cnt": 1}]),
        iter([0]),
    ]
    score = calculate_resource_risk_score(db, "res-1", "tenant-1")
    # 7 * 2 * 1 = 14
    assert score == 14.0


@pytest.mark.unit
def test_risk_score_blast_radius_increases_score() -> None:
    db = MagicMock()
    col_mock = MagicMock()
    col_mock.get.return_value = {"resource_id": "res-1", "is_public": False}
    db.collection.return_value = col_mock
    db.aql.execute.side_effect = [
        iter([{"sev": "HIGH", "cnt": 1}]),  # severity_base=7
        iter([5]),  # 5 reachable → blast_factor = 1 + 5/5 = 2.0
    ]
    score = calculate_resource_risk_score(db, "res-1", "tenant-1")
    # 7 * 1 * 2 = 14
    assert score == 14.0


@pytest.mark.unit
def test_risk_score_blast_factor_capped_at_two() -> None:
    db = MagicMock()
    col_mock = MagicMock()
    col_mock.get.return_value = {"resource_id": "res-1", "is_public": False}
    db.collection.return_value = col_mock
    db.aql.execute.side_effect = [
        iter([{"sev": "HIGH", "cnt": 1}]),
        iter([100]),  # 100 reachable → blast_factor = 1 + min(100/5, 1) = 2.0 (capped)
    ]
    score = calculate_resource_risk_score(db, "res-1", "tenant-1")
    # 7 * 1 * 2 = 14
    assert score == 14.0


@pytest.mark.unit
def test_risk_score_severity_base_capped_at_50() -> None:
    db = MagicMock()
    col_mock = MagicMock()
    col_mock.get.return_value = {"resource_id": "res-1", "is_public": False}
    db.collection.return_value = col_mock
    db.aql.execute.side_effect = [
        iter([{"sev": "CRITICAL", "cnt": 10}]),  # raw = 100 → capped at 50
        iter([0]),
    ]
    score = calculate_resource_risk_score(db, "res-1", "tenant-1")
    # severity_base=50, exposure=1, blast=1 → 50
    assert score == 50.0


@pytest.mark.unit
def test_risk_score_capped_at_100() -> None:
    db = MagicMock()
    col_mock = MagicMock()
    col_mock.get.return_value = {"resource_id": "res-1", "is_public": True}
    db.collection.return_value = col_mock
    db.aql.execute.side_effect = [
        iter([{"sev": "CRITICAL", "cnt": 10}]),  # base=50, exposure=2 → 100
        iter([100]),  # blast_factor=2 → would be 200 but capped at 100
    ]
    score = calculate_resource_risk_score(db, "res-1", "tenant-1")
    assert score == 100.0


@pytest.mark.unit
def test_risk_score_in_attack_path_enforces_minimum() -> None:
    db = MagicMock()
    col_mock = MagicMock()
    col_mock.get.return_value = {"resource_id": "res-1", "is_public": False}
    db.collection.return_value = col_mock
    db.aql.execute.side_effect = [
        iter([{"sev": "LOW", "cnt": 1}]),  # score would be 1 without minimum
        iter([0]),
    ]
    score = calculate_resource_risk_score(db, "res-1", "tenant-1", in_attack_path=True)
    assert score == 40.0


@pytest.mark.unit
def test_risk_score_in_attack_path_does_not_lower_score() -> None:
    db = MagicMock()
    col_mock = MagicMock()
    col_mock.get.return_value = {"resource_id": "res-1", "is_public": True}
    db.collection.return_value = col_mock
    db.aql.execute.side_effect = [
        iter([{"sev": "CRITICAL", "cnt": 5}]),  # base=50, exposure=2 → 100
        iter([0]),
    ]
    score = calculate_resource_risk_score(db, "res-1", "tenant-1", in_attack_path=True)
    assert score == 100.0  # stays at 100, not lowered to 40


@pytest.mark.unit
def test_risk_score_informational_findings_only() -> None:
    db = MagicMock()
    col_mock = MagicMock()
    col_mock.get.return_value = {"resource_id": "res-1", "is_public": False}
    db.collection.return_value = col_mock
    db.aql.execute.side_effect = [
        iter([{"sev": "INFORMATIONAL", "cnt": 2}]),  # 2 * 0.5 = 1.0
        iter([0]),
    ]
    score = calculate_resource_risk_score(db, "res-1", "tenant-1")
    assert score == 1.0


@pytest.mark.unit
def test_risk_score_unknown_severity_uses_weight_1() -> None:
    db = MagicMock()
    col_mock = MagicMock()
    col_mock.get.return_value = {"resource_id": "res-1", "is_public": False}
    db.collection.return_value = col_mock
    db.aql.execute.side_effect = [
        iter([{"sev": "UNKNOWN", "cnt": 3}]),  # 3 * 1.0 (fallback) = 3.0
        iter([0]),
    ]
    score = calculate_resource_risk_score(db, "res-1", "tenant-1")
    assert score == 3.0


@pytest.mark.unit
def test_risk_score_uses_resource_id_from_doc() -> None:
    db = MagicMock()
    col_mock = MagicMock()
    col_mock.get.return_value = {"resource_id": "actual-resource-id", "is_public": False}
    db.collection.return_value = col_mock
    db.aql.execute.side_effect = [iter([]), iter([])]

    calculate_resource_risk_score(db, "some-key", "tenant-1")

    first_call_bind_vars = db.aql.execute.call_args_list[0][1]["bind_vars"]
    assert first_call_bind_vars["resource_id"] == "actual-resource-id"


@pytest.mark.unit
def test_risk_score_falls_back_to_key_when_no_resource_id() -> None:
    db = MagicMock()
    col_mock = MagicMock()
    col_mock.get.return_value = {"is_public": False}  # no resource_id field
    db.collection.return_value = col_mock
    db.aql.execute.side_effect = [iter([]), iter([])]

    calculate_resource_risk_score(db, "the-key", "tenant-1")

    first_call_bind_vars = db.aql.execute.call_args_list[0][1]["bind_vars"]
    assert first_call_bind_vars["resource_id"] == "the-key"


@pytest.mark.unit
def test_risk_score_respects_custom_collection() -> None:
    db = MagicMock()
    col_mock = MagicMock()
    col_mock.get.return_value = {"resource_id": "r1", "is_public": False}
    db.collection.return_value = col_mock
    db.aql.execute.side_effect = [iter([]), iter([])]

    calculate_resource_risk_score(db, "r1", "tenant-1", collection="identities")
    db.collection.assert_called_with("identities")


# ---------------------------------------------------------------------------
# calculate_path_risk_score
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_path_risk_score_empty_nodes_returns_zero() -> None:
    assert calculate_path_risk_score([], hop_count=1) == 0.0


@pytest.mark.unit
def test_path_risk_score_zero_hops_returns_zero() -> None:
    assert calculate_path_risk_score([{"risk_score": 50}], hop_count=0) == 0.0


@pytest.mark.unit
def test_path_risk_score_single_hop_depth_factor() -> None:
    # depth_factor = 1 + 1/1 = 2.0
    # max_score = 30, result = 30 * 2 = 60
    score = calculate_path_risk_score([{"risk_score": 30}], hop_count=1)
    assert score == 60.0


@pytest.mark.unit
def test_path_risk_score_two_hops_lower_than_one_hop() -> None:
    nodes = [{"risk_score": 30}]
    one_hop = calculate_path_risk_score(nodes, hop_count=1)  # depth = 2.0
    two_hops = calculate_path_risk_score(nodes, hop_count=2)  # depth = 1.5
    assert one_hop > two_hops


@pytest.mark.unit
def test_path_risk_score_uses_max_node_score() -> None:
    nodes = [{"risk_score": 10}, {"risk_score": 50}, {"risk_score": 5}]
    # max = 50, depth = 1 + 1/2 = 1.5 → 75
    score = calculate_path_risk_score(nodes, hop_count=2)
    assert score == 75.0


@pytest.mark.unit
def test_path_risk_score_capped_at_100() -> None:
    nodes = [{"risk_score": 90}]
    # depth_factor = 2.0 → 90*2=180 → capped at 100
    score = calculate_path_risk_score(nodes, hop_count=1)
    assert score == 100.0


@pytest.mark.unit
def test_path_risk_score_handles_missing_risk_score_field() -> None:
    nodes = [{"name": "no-score-field"}, {"risk_score": None}]
    score = calculate_path_risk_score(nodes, hop_count=1)
    assert score == 0.0


@pytest.mark.unit
def test_path_risk_score_four_hops() -> None:
    nodes = [{"risk_score": 40}]
    # depth_factor = 1 + 1/4 = 1.25 → 40 * 1.25 = 50
    score = calculate_path_risk_score(nodes, hop_count=4)
    assert score == 50.0


# ---------------------------------------------------------------------------
# score_to_severity
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    "score,expected",
    [
        (0.0, "INFORMATIONAL"),
        (1.0, "LOW"),
        (24.9, "LOW"),
        (25.0, "MEDIUM"),
        (49.9, "MEDIUM"),
        (50.0, "HIGH"),
        (74.9, "HIGH"),
        (75.0, "CRITICAL"),
        (100.0, "CRITICAL"),
    ],
)
def test_score_to_severity_boundaries(score: float, expected: str) -> None:
    assert score_to_severity(score) == expected


# ---------------------------------------------------------------------------
# _SEVERITY_WEIGHTS completeness
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_severity_weights_include_all_standard_levels() -> None:
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        assert sev in _SEVERITY_WEIGHTS
        assert _SEVERITY_WEIGHTS[sev] > 0


@pytest.mark.unit
def test_severity_weights_order() -> None:
    assert _SEVERITY_WEIGHTS["CRITICAL"] > _SEVERITY_WEIGHTS["HIGH"]
    assert _SEVERITY_WEIGHTS["HIGH"] > _SEVERITY_WEIGHTS["MEDIUM"]
    assert _SEVERITY_WEIGHTS["MEDIUM"] > _SEVERITY_WEIGHTS["LOW"]
    assert _SEVERITY_WEIGHTS["LOW"] > _SEVERITY_WEIGHTS["INFORMATIONAL"]
