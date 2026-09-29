"""US-00.11 — equivalência do risk scoring em lote com a referência.

O AQL de `recalculate_risk_scores` deve produzir o mesmo score da
`calculate_resource_risk_score` (referência Python) para os mesmos dados.
"""

from __future__ import annotations

import pytest

from app.db.init import init_tenant_schema
from app.services.risk_score import calculate_resource_risk_score
from app.workers.tasks.attack_paths import recalculate_risk_scores
from tests.conftest import TEST_TENANT_A

pytestmark = pytest.mark.integration


def _seed(db) -> None:
    """Dois recursos: um exposto com findings críticos, um interno sem nada."""
    db.collection("resources").insert(
        {
            "_key": "ec2_exposed",
            "tenant_id": TEST_TENANT_A,
            "resource_id": "i-exposed",
            "resource_type": "ec2_instance",
            "is_public": True,
            "in_attack_path": True,
        }
    )
    db.collection("resources").insert(
        {
            "_key": "vol_internal",
            "tenant_id": TEST_TENANT_A,
            "resource_id": "vol-internal",
            "resource_type": "ebs_volume",
        }
    )
    for i, (sev, rid) in enumerate([("CRITICAL", "i-exposed"), ("HIGH", "i-exposed"), ("MEDIUM", "i-exposed")]):
        db.collection("findings").insert(
            {
                "finding_id": f"f-{i}",
                "tenant_id": TEST_TENANT_A,
                "check_id": f"check_{i}",
                "resource_id": rid,
                "severity": sev,
                "status": "FAIL",
            }
        )


@pytest.mark.integration
def test_batch_scores_match_reference(db_tenant_a):
    init_tenant_schema(db_tenant_a)
    _seed(db_tenant_a)

    result = recalculate_risk_scores.apply(kwargs={"tenant_id": TEST_TENANT_A}).get()
    assert result["errors"] == 0
    assert result["updated"] >= 2

    for key, collection in [("ec2_exposed", "resources"), ("vol_internal", "resources")]:
        expected = calculate_resource_risk_score(
            db_tenant_a, key, TEST_TENANT_A, collection=collection, in_attack_path=key == "ec2_exposed"
        )
        actual = db_tenant_a.collection(collection).get(key)["risk_score"]
        assert actual == pytest.approx(expected, abs=0.01), f"{key}: {actual} != {expected}"
