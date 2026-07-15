import pytest

from app.services.compliance_service import _score, _score_by_control


@pytest.mark.unit
class TestScore:
    def test_all_pass(self):
        assert _score(10, 0) == 100.0

    def test_all_fail(self):
        assert _score(0, 10) == 0.0

    def test_no_findings(self):
        assert _score(0, 0) == 0.0


@pytest.mark.unit
class TestScoreByControl:
    """control_status maps control_id -> (pass, fail, accepted, muted)."""

    def test_all_controls_passing(self):
        score, p, f, u = _score_by_control({"1.1": (2, 0, 0, 0), "1.2": (1, 0, 0, 0)}, catalog_control_ids=None)
        assert (score, p, f, u) == (100.0, 2, 0, 0)

    def test_control_with_any_fail_counts_as_failing(self):
        # 3 assets pass control 1.1, 1 asset fails it — the control is still Fail overall.
        score, p, f, u = _score_by_control({"1.1": (3, 1, 0, 0)}, catalog_control_ids=None)
        assert (score, p, f, u) == (0.0, 0, 1, 0)

    def test_mixed_controls(self):
        control_status = {"1.1": (2, 0, 0, 0), "1.2": (0, 3, 0, 0), "1.3": (1, 0, 0, 0)}
        score, p, f, u = _score_by_control(control_status, catalog_control_ids=None)
        assert p == 2
        assert f == 1
        assert u == 0
        assert score == 66.7

    def test_catalog_controls_without_findings_are_unscored(self):
        control_status = {"1.1": (2, 0, 0, 0)}
        catalog_ids = {"1.1", "1.2", "1.3"}
        score, p, f, u = _score_by_control(control_status, catalog_control_ids=catalog_ids)
        assert p == 1
        assert f == 0
        assert u == 2
        # Unscored excluded from the denominator — 1/1, not 1/3.
        assert score == 100.0

    def test_unscored_only_when_catalog_is_none_means_no_unscored_state(self):
        # No catalog available (non-AWS framework) — every control judged purely by findings.
        score, p, f, u = _score_by_control({"1.1": (1, 0, 0, 0)}, catalog_control_ids=None)
        assert u == 0

    def test_no_controls_at_all(self):
        score, p, f, u = _score_by_control({}, catalog_control_ids=None)
        assert (score, p, f, u) == (0.0, 0, 0, 0)

    def test_catalog_only_no_findings_yet_is_fully_unscored(self):
        score, p, f, u = _score_by_control({}, catalog_control_ids={"1.1", "1.2"})
        assert (score, p, f, u) == (0.0, 0, 0, 2)

    def test_accepted_only_control_folds_into_pass(self):
        # No real PASS/FAIL, only an accepted-risk finding — counts as Pass.
        score, p, f, u = _score_by_control({"1.1": (0, 0, 2, 0)}, catalog_control_ids=None)
        assert (score, p, f, u) == (100.0, 1, 0, 0)

    def test_muted_only_control_folds_into_unscored(self):
        # No real PASS/FAIL/ACCEPTED, only a muted finding — not evaluated for scoring.
        score, p, f, u = _score_by_control({"1.1": (0, 0, 0, 3)}, catalog_control_ids=None)
        assert (score, p, f, u) == (0.0, 0, 0, 1)

    def test_fail_wins_over_accepted_on_the_same_control(self):
        # One asset's risk was accepted, another asset genuinely fails — still Fail overall.
        score, p, f, u = _score_by_control({"1.1": (0, 1, 1, 0)}, catalog_control_ids=None)
        assert (score, p, f, u) == (0.0, 0, 1, 0)

    def test_pass_wins_over_muted_on_the_same_control(self):
        # A muted finding on one asset doesn't drag down a control other assets pass.
        score, p, f, u = _score_by_control({"1.1": (1, 0, 0, 2)}, catalog_control_ids=None)
        assert (score, p, f, u) == (100.0, 1, 0, 0)
