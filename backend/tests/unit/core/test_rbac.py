"""Unit tests — app.core.rbac (roles e permissões, Epic 06 Sprint 1).

Casos prescritos no sprint plan do épico:
- has_permission(Role.SecOps, "incidents:approve_tier2") -> True
- has_permission(Role.DevOps, "incidents:approve_tier2") -> False
"""

import pytest
from fastapi import HTTPException

from app.core.deps import CurrentUser
from app.core.rbac import Role, has_permission, require_permission


@pytest.mark.unit
def test_secops_has_tier2_approval():
    assert has_permission(Role.SecOps, "incidents:approve_tier2") is True


@pytest.mark.unit
def test_devops_lacks_tier2_approval():
    assert has_permission(Role.DevOps, "incidents:approve_tier2") is False


@pytest.mark.unit
def test_platform_admin_wildcard():
    assert has_permission(Role.PlatformAdmin, "qualquer:coisa") is True


@pytest.mark.unit
def test_auditor_is_read_only():
    assert has_permission(Role.Auditor, "scans:trigger") is False
    assert has_permission(Role.Auditor, "audit_log:read") is True


@pytest.mark.unit
def test_unknown_role_has_no_permissions():
    assert has_permission("Intern", "findings:read") is False


def _user(role: Role) -> CurrentUser:
    return CurrentUser(sub="u1", tenant_id="acme", role=role)


@pytest.mark.unit
def test_require_permission_passes_for_granted_role():
    gate = require_permission("findings:read")
    assert gate(_user(Role.SecOps)).role is Role.SecOps


@pytest.mark.unit
def test_require_permission_raises_403_for_denied_role():
    gate = require_permission("scans:trigger")
    with pytest.raises(HTTPException) as exc:
        gate(_user(Role.DevOps))
    assert exc.value.status_code == 403
