"""US-01.19 — guard de SSRF/path traversal do IaC scan."""

import pytest

from app.services import iac_guard
from app.services.iac_guard import IacScanRejectedError, confine_scan_path, validate_repo_url

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _public_dns(monkeypatch):
    """Suíte unitária: DNS 'resolve' sempre para um IP público fake."""
    monkeypatch.setattr(iac_guard.socket, "getaddrinfo", lambda host, port: [(2, 1, 6, "", ("93.184.216.34", 0))])


def test_https_host_in_allowlist_passes():
    assert validate_repo_url("https://github.com/org/repo.git")


def test_ssh_and_git_forms_pass():
    assert validate_repo_url("ssh://git@github.com/org/repo.git")
    assert validate_repo_url("git@github.com:org/repo.git")


def test_disallowed_host_rejected():
    with pytest.raises(IacScanRejectedError, match="IAC_ALLOWED_HOSTS"):
        validate_repo_url("https://evil.example.com/org/repo.git")


def test_non_git_scheme_rejected():
    with pytest.raises(IacScanRejectedError, match="https"):
        validate_repo_url("http://github.com/org/repo.git")
    with pytest.raises(IacScanRejectedError):
        validate_repo_url("file:///etc/passwd")


def test_private_dns_rejected(monkeypatch):
    monkeypatch.setattr(iac_guard.socket, "getaddrinfo", lambda host, port: [(2, 1, 6, "", ("10.0.0.5", 0))])
    with pytest.raises(IacScanRejectedError, match="non-routable"):
        validate_repo_url("https://github.com/org/repo.git")


def test_metadata_ip_rejected(monkeypatch):
    monkeypatch.setattr(iac_guard.socket, "getaddrinfo", lambda host, port: [(2, 1, 6, "", ("169.254.169.254", 0))])
    with pytest.raises(IacScanRejectedError, match="non-routable"):
        validate_repo_url("https://github.com/org/repo.git")


def test_unresolvable_host_rejected(monkeypatch):
    def _boom(host, port):
        raise iac_guard.socket.gaierror(8, "nodename nor servname provided")

    monkeypatch.setattr(iac_guard.socket, "getaddrinfo", _boom)
    with pytest.raises(IacScanRejectedError, match="does not resolve"):
        validate_repo_url("https://github.com/org/repo.git")


# ── path confinement ──────────────────────────────────────────────────────────


def test_relative_path_inside_clone_passes(tmp_path):
    result = confine_scan_path(tmp_path, "infra/terraform")
    assert result == (tmp_path / "infra/terraform").resolve()


def test_dot_passes(tmp_path):
    assert confine_scan_path(tmp_path, ".") == tmp_path.resolve()


def test_traversal_rejected(tmp_path):
    with pytest.raises(IacScanRejectedError, match="escapes"):
        confine_scan_path(tmp_path, "../../etc/passwd")


def test_absolute_path_rejected(tmp_path):
    with pytest.raises(IacScanRejectedError, match="escapes"):
        confine_scan_path(tmp_path, "/etc/passwd")


def test_symlink_escape_rejected(tmp_path):
    outside = tmp_path.parent / "outside-secret"
    outside.mkdir(exist_ok=True)
    link = tmp_path / "link"
    link.symlink_to(outside)
    with pytest.raises(IacScanRejectedError, match="escapes"):
        confine_scan_path(tmp_path, "link")
