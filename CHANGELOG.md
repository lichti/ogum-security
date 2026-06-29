# Changelog

All notable changes to Ogum Security are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Commit types that trigger version bumps:
- `feat:` → **MINOR** (`0.1.0` → `0.2.0`)
- `fix:` → **PATCH** (`0.1.0` → `0.1.1`)
- `BREAKING CHANGE:` footer → **MAJOR** (`0.x.x` → `1.0.0`)
- `chore:`, `docs:`, `test:`, `refactor:`, `ci:` → no bump (included in next release)

---

## [Unreleased]

### Added
<!-- New features since the last release. -->

### Changed
<!-- Changes to existing features. -->

### Fixed
<!-- Bug fixes. -->

### Removed
<!-- Removed features or deprecated items. -->

### Security
<!-- Security patches and advisories. -->

---

## [0.1.0] - 2026-06-28

First release — MVP foundation: project scaffold, infrastructure stack, and
Ogum.Inventory Sprint 1 (AWS basic discovery).

### Added

**Ogum.Inventory — Sprint 1 (AWS Basic Discovery)**
- `app/models/inventory.py`: Pydantic v2 schemas — `ResourceBase`, `AWSResource`,
  `Identity`, `NetworkEndpoint`, `DataAsset`. `AWSResource` and `Identity` auto-extract
  `account_id` from ARN. All models expose `arango_key()`, `to_arango_doc()`,
  and `to_arango_update()` for idempotent ArangoDB persistence.
- `app/db/init.py`: idempotent tenant schema initializer — 5 vertex collections
  (`resources`, `identities`, `vulnerabilities`, `network_endpoints`, `data_assets`),
  5 edge collections (`EXPOSED_TO`, `ASSUMES_ROLE`, `CONTAINS_BUG`,
  `STORES_SENSITIVE_DATA`, `ROUTES_TRAFFIC`), and persistent indexes on
  `tenant_id`, `provider`, `resource_type`, and `resource_id`.
- `app/workers/celery_app.py`: Celery application bound to Redis broker/backend.
- `app/workers/tasks/discovery.py`: `discover_aws_basic` Celery task — discovers
  EC2 instances, IAM roles/users, and S3 buckets; upserts to ArangoDB;
  soft-deletes resources absent from the current run (`status: deleted`).
  `retry_with_backoff` decorator handles AWS throttling with exponential
  backoff + jitter (max 5 retries, max 60s delay).
- Full test suite — 39 tests, 0 failures:
  - Unit tests for all inventory models and the `retry_with_backoff` decorator.
  - Integration tests for discovery persistence, upsert idempotency, soft-delete,
    throttle retry, and physical tenant isolation — all against real ArangoDB.

**Project Scaffold**
- Docker Compose stack: ArangoDB 3.12, Redis 7, Redpanda v24.2, Qdrant v1.11,
  Ollama, FastAPI backend, Celery worker, Next.js frontend.
- FastAPI entrypoint (`app/main.py`) with `/health` endpoint.
- `app/core/config.py`: Pydantic-settings configuration with full env-var support.
- 4-layer test structure: `unit`, `integration`, `security`, `e2e`.
- `backend/pyproject.toml`: Poetry-managed dependencies — FastAPI, Celery, Prowler v5,
  python-arango, boto3, moto, LangChain, Qdrant, Ollama.
- Dockerfiles for backend and frontend.
- `docs/getting-started.md`, `docs/overview.md`, `CONTRIBUTING.md`.

**Ogum.CDR — Specification**
- Cloud Detection and Response module design: two-tier response model
  (Tier 1 automatic < 10s, Tier 2 human-approved), YAML playbooks,
  forensic collection before destructive actions, immutable audit log.

### Changed
- Upgraded Prowler to v5 (`prowler-core` sub-package) with native OCSF output,
  Prowler Hub API, and SARIF output for IaC findings.
- Upgraded target Python runtime to 3.13.

---

[Unreleased]: https://github.com/ogum-security/ogum-security/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ogum-security/ogum-security/releases/tag/v0.1.0
