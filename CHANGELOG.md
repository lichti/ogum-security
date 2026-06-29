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

- **Ogum.Inventory Sprint 3 — REST API + Inventory UI**
  - `GET /api/v1/inventory` — list resources with filters (`provider`, `resource_type`,
    `account_id`, `region`, `status`, `search`), `limit`/`offset` pagination, and
    `sort_by`/`sort_dir` ordering; returns standard `{data, meta, error}` envelope
  - `GET /api/v1/inventory/stats` — aggregate counts by provider, resource type, status;
    also returns `identity_count`, `data_asset_count`, and `last_discovery_at`
  - `GET /api/v1/inventory/{resource_key}` — full resource detail including all
    relationship edges (inbound + outbound across all 8 edge collections)
  - `POST /api/v1/inventory/discover` — enqueues `discover_aws` Celery task and returns
    `job_id` (Celery task ID); returns 422 for providers not yet implemented
  - `app/services/inventory_service.py` — ArangoDB query service; AQL built with
    `bind_vars` only (no string interpolation with user input); sort field validated
    against allowlist before use
  - `app/models/api_responses.py` — Pydantic v2 response models: `ApiResponse[T]`,
    `Meta`, `ResourceSummary`, `ResourceDetail`, `EdgeSummary`, `InventoryStats`,
    `DiscoverJobResponse`
  - `X-Tenant-ID` header (dev mode) — replaces JWT tenant extraction until Sprint 7;
    clearly marked as temporary in code comments
  - Frontend: Next.js 15 App Router scaffold — `layout.tsx`, `page.tsx` (→ /inventory),
    `globals.css`, `tsconfig.json`, `next.config.ts`, `tailwind.config.ts`
  - Frontend: `InventoryPage` (`src/app/inventory/page.tsx`) — full inventory UI with
    React Query data fetching, provider tabs, filters, paginated DataTable, and DetailPanel
  - Frontend: `DataTable` component — sortable table with Provider badge, name/ID,
    type, account, region, status badge, pagination controls, and skeleton loading state
  - Frontend: `ProviderTabs` component — All/AWS/Azure/GCP/K8s tabs with resource counts
  - Frontend: `Filters` component — search input (name/ARN/ID), resource type dropdown,
    region dropdown
  - Frontend: `DetailPanel` component — 420px slide-in panel with Metadata section,
    Tags, Relationships (edges with direction arrows), Findings placeholder, and
    "Open in console" deep-link for AWS resources
  - Frontend: `Badge` component (`components/ui/Badge.tsx`) — provider, status, and
    severity variants with dark-theme color coding (orange accent, slate palette)
  - Frontend: `Skeleton` component (`components/ui/Skeleton.tsx`) — loading placeholder
  - Frontend: `src/lib/types.ts` — TypeScript interfaces for all API response shapes
  - Frontend: `src/lib/api.ts` — Axios-based API client with `X-Tenant-ID` interceptor
  - Jest testing setup — `jest.config.js`, `jest.setup.ts`, `@testing-library/react`,
    `@testing-library/jest-dom`, `@testing-library/user-event` added to devDependencies
  - 16 backend API integration tests (100% passing) — happy path, filters, pagination,
    search, 422 validation, 404 for missing resource, stats aggregation, discover dispatch
  - 32 frontend component tests — Badge (11 tests), DataTable (9 tests), DetailPanel
    (12 tests); all passing with `@testing-library/react`

- **Ogum.Inventory Sprint 2 — Expanded AWS Discovery (`discover_aws` task)**
  - Full coverage: VPC, Subnet, Internet Gateway, Elastic IP, Security Group, RDS, Lambda,
    EKS, EKS, ECR, KMS (customer-managed keys only), Secrets Manager (metadata only),
    CloudTrail, and IAM Groups
  - `IdentityType.IAM_GROUP` enum value added to inventory model
  - Three new edge collections: `BELONGS_TO`, `ATTACHED_TO`, `MEMBER_OF`
  - `_upsert_edge` helper: idempotent AQL UPSERT keyed on `(_from, _to)`
  - `_create_resource_edges` orchestrator: builds BELONGS_TO (EC2→VPC, Subnet→VPC),
    ATTACHED_TO (SG→EC2, SG→Lambda), ROUTES_TRAFFIC (IGW→VPC),
    ASSUMES_ROLE (EC2/Lambda→IAM Role), and MEMBER_OF (IAM User→IAM Group) edges
  - `discover_aws` Celery task: full discovery with edge creation, replaces `discover_aws_basic`
    for production use; `discover_aws_basic` retained for backwards compatibility
  - `pythonpath = ["."]` added to `pyproject.toml` pytest config (no manual `PYTHONPATH` export needed)

- **Integration tests — Sprint 2 (17 new tests, 50 total passing)**
  - `TestAWSExpandedDiscovery`: VPC discovery, open-ingress SG marked `is_public=True`,
    RDS instance discovery, Lambda with execution role, ECR repository, soft-delete of removed VPC
  - `TestRelationshipEdgeCreation`: EC2→VPC (BELONGS_TO), SG→EC2 (ATTACHED_TO),
    IGW→VPC (ROUTES_TRAFFIC), Lambda→Role (ASSUMES_ROLE), 2-hop AQL traversal IGW→VPC→EC2

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
