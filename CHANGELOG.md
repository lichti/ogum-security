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

### Fixed

- **AWS discovery credential guard**: `NoCredentialsError` was not caught when `account_id` was
  already provided at registration — the `sts:GetCallerIdentity` call was skipped, so missing
  credentials were only detected mid-discovery inside `_list_vpcs`. Fixed by always calling STS
  upfront to validate credentials regardless of whether `account_id` is known.

### Added

- **Multi-method credential support for all providers**:
  - **AWS**: IAM Role (`role_arn` via `sts:AssumeRole`) and static API keys
    (`aws_access_key_id` / `aws_secret_access_key`, dev only) are both supported in the UI
    and API; ambient worker credentials remain the fallback when neither is provided
  - **Azure**: Service Principal (`azure_tenant_id` + `azure_client_id` + `azure_client_secret`)
    and `DefaultAzureCredential` (Managed Identity / ADC) are both selectable in the wizard
  - **GCP**: Service Account JSON and Application Default Credentials (ADC) are both supported
  - **Kubernetes**: external kubeconfig (JSON) and in-cluster ServiceAccount are both selectable
- **`credential_type` field** on `ProviderConfig`: records which credential method was used
  at registration time (`role`, `static`, `ambient`, `service_principal`, `managed_identity`,
  `service_account`, `adc`, `kubeconfig`, `incluster`) — no secrets stored
- **`azure_tenant_id` / `azure_client_id`** stored on `ProviderConfig` (non-secret, safe to
  persist) so re-triggered discovery can restore Azure credential context
- **`provider_key` threading** in `discover_azure` and `discover_gcp`: both tasks now accept
  and propagate the `provider_key` parameter so ArangoDB status updates work correctly
- **Status updates for Azure and GCP**: `_set_provider_status(db, provider_key, "active"|"error")`
  now called on task success and failure, consistent with AWS behavior
- **`MethodSelector` UI component** in `ConnectWizard`: segmented control for choosing
  credential method per provider — no separate page or modal required
- **Provider Management API** (`/api/v1/providers`): new endpoints `GET /{id}`, `PATCH /{id}`,
  and `POST /{id}/discover` for fetching, updating, and re-triggering discovery on a specific provider
- **Provider `status` field**: `ProviderConfig` now tracks `pending | active | error | disabled` state;
  status transitions automatically on discovery dispatch and enable/disable toggle
- **`ProviderUpdateRequest` model**: supports partial PATCH of `display_name`, `regions`, and `enabled`
- **`DiscoverResponse` model**: typed response for the re-trigger discovery endpoint
- **`ProviderType` enum**: provider field is now validated as a literal type (`aws | azure | gcp | k8s`)
- **`/providers` page** (frontend): connected accounts management page with table showing provider
  type, display name, account identifier, regions, status badge, last discovery time, and per-row
  actions (re-discover, enable/disable, delete)
- **`ProvidersTable` component**: reusable table and card components for provider management,
  with busy state per row and correct disabled states for actions
- **`providersApi` client additions**: `get()`, `update()`, and `triggerDiscovery()` methods
- **`docs/connecting-accounts.md`**: comprehensive guide covering UI wizard, API reference,
  credential model, discovery schedule, status reference, and troubleshooting

### Fixed

- `docker/backend.Dockerfile` — base image updated from `python:3.11-slim` to `python:3.13-slim`
  to match the Python 3.13 requirement in `pyproject.toml`; `docker compose up` was failing
  with "currently activated Python version 3.11.15 is not supported by the project"
- `backend/pyproject.toml` — Python constraint changed from `^3.13` (`>=3.13,<4.0`) to
  `>=3.13,<3.14`; `prowler ^5.31.0` requires `Python <3.14` and Poetry was unable to resolve
  dependencies when the upper bound was open-ended at `<4.0`
- `backend/pyproject.toml` — removed all cloud provider SDK direct declarations
  (`azure-identity`, `azure-mgmt-security`, `azure-mgmt-compute`, `azure-mgmt-network`,
  `azure-mgmt-storage`, `azure-mgmt-containerservice`, `azure-mgmt-keyvault`,
  `google-cloud-securitycenter`, `google-cloud-compute`, `google-cloud-storage`,
  `google-cloud-container`, `kubernetes`); `prowler ^5.31.0` pins specific versions of all
  these packages and any independent range declaration causes dependency resolution failure.
  All these SDKs remain available as prowler transitive dependencies; only `boto3` is kept
  as a direct dependency since it is used in discovery tasks that run independently of prowler
- `backend/pyproject.toml` — removed `truffleHog3 ^3.0.0`; all 3.x versions pin
  `attrs==20.3.0` which is incompatible with `prowler`'s required `jsonschema==4.23.0`
  (which needs `attrs>=22.2.0`); `truffleHog3` was planned for Epic 03 (Side-Scanning)
  and is deferred until a compatible secrets-scanner alternative is chosen
- `backend/pyproject.toml` and `docker/backend.Dockerfile` — downgraded target runtime
  from Python 3.13 to **Python 3.12**; Python 3.13 has no pre-built wheels for several
  `prowler` transitive dependencies (notably `alibabacloud-tea`), which forces source
  compilation; during source compilation, Poetry's mid-install downgrade of `packaging`
  (26.2 → 23.2) leaves `packaging/tags.py` temporarily absent, breaking the build
  isolation subprocess; Python 3.12 has full wheel coverage for all prowler dependencies,
  eliminating source builds and the packaging race condition entirely
- `.github/workflows/ci.yml` — updated all `python-version` references from `3.13` to
  `3.12` to match the runtime constraint in `pyproject.toml` and `backend.Dockerfile`
- `.github/workflows/ci.yml` — added `docker-build` job that runs `docker compose build
  --no-cache` on every push and PR; validates that the Docker build succeeds before any
  other job runs; prevents `docker compose up` regressions from reaching `main`

### Added

- **Ogum.Inventory Sprint 5 — Onboarding, Export, and Tenant Isolation**
  - `tenant_config` document collection added to `init_tenant_schema()` — stores connected
    provider metadata per tenant (no credentials — those come from env/Vault at task time)
  - `app/models/provider.py` — Pydantic v2 schemas: `ProviderConfig`, `ProviderRegisterRequest`,
    `ProviderRegisterResponse`
  - `app/services/provider_service.py` — CRUD on `tenant_config` collection:
    `register_provider`, `list_providers`, `delete_provider`, `update_provider_last_discovery`
  - `POST /api/v1/providers` — register a cloud provider connection; dispatches discovery
    task (aws/azure/gcp/k8s) and records job_id; 201 with `provider_id` and `discovery_job_id`
  - `GET /api/v1/providers` — list all connected providers for the tenant
  - `DELETE /api/v1/providers/{provider_id}` — remove a provider config; 404 if not found
  - `GET /api/v1/inventory/export?format=csv` — streaming CSV export of full tenant inventory
    (capped at 50k rows); `Content-Disposition` attachment header with timestamped filename
  - `GET /api/v1/inventory/export?format=json` — streaming OCSF-inspired JSON export with
    `ocsf_version`, `metadata` (tenant_id, exported_at, total_resources, product), and
    `resources` array; 422 for unsupported format values
  - Export endpoint registered before `/{resource_key}` to prevent route shadowing
  - Frontend: `ConnectWizard` component (`components/providers/ConnectWizard.tsx`) — 4-step
    modal (select provider → configure → connecting → done); supports AWS, Azure, GCP, K8s;
    provider-specific fields shown conditionally; error display on failed registration
  - Frontend: `/providers/new` page — renders ConnectWizard; redirects to /inventory on success
  - Frontend: Inventory page — pristine empty state (zero resources + no active filters)
    now shows "No cloud accounts connected" callout with a "Connect Account" CTA link
  - Frontend: `providersApi` and `inventoryApi.exportCsv/exportJson` added to `src/lib/api.ts`
  - Frontend: `ProviderConfig`, `ProviderRegisterRequest`, `ProviderRegisterResponse`
    interfaces added to `src/lib/types.ts`
  - 15 backend integration tests — all passing:
    - `test_providers_api.py` (15): register (AWS, Azure, GCP), missing header → 422,
      idempotency, list empty/populated, delete existing/nonexistent, CSV export content-type
      and header row, JSON export OCSF structure, JSON metadata fields, invalid format → 422,
      CSV with seeded resources contains data rows
  - 2 new tenant isolation tests (`TestProviderConfigIsolation`): provider config in
    Tenant A not visible in Tenant B; AQL on Tenant B returns zero Tenant A resources
  - 8 frontend component tests for `ConnectWizard` — provider selection, configure step per
    provider, back navigation, cancel handler; all passing
  - `docs/getting-started.md` — new "Using the Web Console" and "Using the API" sections
    with `curl` examples for connect, list, export CSV, and export JSON

- **Ogum.Inventory Sprint 4 — Multi-Provider Discovery + Celery Beat Scheduling**
  - `AzureResource(ResourceBase)` model — adds `subscription_id` field; `arango_key()`
    uses `{sub_prefix}_{resource_group}_{name}` for unique, length-safe ArangoDB keys
  - `GCPResource(ResourceBase)` model — adds `project_id` field; inherits `arango_key()`
    from `ResourceBase` using `{provider}_{type}_{compact_id}`
  - `K8sResource(ResourceBase)` model — adds `cluster_name` and `namespace` fields;
    overrides `arango_key()` as `k8s_{cluster}_{type}[_{namespace}]_{uid}`
  - `app/workers/tasks/scheduling.py` — `acquire_lock(redis, tenant_id, provider)` and
    `release_lock(redis, tenant_id, provider)` helpers using Redis `SET NX EX` pattern
    (TTL = 7h); `trigger_all_discoveries` Celery task routes Beat events to provider tasks
  - `app/workers/tasks/azure_discovery.py` — `discover_azure` task: VMs, VNets, NSGs,
    Storage Accounts, AKS clusters, Key Vaults (metadata only); soft-delete of absent
    resources; distributed lock guards against concurrent runs
  - `app/workers/tasks/gcp_discovery.py` — `discover_gcp` task: Compute instances
    (aggregated across all zones), GCS buckets, GKE clusters; distributed lock
  - `app/workers/tasks/k8s_discovery.py` — `discover_k8s` task: Pods, Deployments,
    Services, Nodes, Namespaces; supports kubeconfig dict or in-cluster config;
    distributed lock; K8s UIDs used as `resource_id` for stable keys
  - `celery_app.py` — updated `include` list to register all new task modules;
    default `beat_schedule` added (`trigger_all_discoveries` every 6h for dev)
  - `docker-compose.yml` — `celery-beat` service added (single instance, Redis-backed)
  - `pyproject.toml` — added `azure-mgmt-compute`, `azure-mgmt-network`,
    `azure-mgmt-storage`, `azure-mgmt-containerservice`, `azure-mgmt-keyvault`,
    `google-cloud-compute`, `google-cloud-storage`, `google-cloud-container`,
    `kubernetes` as explicit runtime dependencies
  - 19 integration tests — all passing:
    - `test_scheduling.py` (7): distributed lock acquisition, release, tenant/provider
      isolation, trigger routing, unknown-provider error handling
    - `test_azure_discovery.py` (4): VMs persisted, idempotency, soft-delete, lock skip
    - `test_gcp_discovery.py` (4): compute instances persisted, idempotency, soft-delete, lock skip
    - `test_k8s_discovery.py` (4): pods persisted, idempotency, soft-delete, lock skip

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
