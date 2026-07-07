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

- **Post-scan inventory extraction (all providers)**: CSPM scans now automatically populate the inventory after each scan run — no separate discovery task required. `prowler_inventory.extract_inventory_from_findings()` deduplicates resources by `resource_uid`, routes to the correct collection (`resources`, `identities`, `data_assets`), and upserts with `last_scanned_at` and normalized `resource_type`. Supports all four providers: AWS, Azure, GCP, and Kubernetes.
- **`ProwlerService.run_azure_scan`**, **`run_gcp_scan`**, **`run_kubernetes_scan`**: new scan methods wrapping `AzureProvider`, `GcpProvider`, and `KubernetesProvider`. `run_cspm_scan` task now routes to the correct method by provider (was AWS-only).
- **Provider-aware default frameworks in `GET /api/v1/scans`**: when no frameworks are specified, the scan API selects sane defaults per provider (`CIS-AWS-2.0 + PCI + SOC2` for AWS, `CIS-AZURE-2.0` for Azure, `CIS-GCP-2.0` for GCP, `CIS-K8S-1.12` for Kubernetes).
- **`ScanResult` dataclass**: `ProwlerService` scan methods now return `ScanResult(findings, raw_outputs)` so the task can use raw `OutputFinding` objects for inventory extraction without a second pass.
- **43 unit tests for `prowler_inventory`**: cover type normalization (AWS/Azure/GCP/K8s), collection routing (IAM → identities, S3 → data_assets, EC2 → resources), tag extraction, public IP detection, ArangoDB key generation, deduplication, and edge cases.
- **Risk Score engine (Epic 02 Sprint 1)**: `app/services/risk_score.py` — contextual risk scoring (0–100) for every resource in the graph. Score formula: `severity_base × exposure_factor × blast_factor`, capped at 100. Severity base is the weighted sum of FAIL findings (CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1). Exposure factor doubles score for public/internet-facing resources. Blast factor scales with the count of sensitive data assets reachable within 3 hops. Resources in confirmed attack paths have a minimum score of 40. Path risk score uses max-node score amplified by a depth factor (shorter path = more dangerous).
- **Attack Path detection (Epic 02 Sprint 1)**: `app/services/attack_path_service.py` — AQL graph traversal queries that discover paths from internet-facing resources to sensitive data assets (up to 4 hops), IAM privilege escalation chains, and toxic combinations. Four toxic combination rules: TC-02 (public bucket with credentials), TC-03 (overpermissioned identity → production database), TC-04 (K8s pod with host network). Results are persisted to the new `attack_paths` collection with `is_toxic_combination` flag, risk score, severity, and path metadata. Resources participating in any attack path are marked `in_attack_path=true`.
- **Post-scan graph enrichment tasks (Epic 02 Sprint 1)**: `app/workers/tasks/attack_paths.py` — two Celery tasks (`recalculate_risk_scores`, `detect_attack_paths`) enqueued automatically after each CSPM scan completes. `recalculate_risk_scores` bulk-updates the `risk_score` field on all resources, identities, and data assets. `detect_attack_paths` runs the full detection pipeline and persists results.
- **`attack_paths` ArangoDB collection**: added to the tenant schema with persistent indexes on `tenant_id + risk_score`, `tenant_id + is_toxic_combination`, and `tenant_id + severity` for efficient filtering. Added `risk_score` index on `resources`, `identities`, and `data_assets` for sort performance.

- **Dashboard home (F0.3)**: replaced `/` redirect with a real security overview page showing ThreatScore, finding counts by severity (CRITICAL/HIGH/MEDIUM/LOW — each links to `/findings?severity=X`), last 5 scan jobs with status icons and relative timestamps, and quick-navigation links to all main sections.
- **`GET /api/v1/findings/stats`**: new endpoint returning aggregate counts `by_severity` and `by_status` plus `total` — a single AQL query, scoped by tenant, used by the dashboard.
- **`findingsApi.stats()`**: new client method in `frontend/src/lib/api.ts`; `FindingsStats` type added to `types.ts`.

### Fixed

- **Prowler metadata normalization**: `result.metadata` in `OutputFinding` is `CheckMetadata` directly — the previous code was accessing `metadata.CheckMetadata` (one level too deep), causing all `check_id`, `title`, `description`, `severity`, and `resource_type` to resolve as `"unknown"` on every finding.
- **Finding `_key` sanitization**: `arango_key()` now uses `sha256(check_id|resource_id|tenant_id)` instead of string substitution — prowler resource names/UIDs can contain dots, parens, `@`, and other characters that ArangoDB rejects as `_key` values, causing `ERR 1221` on upsert.
- **Prowler v5 API alignment**: rewrote `ProwlerService.run_aws_scan` to match the actual prowler-core v5 API — `AwsProvider` now takes flat keyword args (no `audit_config` dict), and scanning uses the high-level `Scan` class with `compliances=[...]` instead of manual check iteration. Framework IDs are mapped to prowler's file slugs (`CIS-AWS-2.0` → `cis_2.0_aws`, etc.). `_normalize` converts `OutputFinding` pydantic objects to Ogum's `Finding` model via field introspection.
- **CSPM scan import path**: corrected `prowler.providers.aws.provider` → `prowler.providers.aws.aws_provider` — the module was renamed in prowler v5 and the worker was failing with `ModuleNotFoundError` on every scan trigger.

### Added

- **Dev seed endpoint (F0.1)**: `POST /api/v1/dev/seed` inserts 19 realistic demo findings (CRITICAL/HIGH/MEDIUM/LOW, mix of FAIL/PASS/MUTED) into ArangoDB without requiring real cloud credentials. Only available when `DEV_MODE=true`. Endpoint is idempotent. Complementary `DELETE /api/v1/dev/seed` clears findings and scan_jobs. Standalone script `backend/scripts/seed_demo.py` and `make seed` / `make seed-clear` Makefile targets for local use. `DEV_MODE` setting added to `config.py` and `.env.example`.

- **Discovery job tracking (US-10.09)**: all four discovery tasks (`discover_aws`, `discover_azure`,
  `discover_gcp`, `discover_k8s`) now write to the `scan_jobs` ArangoDB collection so runs appear in
  `/admin/jobs`. A new `_job_tracking` helper module (`start_discovery_job`, `complete_discovery_job`,
  `fail_discovery_job`) handles the lifecycle with fire-and-forget semantics — tracking failures never
  abort discovery. Integration tests cover all state transitions and the missing-collection edge case.

- **Admin Jobs API (Epic 10 Sprint 1)**: cross-tenant job inspection and control endpoints under
  `/api/v1/admin/`. `GET /admin/jobs` lists scan jobs across all tenant databases (or scoped to one
  via `?tenant_id=`), with optional `status` filter and keyset cursor pagination. `GET
  /admin/jobs/{id}` returns full job detail including findings counts and logs. `POST
  /admin/jobs/{id}/retry` re-enqueues a failed job and records the action in `admin_audit_log`.
  `DELETE /admin/jobs/{id}` calls Celery revoke. `GET /admin/workers` inspects live worker state
  via Celery inspect. `GET /admin/queue-depth` returns pending message counts for all known queues
  via Redis `LLEN`. `admin_audit_log` collection added to a dedicated `ogum_admin` database.
  All routes marked `TODO(epic-06)` for role enforcement once Auth/RBAC is implemented.

- **App shell navigation (Epic 11 Sprint 1)**: global layout with fixed sidebar and header wrapping
  all pages. `AppShell` composes `Sidebar` + `Header` and is wired into `app/layout.tsx`.
  `Sidebar` organises all platform modules into labelled sections with active links for implemented
  pages (`/`, `/inventory`, `/findings`, `/compliance`, `/providers`) and disabled `<span>` elements
  with a "Soon" badge for modules not yet built (Attack Paths, Side Scanning, Pulse, CDR, AI
  Remediation, Integrations, Agent, Admin). `Header` shows a dynamic breadcrumb based on the
  current route. `NavItem` highlights the active route with an orange left border.

- **Makefile** (`Makefile`): covers Docker Compose lifecycle (`up`, `down`, `up-infra`, `up-backend`,
  `restart`), code quality (`lint`, `format`, `typecheck`, `check`, `fe-lint`, `fe-typecheck`),
  tests by layer (`test-unit`, `test-integration`, `test-security`, `fe-test`, `agent-test`),
  dependency management (`install`, `update-deps`), container shells, log tailing, and a
  `health` target that checks all services. Run `make help` to list all targets.
- **Terraform test fixtures** (`infra/terraform/test-fixtures/`): deploys intentionally
  misconfigured AWS resources (EC2, S3, IAM, Security Groups, VPC, CloudTrail) for validating
  Ogum.Inventory discovery and Ogum.Static CSPM findings. Includes compliant baselines alongside
  misconfigured scenarios for diff testing. `terraform output expected_findings` lists the exact
  CSPM findings that should appear after scanning the fixture account.

- **IaC scanning (Ogum.Static Sprint 4)**: `POST /api/v1/scans/iac` triggers a Celery task that
  shallow-clones a Git repository, runs Checkov across Terraform, CloudFormation, and Kubernetes
  manifests, and persists findings with `source: iac`. Repository tokens are injected into the
  HTTPS URL at clone time and never stored or logged. Cloned repos are cleaned up in a `finally`
  block after each scan.
- **`CheckovService`** (`app/services/checkov_service.py`): wraps Checkov's programmatic API
  (`TFRunner`, `CFNRunner`, `K8sRunner`), normalizes check results to `Finding` objects with
  OCSF-aligned severity levels, and maps resource IDs to cloud provider (`aws`, `azure`, `gcp`,
  `iac`). Raises a graceful `[]` result on `ImportError` (checkov optional dependency).
- **`GET /api/v1/findings/export`**: streams all findings matching the active filter set as CSV
  or JSON (OCSF-aligned). Streaming uses a generator with keyset cursor pagination internally —
  safe for exports of 100k+ findings without loading all rows into memory. The `/export` route is
  registered before `/{finding_key}` to prevent FastAPI treating the literal "export" as a path
  parameter.
- **Export button** (`components/findings/ExportButton.tsx`): dropdown with CSV and JSON (OCSF)
  options; triggers a browser `Blob` download with the current filter set applied. Appears in the
  Findings page header next to the severity counter chips.
- **`docs/scanning.md`**: public documentation covering CSPM scan trigger and polling, supported
  compliance frameworks, IaC scan parameters (including token security notes), export formats and
  filter options, and CSV field reference.

- **Findings UI (Ogum.Static Sprint 3)**: `/findings` page with a full-featured `FindingsTable`
  component — severity badge column, MUTED/ACCEPTED/PASS/FAIL status, provider badge,
  keyset cursor pagination (Previous/Next). `FindingFilters` bar with debounced search, six
  dropdown filters (severity, status, provider, framework, source), and active-filter chips
  with individual clear and "Clear all". `FindingDetailPanel` slide-in (440px) showing resource
  metadata, risk description, remediation steps, CLI command with copy-to-clipboard, framework
  badges, mute modal with required reason field, and a placeholder "Generate PR ✨" (Ogum.AI,
  Epic 05). Panel closes on Escape key or backdrop click.
- **Compliance dashboard** (`/compliance`): framework score sidebar with pass/fail counts and
  progress bar, main panel with detailed scores, ThreatScore gauge (0–100 weighted by severity
  of open FAIL findings), top-10 failing controls ordered by occurrence count.
- **`GET /api/v1/compliance/summary`**: AQL-powered aggregation endpoint returning per-framework
  pass/fail/total/score, global ThreatScore, and top-10 failing checks by count — all scoped to
  the requesting tenant.
- **`SeverityBadge` component** (`components/ui/SeverityBadge.tsx`): dedicated wrapper around
  `Badge` that maps `SeverityLevel` enum to the correct variant — reused across findings table,
  detail panel, and compliance page.
- **Frontend types and API client** extended with `Finding`, `FindingDetail`, `PagedFindings`,
  `FindingsFilter`, `ComplianceSummary`, `FrameworkScore` types; `findingsApi` (list, get, mute,
  accept) and `complianceApi` (summary) added to `lib/api.ts`.

- **Findings API (Ogum.Static Sprint 2)**: `GET /api/v1/findings` with server-side filtering
  (provider, severity, status, framework, region, account_id, resource_type, source, full-text `q`)
  and keyset cursor pagination (stable across large datasets). `GET /api/v1/findings/{key}` returns
  the full finding enriched with linked resource metadata, attack path placeholders (Epic 02), and
  the best available CLI remediation command. `PATCH /api/v1/findings/{key}` mutates status to
  `MUTED` (requires `reason`) or `ACCEPTED`; every change is written to the `audit_log` collection.
- **`audit_log` vertex collection** added to tenant schema with indexes on `tenant_id` and
  `(tenant_id, finding_key)` — stores every finding status mutation with actor, reason, and timestamp.
- **`app/services/cli_command.py`**: provider-aware CLI command builder. Priority: stored
  `remediation_code` from Prowler → known resource-type template → provider fallback.
  Supports AWS, Azure, GCP, and Kubernetes. ARN-style resource IDs are simplified to the last
  segment for ergonomic CLI output.

- **CSPM scan engine (Ogum.Static Sprint 1)**: Prowler v5 programmatic integration via
  `ProwlerService`. `POST /api/v1/scans` triggers a Celery task (`run_cspm_scan`) that
  executes Prowler checks, normalizes results to OCSF-aligned `Finding` objects, and persists
  them in ArangoDB with idempotent upserts (`check_id + resource_id + tenant_id` as key).
  `GET /api/v1/scans/{job_id}` and `GET /api/v1/scans` expose job status and history.
- **`findings` and `scan_jobs` vertex collections** added to tenant schema (`init_tenant_schema`).
  `HAS_FINDING` edge collection links `resources → findings`.
  Persistent indexes on `tenant_id`, `severity`, `status`, `provider`, and `check_id`.
- **`Finding` and `ScanJob` Pydantic models** (`app/models/finding.py`): OCSF-aligned severity
  levels (CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL), finding status (FAIL/PASS/MUTED/ACCEPTED),
  framework mapping list, remediation text and code, scan job lifecycle tracking.

- **Provider delete purges all associated resources**: `DELETE /api/v1/providers/{id}` now
  hard-deletes all documents in `resources`, `identities`, `data_assets`, and
  `network_endpoints` scoped to the provider's account, then sweeps orphaned edges from all
  eight edge collections. The response includes a `purged` map with per-collection delete counts.
- **Scan all regions by default**: `regions: []` (empty list) now means "scan all enabled regions"
  across all providers. For AWS, the task calls `ec2:DescribeRegions` to resolve the full list
  at runtime. Azure, GCP, and Kubernetes already scanned all resources regardless of region.
  The wizard and edit modal show an empty field by default with a hint explaining the behavior;
  users can still restrict to specific regions by listing them comma-separated.

- **Edit provider**: `PATCH /api/v1/providers/{id}` now accepts `role_arn`, `azure_tenant_id`,
  and `azure_client_id` updates (non-secret, safe to persist); `EditProviderModal` component
  pre-fills current config values and supports optionally re-triggering discovery with new
  ephemeral credentials (API keys, client secret, SA JSON, kubeconfig) that are forwarded to
  the worker and never stored.
- **`DiscoverRequest` type** exported from `@/lib/types`; `providersApi.triggerDiscovery` now
  accepts an optional `DiscoverRequest` body for re-trigger with static credentials.
- **Edit button** (Pencil icon) added to `ProvidersTable` and `ProviderCard` — opens
  `EditProviderModal` with current provider values pre-filled.

### Fixed

- **Re-trigger discovery with static credentials**: `POST /{id}/discover` now accepts an optional
  `DiscoverRequest` body so providers registered with `credential_type: static`,
  `service_principal`, `service_account`, or `kubeconfig` can re-provide their ephemeral
  credentials without re-registering the provider.
- **`discover_aws` diagnostic log**: the task now logs `has_role_arn` and `has_static_keys` at
  INFO level on start, making it easy to verify whether credentials reached the Celery worker.
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
