# QA Scenario — Admin Panel

Covers: `/admin`, `/admin/jobs`, `/admin/workers`, `/admin/queue-depth`, and
`/api/v1/admin/*`. This is a cross-tenant view — the admin API intentionally does not scope by a
single `X-Tenant-Id` header the way product-facing endpoints do.

> **Note:** admin routes are marked `TODO(epic-06): add @require_role(["PlatformAdmin"])` in the
> code today — there is no role enforcement yet. Treat any finding here as expected until
> Epic 06 (Auth/RBAC) lands, but re-run this scenario once it does, since the expected result for
> "unauthenticated access" changes from "allowed" to "403".

## Pre-conditions

- At least one job exists from any other scenario (`inventory.md`, `cspm-compliance.md`,
  `side-scanning.md`) — ideally one `completed` and one `failed` (force a failure with bad
  credentials on a provider to get one on demand).

## Scenario 1 — Job listing and detail

**Steps:**
1. Navigate to `/admin/jobs`.
2. Filter by tenant, then by status.
3. Click a job to see its detail view.
4. Compare against the raw document: `GET /api/v1/admin/jobs/{job_id}?tenant_id=<tenant>`.

**Expected result:**
- The table shows jobs across tenants when no tenant filter is applied — this is the point of
  the admin view, distinct from `/inventory`'s tenant-scoped `GET /api/v1/scans`.
- Status filter (`queued`/`running`/`failed`/`completed`) narrows correctly.
- Detail view matches the API response exactly — no fields silently dropped in the UI.

## Scenario 2 — Force/trigger a job

**Steps:**
1. `POST /api/v1/admin/jobs/trigger` with `task_type: "cspm"`, a valid `provider_id`/`provider`,
   and `tenant_id`.
2. Repeat with `task_type: "discovery"` — this now dispatches `run_cspm_scan` under the hood
   (AWS discovery was retired in favor of CSPM-scan-as-discovery, see the CHANGELOG entry
   "Prowler as the single source of truth for Inventory"), not a separate discovery task.
3. Repeat with `task_type: "iac"`.

**Expected result:**
- Each call returns `202` with a `job_id` immediately (bypasses the Celery Beat schedule).
- A new `scan_jobs` document appears with `status: running` shortly after.
- `task_type: "discovery"` and `task_type: "cspm"` both end up as `run_cspm_scan` jobs — confirm
  via `scan_jobs.provider == "aws"` (or whatever `provider` was passed) on the resulting doc,
  there's no separate `discover_aws`/`discover_aws_basic` task left to look for.

**What to check if it fails:** `admin_service.py::trigger_job` — confirm the `TaskType.DISCOVERY`
branch calls `run_cspm_scan.delay(...)`, not an import of the removed `discovery.py` module (this
would be an `ImportError` visible in worker logs, not a silent failure).

## Scenario 3 — Retry a failed job

**Pre-condition:** a job in `status: failed`.

**Steps:**
1. From `/admin/jobs`, click retry on the failed job (or `POST /api/v1/admin/jobs/{job_id}/retry`
   with `{"tenant_id": "...", "actor_email": "..."}`).
2. Confirm a `new_job_id` is returned and a new job appears.
3. Check the audit log for the retry action.

**Expected result:**
- Original job's `job_id` is referenced as `original_job_id` in the response.
- New job runs with `frameworks: None` (full catalog) regardless of what the original job used —
  retry always re-runs the full check catalog now, not whatever curated subset the original job
  happened to use.
- Audit log entry exists: `action: "job.retry"`, `before_state.status == "failed"`,
  `after_state.new_job_id` matches.

## Scenario 4 — Log streaming

**Steps:**
1. `GET /api/v1/admin/jobs/{job_id}/logs?tenant_id=<tenant>` (Server-Sent Events).
2. Observe the stream in the UI (`/admin/jobs` detail view, logs panel).

**Expected result:**
- Each stored log line arrives as a separate SSE `data:` event with an `index`.
- Stream ends with a `data: [DONE]` event.
- A job with no stored logs yields a single `[no logs]` line, not an empty/hung stream.

## Scenario 5 — Revoke a running job

**Pre-condition:** a job in `status: queued` or `running` (trigger one from Scenario 2 and act
before it completes — a full-catalog CSPM scan takes several minutes, which is enough time).

**Steps:**
1. `DELETE /api/v1/admin/jobs/{job_id}?tenant_id=<tenant>&actor_email=<email>`.
2. Check the job's status afterward.

**Expected result:**
- Returns `204`.
- The Celery task is revoked (check `docker compose logs worker` for a revocation log line) and
  the job's status reflects cancellation rather than continuing to `completed` as if nothing
  happened.

## Scenario 6 — Workers and queue depth

**Steps:**
1. Navigate to `/admin/workers`, then `/admin/queue-depth`.
2. Cross-check against `GET /api/v1/admin/workers` and `GET /api/v1/admin/queue-depth`.
3. Trigger several jobs in quick succession (Scenario 2, repeated) and watch queue depth change.

**Expected result:**
- Worker list shows at least the local `worker` container as active, with a hostname and status.
- Queue depth increases when jobs are queued faster than the worker can process them, and drains
  back down as they complete — a queue depth stuck at a high number with no worker activity in
  the logs indicates the worker isn't consuming from that queue (check `celery_app.py`'s
  `include=` list and the queue routing).
