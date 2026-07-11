# QA Scenario — Connecting an Account & Inventory

Covers: `POST /api/v1/providers`, the Connect Wizard UI, and the `/inventory` page.

AWS inventory is built entirely by the CSPM scan itself (`run_cspm_scan` — see
[`architecture decision on Prowler as the source of truth`](../overview.md#70-oguminventory--layer-zero)).
There is no separate discovery pass for AWS to test independently of a scan.

## Pre-conditions

- Local stack running (`docker compose up -d`).
- AWS credentials for a test account — either an IAM role ARN + external ID, or a static
  access key pair. Prefer the Terraform fixtures under `infra/terraform/test-fixtures/` so the
  scan produces predictable findings and resources.
- A tenant ID to use for `X-Tenant-Id` / `X-Tenant-ID` headers throughout (any string; the
  backend creates the tenant database on first use in dev mode).

## Scenario 1 — Connect via the UI

**Steps:**
1. Navigate to `/providers` and click **Connect Account**.
2. Select **Amazon Web Services**.
3. Fill in the role ARN (or static keys) and region(s), leave **account ID** blank if unknown.
4. Click **Connect & Start Discovery**.

**Expected result:**
- UI moves to a "Connecting..." state with copy indicating this runs a full scan and can take a
  few minutes (not "a moment") — if it still says "a moment", that copy regressed.
- After the scan completes (poll `GET /api/v1/scans/{job_id}` or watch `docker compose logs -f
  worker | grep run_cspm_scan`), the UI moves to a "Connected" state showing the new job ID.
- Provider status transitions `pending` → `active` once the first scan completes successfully.

**What to check if it fails:**
- `tenant_config` collection for the new provider doc (`status` field).
- `scan_jobs` collection for a doc with matching `provider_id` — `status` should reach
  `completed`, not stay `running` or flip to `failed` (`error_message` field has the reason).

## Scenario 2 — Inventory reflects the scan

**Pre-condition:** Scenario 1 completed, scan status is `completed`.

**Steps:**
1. Navigate to `/inventory`.
2. Check the summary counts at the top (`N resources · N identities`).
3. Filter by provider = AWS, then by category = Security & Identity.
4. Click a resource row to open the detail panel.
5. Search by a known resource name/ARN fragment in the search box.

**Expected result:**
- Resource/identity counts are non-zero and match `GET /api/v1/inventory/stats`.
- Every row has a non-empty `Type` column — no row should show a blank type (this was the
  regression behind the `identity_type`/`asset_type` schema bug fixed in Epic 00; a blank type
  means a document is missing its required field again).
- Category filters narrow the list correctly; "Other" is expected to have the largest count in a
  typical AWS account (only a curated subset of resource types has a category mapping — see
  `frontend/src/lib/inventoryCategories.ts` — this is expected, not a bug).
- Detail panel shows region, account ID, tags, and — for resources with graph edges — related
  resources.

**What to check if it fails:**
```
FOR d IN resources FILTER d.tenant_id == "<tenant>" AND d.status != "deleted"
  FILTER d.resource_type == null OR d.resource_type == ""
  RETURN d._key
```
Any result here is a bug — every active resource must have `resource_type` populated. Same query
pattern for `identities.identity_type` and `data_assets.asset_type`.

## Scenario 3 — Re-scan doesn't duplicate or lose data

**Pre-condition:** Scenario 2 completed.

**Steps:**
1. Note the current `resources`/`identities`/`data_assets` counts from `/inventory`.
2. Trigger a manual re-scan: `POST /api/v1/scans` with the same `provider_id` (see
   [`scanning.md`](../scanning.md)).
3. Wait for completion, refresh `/inventory`.

**Expected result:**
- Counts stay the same (± any real infrastructure drift if using a live account) — no
  duplication. A resource that existed before the second scan and still exists in the cloud
  keeps the same `_key` (upsert, not insert).
- If a resource was actually removed from the account between scans, it disappears from the
  default `/inventory` view (soft-deleted) but is still queryable with `?status=deleted`.

**What to check if it fails:**
```
FOR d IN resources FILTER d.tenant_id == "<tenant>"
  COLLECT arn = d.arn WITH COUNT INTO c FILTER c > 1 RETURN {arn, c}
```
Any result means the same ARN produced more than one document — the upsert-by-ARN logic in
`workers/tasks/cloud_utils.py::_upsert` broke.
