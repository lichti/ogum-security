# QA Scenario — Attack Paths

Covers: `/attack-paths` UI (filters, graph visualization, pathfinding, AQL console) and
`GET /api/v1/attack-paths`. For verifying that attack paths are *derived correctly* from a scan,
see [`cspm-compliance.md`](./cspm-compliance.md) Scenario 6 first — this scenario assumes paths
already exist and focuses on the page's own behavior.

## Pre-conditions

- [`cspm-compliance.md`](./cspm-compliance.md) completed — attack paths exist for the tenant.

## Scenario 1 — Severity filters and counts

**Steps:**
1. Navigate to `/attack-paths`.
2. Note the `Total`/`CRITICAL`/`HIGH`/`MEDIUM`/`LOW` counts in the header cards.
3. Click each severity card.

**Expected result:**
- Header counts sum to `Total` (`CRITICAL + HIGH + MEDIUM + LOW == Total`).
- Clicking a severity card filters the list below to only that severity.
- `New (24h)` count only includes paths with `detected_at` in the last 24 hours — re-running a
  scan should increase this if it produces new paths, not reset it.

## Scenario 2 — Graph visualization

**Steps:**
1. Click a path in the list, prioritizing one with `is_toxic_combination: true` if available.
2. Observe the canvas on the right.
3. Use the zoom/fit controls (bottom-left of the canvas).

**Expected result:**
- Canvas renders an **ENTRY** node and a **TARGET** node connected by a labeled edge, with the
  entry point's type (`iam_user`, `iam_role`, etc.) and the target's type
  (`dynamo_db_table`, etc.) shown under each node's name.
- For multi-hop paths, every intermediate vertex from `path_vertex_ids` appears in the canvas.
- Fit-to-view and zoom controls work without breaking the layout.
- A `Toxic` badge appears in the list for paths with `is_toxic_combination: true`; the rule name
  (`TC-02`, `TC-03`, `privilege_escalation`) is shown under each list entry.

**What to check if it fails:** confirm the path's `entry_point_id`/`target_id`/`path_vertex_ids`
resolve to real documents (see `cspm-compliance.md` Scenario 6) — a rendering failure with valid
IDs is a frontend bug (`AttackPathCanvas` component); a rendering failure with dangling IDs is a
backend data-consistency bug.

## Scenario 3 — Pathfinding (`GET /api/v1/graph/paths/{from_id}/{to_id}`)

**Steps:**
1. Click **Pathfinding** in the top-right of `/attack-paths`.
2. Pick a known internet-exposed resource as the source and a known sensitive data asset as the
   target (use IDs from Scenario 2, or from `/inventory`).
3. Submit.

**Expected result:**
- If a path exists in the graph between the two vertices, it renders the same way a detected
  attack path does.
- If no path exists, the UI shows a clear "no path found" state, not a blank canvas or an
  unhandled error.

**What to check if it fails:** `graph.py::get_shortest_path` — confirm it distinguishes "no path"
from an actual query error (these should not look the same in the UI).

## Scenario 4 — AQL Console

Tenant isolation for this endpoint comes from ArangoDB's per-tenant database (`ogum_<tenant_id>`,
see the multi-tenancy ADR) — `X-Tenant-Id` selects which physical database the query runs
against, not a filter within a shared database. There is no other tenant's data reachable from a
query in this session no matter what the query text says, because no other tenant's documents
exist in that database at all. The check here is narrower than "does a filter-less query leak
data" — it's "is read-only actually enforced" and "does the header genuinely select the right
database".

**Steps:**
1. Click **AQL Console** in the top-right of `/attack-paths`.
2. Run a read-only query with no `tenant_id` filter at all, e.g.:
   ```aql
   FOR d IN identities LIMIT 5 RETURN d
   ```
3. Attempt a write query (`INSERT`/`UPDATE`/`REMOVE`/`UPSERT`).
4. Repeat step 2 against a second tenant (different `X-Tenant-Id` header, e.g. via `curl` or by
   switching tenants in dev mode) and confirm the results differ and each set only contains that
   tenant's data.

**Expected result:**
- The filter-less read-only query in step 2 succeeds and returns only the calling tenant's
  documents (there is nothing else in that database to return).
- The write query in step 3 is rejected by `_validate_read_only` with a clear error, not executed.
- Step 4 confirms two different `X-Tenant-Id` headers genuinely resolve to two different
  ArangoDB databases — this is the isolation boundary that actually matters here.

**What to check if it fails:** `graph.py::execute_aql` / `_validate_read_only` for the write-query
rejection; `api/v1/inventory.py::get_tenant_db` (or the shared dependency graph.py uses) for how
`X-Tenant-Id` maps to a database name — a bug here is cross-tenant data exposure and should be
treated as a P0 regardless of where in the stack it's found.

## Scenario 5 — Crown jewels and exposure summary

**Steps:**
1. `PATCH /api/v1/graph/resources/{resource_id}/crown-jewel` with `{"is_crown_jewel": true}` on a
   sensitive data asset.
2. `GET /api/v1/graph/crown-jewels` — confirm it appears.
3. `GET /api/v1/graph/exposure` — check the exposure summary numbers.

**Expected result:**
- The marked resource appears in the crown-jewels list.
- Exposure summary counts (`exposed_resources`, `exposed_data_assets`, `exposed_endpoints`) are
  consistent with `resources`/`data_assets` documents where `is_public == true` or
  `exposed_internet == true` (see `graph/exposure.py`).
