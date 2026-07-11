# QA Scenario — Full CSPM Scan Consistency

Covers: a single CSPM scan's output staying consistent across Findings, Inventory, Compliance,
and Attack Paths at once. This is the scenario to run after any change to
`prowler_service.py`, `prowler_inventory.py`, `graph/*.py`, or `cspm_scan.py` — those four files
feed all four pages from one scan run, so a bug in any of them tends to surface as a
cross-page inconsistency rather than a failure in one place.

## Pre-conditions

- [`inventory.md`](./inventory.md) Scenario 1 completed — an AWS provider is connected.
- Recommended: use the Terraform test fixtures (`infra/terraform/test-fixtures/`), which are
  designed to trigger specific findings (public S3 bucket, admin-privileged role, wildcard IAM
  policy, unencrypted resource) so this scenario has deterministic things to look for. A
  reference run against those fixtures produced 405 checks / 174 FAIL / 9 attack paths, 7 of them
  toxic combinations — your numbers will differ with a different account, but the structural
  checks below (e.g. severity spread not collapsing to one value) do not.

## Scenario 1 — Trigger a full-catalog scan

**Steps:**
1. `POST /api/v1/scans` with only `provider_id` (omit `frameworks` — see
   [`scanning.md`](../scanning.md) for why the full catalog is the default, not a curated
   subset).
2. Poll `GET /api/v1/scans/{job_id}` until `status: completed`. A full-catalog scan takes several
   minutes, not seconds — do not assume it hung just because it's still `running` after 1 minute.

**Expected result:**
- `frameworks` on the completed job doc is `[]` (empty list represents "ran the full catalog",
  not "ran nothing" — see `cspm_scan.py::run_cspm_scan` docstring).
- `checks_total == checks_completed == findings_found`.
- `findings_fail <= findings_found`.

**What to check if it fails:** `docker compose logs worker | grep run_cspm_scan` for exceptions;
`scan_jobs.error_message` if `status == failed`.

## Scenario 2 — Findings severity and status are not collapsed to one value

This is a direct regression scenario for two bugs found in this session: `Status` and
`Severity` in prowler-core are `(str, Enum)` without a `__str__` override, so a careless
`str(enum_member)` silently produces `"Status.PASS"` / `"Severity.high"` instead of `"PASS"` /
`"high"` — which then fails to match the internal mapping and falls through to a default,
misclassifying **every** finding the same way.

**Steps:**
1. Query the findings collection grouped by `status`:
   ```
   FOR f IN findings FILTER f.tenant_id == "<tenant>" COLLECT s = f.status WITH COUNT INTO c RETURN {s, c}
   ```
2. Query grouped by `severity`:
   ```
   FOR f IN findings FILTER f.tenant_id == "<tenant>" COLLECT s = f.severity WITH COUNT INTO c RETURN {s, c}
   ```

**Expected result:**
- Both `PASS` and `FAIL` appear (a scan against any real account produces both — 100% FAIL was
  the symptom of the `Status` bug).
- More than one severity level appears, and the spread roughly follows the check catalog's real
  distribution (AWS: mostly `MEDIUM`/`HIGH`, some `CRITICAL`/`LOW`) — 100% `MEDIUM` was the
  symptom of the `Severity` bug. Note that `INFORMATIONAL` is legitimately absent for all four
  providers today — no check in the AWS/Azure/GCP/Kubernetes catalogs currently uses that
  severity, so its absence is not itself a failure signal.

**What to check if it fails:** `ProwlerService._normalize` in `prowler_service.py` — confirm it
reads `.value` off the status/severity object rather than calling `str()` directly on it.

## Scenario 3 — Inventory has zero missing type fields

**Steps:**
```
FOR d IN identities FILTER d.tenant_id == "<tenant>" AND d.status != "deleted" AND (d.identity_type == null OR d.identity_type == "") RETURN d._key
FOR d IN data_assets FILTER d.tenant_id == "<tenant>" AND d.status != "deleted" AND (d.asset_type == null OR d.asset_type == "") RETURN d._key
FOR d IN resources FILTER d.tenant_id == "<tenant>" AND d.status != "deleted" AND (d.resource_type == null OR d.resource_type == "") RETURN d._key
```

**Expected result:** all three queries return an empty list.

## Scenario 4 — Graph edges exist and security groups aren't misrouted

**Steps:**
1. Check edge counts:
   ```
   FOR e IN BELONGS_TO RETURN 1
   FOR e IN ATTACHED_TO RETURN 1
   FOR e IN ASSUMES_ROLE RETURN 1
   FOR e IN STS_ASSUMEROLE_ALLOW RETURN 1
   FOR e IN STORES_SENSITIVE_DATA RETURN 1
   ```
   (wrap each in `COLLECT WITH COUNT INTO c RETURN c` for a single number).
2. Confirm no EC2 security groups (or other non-identity resources whose name happens to contain
   "Group"/"Role" — `AwsAthenaWorkGroup`, `AwsAutoScalingAutoScalingGroup`, `AwsLogsLogGroup`,
   `AwsWafRuleGroup`) ended up in the `identities` collection:
   ```
   FOR d IN identities FILTER d.tenant_id == "<tenant>" AND d.name LIKE "%ecurity%roup%" RETURN d
   ```

**Expected result:**
- `BELONGS_TO`, `ATTACHED_TO`, `ASSUMES_ROLE` are non-zero if the account has EC2 instances with
  a VPC/security group/instance profile. `STS_ASSUMEROLE_ALLOW` and `STORES_SENSITIVE_DATA` are
  non-zero if the account has IAM roles with trust policies and admin-privileged identities
  respectively. `MEMBER_OF` may legitimately be zero if the account has no IAM Groups.
- The security-group query returns nothing — a hit here is the collection-routing regression
  documented in the CHANGELOG under "Prowler as the single source of truth for Inventory — Part
  2/3".

**What to check if it fails:** `graph/resource_edges.py::build_resource_edges` for the edge
counts; `prowler_inventory.py::_collection_for` for the routing regression.

## Scenario 5 — Compliance dashboard matches real scan data

**Steps:**
1. Navigate to `/compliance`.
2. Note the number of frameworks listed in the sidebar.
3. Click a framework, check its pass/fail counts and section breakdown.
4. Click "View findings" from a failing control — confirm it lands on `/findings` pre-filtered
   to that framework/control.
5. Cross-check one framework's numbers against the API directly:
   `GET /api/v1/compliance/summary?framework=<slug>`.

**Expected result:**
- Sidebar shows real frameworks with non-zero control counts each (a full-catalog scan against
  the Terraform fixtures shows 31 in the reference run) — not the ~2,500 duplicate-entry list
  that existed before the framework-family redesign, and not just 3 curated frameworks from the
  pre-full-catalog era.
- Sidebar counts and section percentages match what the API returns for the same framework —
  the UI must not be showing stale/cached numbers from a previous scan.
- "Top Failing Controls" reflects controls that actually have FAIL findings in this scan, not
  leftover data from a different framework.

**What to check if it fails:** `compliance_frameworks.py::derive_section` for section grouping;
`compliance_service.py::get_compliance_summary` for the aggregation query.

## Scenario 6 — Attack paths reflect the same scan

**Steps:**
1. `GET /api/v1/attack-paths` (or navigate to `/attack-paths`).
2. Count total paths and how many have `is_toxic_combination: true`.
3. Click one TC-02 or TC-03 path and confirm the graph visualization renders entry → target
   with a labeled edge, not an empty canvas.

**Expected result:**
- At least one path detected if the account has an admin-privileged identity reachable from an
  internet-exposed entry point (the Terraform fixtures guarantee this).
- `mitre_ttps` is non-empty on toxic-combination paths.
- Every `entry_point_id`/`target_id` referenced by a path resolves to a real document in
  `identities`/`resources`/`data_assets` — a dangling reference here means the edge-building
  step and the attack-path detection step disagree about what exists.

**What to check if it fails:** `attack_path_service.py` for the TC-02/TC-03/privilege-escalation
rules; confirm the entry/target IDs from a failing path actually exist:
```
FOR d IN identities FILTER d._id == "<entry_point_id>" RETURN d
```
