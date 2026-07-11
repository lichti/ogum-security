# QA Scenario — Side-Scanning

Covers: `/side-scanning` UI, `/api/v1/side-scans/*`, and the deep file-system scan tasks
(`scan_ec2_instance_v2`, `scan_lambda_function`, `scan_container_image`, `scan_k8s_container`).

EC2 and Lambda scans are reachable two ways: `POST /api/v1/side-scans/trigger` (manual —
also the "Scan Now" button in the Inventory detail panel), and automatically the first time
`run_cspm_scan` discovers a new EC2 instance or Lambda function (AWS only; deduplicated against
`scan_jobs`, never re-triggered periodically — see `app/services/side_scanning/trigger.py`).
Kubernetes and container-image scans still only fire from external webhooks (a real DaemonSet, a
real ECR push) — there's no equivalent manual/automatic path for those, since they don't originate
from Ogum's own inventory scan the way EC2/Lambda do.

## Pre-conditions

- [`inventory.md`](./inventory.md) completed — a provider is connected with resources to scan.
- A `scanner_token` set on the tenant's `tenant_config` document (the webhooks require
  `X-Ogum-Token` to match it — see `_validate_scanner_token` in `side_scans.py`). Set one via:
  ```
  db.collection("tenant_config").update({"_key": "<key>", "scanner_token": "<any-string>"})
  ```

## Scenario 1 — Container image scan via ECR webhook

**Steps:**
1. `POST /api/v1/side-scans/webhooks/ecr` with `X-Ogum-Tenant-Id` and `X-Ogum-Token` headers and
   a body containing `image_uri`, `image_digest`, `repository_name`, `registry_id`, `provider_id`
   for a real (or test) ECR image.
2. Response should be `202` with a `job_id`.
3. Poll `GET /api/v1/side-scans/jobs/{job_id}` until `status` reaches a terminal state.
4. `GET /api/v1/side-scans/images/{image_digest}/security` for the CI/CD badge endpoint.

**Expected result:**
- Job transitions `queued` → `running` → `completed` (or `failed` with a reason).
- On completion, findings appear scoped to `source: side_scanning`, with vulnerabilities and any
  secrets detected (Trivy `Severity` is the primary severity source — see the CHANGELOG entry on
  Trivy severity precedence).
- The security-badge endpoint returns `overall_status: fail` if any CRITICAL/HIGH finding exists,
  `pass` otherwise.
- An invalid/missing `X-Ogum-Token` → `401`.

**What to check if it fails:** `docker compose logs worker | grep scan_container_image`;
`scan_jobs` collection for the job's `error_message`.

## Scenario 2 — Kubernetes container scan via DaemonSet webhook

**Steps:**
1. `POST /api/v1/side-scans/webhooks/k8s-scan` with the same auth headers and a body containing
   `pod_name`, `pod_namespace`, `container_name`, `pid`, `node_name`, `resource_id`,
   `provider_id` (this simulates what the `ogum-scanner-daemonset` posts in a real cluster — see
   `infra/k8s/ogum-scanner-daemonset.yaml`).
2. Poll the job the same way as Scenario 1.

**Expected result:**
- Findings use `detection_method: k8s_proc_root` for CVEs, `trivy_secret_k8s` for secrets.
- Findings are linked to the Pod vertex via a `HAS_FINDING` edge — verify:
  ```
  FOR e IN HAS_FINDING FILTER e._to == "findings/<finding_key>" RETURN e._from
  ```
  should resolve to the pod's resource document, not a dangling reference.
- No pod restart occurs — this scan reads `/proc/<PID>/root`, it doesn't touch the running
  container.

## Scenario 3 — EC2 and Lambda scanning (manual trigger + auto first-seen)

**Steps — manual trigger:**
1. In `/inventory`, select an active EC2 instance or Lambda function resource.
2. Click **Scan Now** in the detail panel.
3. Confirm the green "Side-scan queued — job {id}" banner, then poll
   `GET /api/v1/side-scans/jobs/{job_id}` (or watch it appear in `/side-scanning`) until terminal.

**Steps — automatic first-seen trigger:**
1. Ensure the target EC2 instance/Lambda has never been side-scanned before (no `scan_jobs` doc
   with `type: "ec2"`/`"lambda"` and matching `resource_id`).
2. Trigger a CSPM/discovery scan for the AWS provider (`POST /api/v1/scans`).
3. After the scan completes, check `scan_jobs` for a new `ec2`/`lambda` entry created without any
   manual action — `run_cspm_scan`'s log line includes `side_scans_triggered=N`.
4. Re-run the same discovery scan a second time — confirm **no** new `ec2`/`lambda` job is created
   for that same resource (first-seen dedup, not a time-window cooldown).

**Expected result:**
- EC2: snapshot created → EBS Direct API scan via `trivy client vm ebs:{snapshot_id}` (+ optional
  YARA via a scoped volume mount when `OGUM_SCANNER_INSTANCE_ID` is configured) → snapshot (and
  scoped volume, if any) deleted in `finally` even if the scan fails (verify no orphaned EBS
  snapshot/volume remains on the account after a failed run — `cleanup_orphan_snapshots` Celery
  Beat task is the safety net if one does leak).
- Lambda: deployment package downloaded to `/dev/shm/ogum-{job_id}/` (RAM disk), scanned, then
  the RAM disk is wiped in `finally` regardless of outcome.
- Both produce an SBOM (`sboms` collection + `HAS_SBOM` edge) alongside findings.
- Triggering a resource that's `status: deleted`, or not an `ec2_instance`/`lambda_function`,
  returns `422`. Triggering a `resource_key` from another tenant, or one that doesn't exist,
  returns `404`.

## Scenario 4 — Retry a failed scan

**Pre-condition:** at least one job from Scenarios 1–3 in `status: failed` (or force one by
passing an invalid `image_digest`/`resource_id`).

**Steps:**
1. `POST /api/v1/side-scans/jobs/{job_id}/retry`.
2. Confirm the response and poll the new job.

**Expected result:**
- Retry re-dispatches the correct task by job `type`: `k8s_container`/`ecr` replay the original
  job doc's fields; `ec2`/`lambda` re-fetch the resource and go through the same
  `enqueue_side_scan()` path as a manual trigger (fresh `volume_id`/`availability_zone` lookup for
  EC2 — the original job doc doesn't carry those). `ec2`/`lambda` retry used to be a silent no-op
  (job record created, nothing re-enqueued) — confirm it actually re-dispatches now.
- Retrying a job that isn't in `failed` status is rejected (`422`).

## Scenario 5 — `/side-scanning` UI

**Steps:**
1. Navigate to `/side-scanning`.
2. Check the KPI cards (EC2 / Lambda / K8s / Registry job counts).
3. Filter by status and by type.
4. Click **Re-scan** on a failed job.

**Expected result:**
- KPI counts match `GET /api/v1/side-scans/jobs` grouped by `job_type`.
- Status/type filters narrow the table correctly.
- Re-scan button triggers the retry mutation and the job's status badge updates (pulse animation
  while running).
