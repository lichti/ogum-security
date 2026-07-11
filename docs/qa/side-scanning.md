# QA Scenario — Side-Scanning

Covers: `/side-scanning` UI, `/api/v1/side-scans/*`, and the deep file-system scan tasks
(`scan_ec2_instance_v2`, `scan_lambda_function`, `scan_container_image`, `scan_k8s_container`).

**Known gap as of this writing:** only the Kubernetes (`/webhooks/k8s-scan`) and container image
(`/webhooks/ecr`) scan types have an HTTP trigger. `scan_ec2_instance_v2` and
`scan_lambda_function` are fully implemented and unit/integration-tested (see
`tests/unit/services/test_side_scanning.py`, `tests/integration/tasks/test_side_scanning_v2.py`),
but nothing in the API dispatches them yet — there is no `POST` endpoint that calls
`scan_ec2_instance_v2.delay(...)`. Scenarios 1–2 below cover the two scan types that are
reachable end-to-end today; Scenario 3 documents how to exercise EC2/Lambda scanning in the
absence of a trigger endpoint, and doubles as a reminder this gap exists until it's closed.

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

## Scenario 3 — EC2 and Lambda scanning (no HTTP trigger yet)

**Steps (dev-only, until a trigger endpoint exists):**
1. From a shell inside the `worker` container, dispatch directly:
   ```python
   from app.workers.tasks.side_scanning import scan_ec2_instance_v2
   scan_ec2_instance_v2.delay(tenant_id="<tenant>", resource_id="<ec2-resource-key>", provider_id="<provider-key>")
   ```
   (or `scan_lambda_function.delay(...)` — check the task signature in `side_scanning.py` for
   exact required kwargs, they've changed between sprints).
2. Poll the resulting job the same way as Scenario 1 (a `scan_jobs` doc is created by the task
   itself via `start_discovery_job`).

**Expected result:**
- EC2: snapshot created → EBS Direct API scan via `trivy client vm ebs:{snapshot_id}` → snapshot
  deleted in `finally` even if the scan fails (verify no orphaned EBS snapshot remains on the
  account after a failed run — `cleanup_orphan_snapshots` Celery Beat task is the safety net if
  one does leak).
- Lambda: deployment package downloaded to `/dev/shm/ogum-{job_id}/` (RAM disk), scanned, then
  the RAM disk is wiped in `finally` regardless of outcome.
- Both produce an SBOM (`sboms` collection + `HAS_SBOM` edge) alongside findings.

**If you're reading this because the trigger endpoint now exists:** update this scenario to use
it instead of direct dispatch, and update the "known gap" note at the top of this file.

## Scenario 4 — Retry a failed scan

**Pre-condition:** at least one job from Scenarios 1–3 in `status: failed` (or force one by
passing an invalid `image_digest`/`resource_id`).

**Steps:**
1. `POST /api/v1/side-scans/jobs/{job_id}/retry`.
2. Confirm the response and poll the new job.

**Expected result:**
- Retry re-dispatches the correct task per `_RETRY_TASK_MAP` (`k8s_container`, `ecr`, `ec2`,
  `lambda`, `sbom_rescan` all map to their respective task).
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
