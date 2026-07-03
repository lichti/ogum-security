# Connecting Cloud Accounts

This guide explains how to connect cloud provider accounts to Ogum Security so that asset discovery can populate the risk graph.

## Overview

Connecting an account is the first action required after deploying Ogum. Every other module (CSPM, Side-Scanning, Attack Path, AI remediation) depends on the inventory built by the discovery job.

**What happens when you connect an account:**

1. Provider configuration is saved in ArangoDB (`tenant_config` collection, no credentials stored).
2. A Celery discovery job is dispatched immediately.
3. The job crawls the provider API and persists resources as vertices in the risk graph.
4. Relationship edges (e.g. EC2 → VPC, IAM Role → Lambda) are created in the same run.
5. The inventory is visible in the UI and available via API.

---

## Connecting via the UI

Navigate to **Connected Accounts** (`/providers`) and click **Connect Account**.

The wizard has two steps:

**Step 1 — Select provider**

| Option | What it covers |
|---|---|
| Amazon Web Services | EC2, IAM, S3, RDS, Lambda, EKS, ECR, VPC, KMS, Secrets Manager |
| Microsoft Azure | VMs, VNets, NSGs, Storage Accounts, AKS, Entra ID, Key Vault |
| Google Cloud Platform | Compute, GCS, GKE, IAM Service Accounts, Cloud SQL, Firewall Rules |
| Kubernetes | Pods, Deployments, Services, Ingresses, ServiceAccounts, RBAC, Nodes |

**Step 2 — Configure**

Fill in the provider-specific identifier:

| Provider | Required field | Example |
|---|---|---|
| AWS | AWS Account ID | `123456789012` |
| Azure | Subscription ID | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| GCP | Project ID | `my-project-id` |
| Kubernetes | Cluster Name | `prod-cluster` |

Optionally set a **Display Name** (defaults to `<PROVIDER> Account`). For AWS, list the regions to scan as a comma-separated string (e.g. `us-east-1, eu-west-1`).

Click **Connect & Start Discovery**. The wizard shows a confirmation with the Celery job ID when the job is queued.

---

## Connecting via the API

### Register a provider

```http
POST /api/v1/providers
X-Tenant-ID: <tenant_id>
Content-Type: application/json

{
  "provider": "aws",
  "display_name": "Production AWS",
  "account_id": "123456789012",
  "regions": ["us-east-1", "eu-west-1"],
  "validate_connection": false
}
```

**Response (201):**

```json
{
  "data": {
    "provider_id": "aws-123456789012",
    "discovery_job_id": "e3b2c1a0-...",
    "message": "Provider registered. Discovery job queued — check /api/v1/inventory for resources."
  },
  "meta": { "request_id": "...", "timestamp": "..." }
}
```

**Provider-specific payloads:**

```jsonc
// Azure
{ "provider": "azure", "display_name": "Azure Prod", "subscription_id": "sub-...", "validate_connection": false }

// GCP
{ "provider": "gcp", "display_name": "GCP Dev", "project_id": "my-project-id", "validate_connection": false }

// Kubernetes
{ "provider": "k8s", "display_name": "EKS Prod", "cluster_name": "prod-cluster", "validate_connection": false }
```

**`validate_connection`**: when `true` (default), the API calls `ec2:DescribeRegions` + `sts:GetCallerIdentity` to verify AWS credentials before saving the config. Set to `false` in environments where the backend inherits credentials via IAM role or env vars.

---

## Managing Connected Accounts

### List all providers

```http
GET /api/v1/providers
X-Tenant-ID: <tenant_id>
```

### Get a single provider

```http
GET /api/v1/providers/{provider_id}
X-Tenant-ID: <tenant_id>
```

### Update display name, regions or enabled state

```http
PATCH /api/v1/providers/{provider_id}
X-Tenant-ID: <tenant_id>
Content-Type: application/json

{
  "display_name": "Production AWS — renamed",
  "regions": ["us-east-1", "eu-west-1", "ap-southeast-1"],
  "enabled": true
}
```

All fields are optional — only the fields present in the request body are updated.

**Effect of `enabled` on status:**

| Value | Resulting `status` |
|---|---|
| `true` | `active` |
| `false` | `disabled` |

### Re-trigger discovery manually

```http
POST /api/v1/providers/{provider_id}/discover
X-Tenant-ID: <tenant_id>
```

Returns 409 if the provider is disabled. Enable it first via PATCH before re-triggering.

**Response (200):**

```json
{
  "data": {
    "provider_id": "aws-123456789012",
    "discovery_job_id": "f4c3d2e1-...",
    "message": "Discovery job queued — check /api/v1/inventory for resources."
  }
}
```

### Delete a provider

```http
DELETE /api/v1/providers/{provider_id}
X-Tenant-ID: <tenant_id>
```

Removes the provider configuration. **Does not delete the resources already in the graph** — existing vertices remain with `status: active` until the next reconciliation pass marks orphaned resources as `deleted`.

---

## Provider Status Reference

| Status | Meaning |
|---|---|
| `pending` | Provider registered, discovery not yet completed |
| `active` | Last discovery completed successfully |
| `error` | Last discovery failed (check worker logs) |
| `disabled` | Manually disabled via PATCH — discovery will not run |

---

## Credential Model

Ogum **never stores credentials** in ArangoDB. Discovery tasks run in Celery workers and use the ambient credential chain of the worker process.

| Provider | Recommended approach | Dev/test fallback |
|---|---|---|
| AWS | IAM Role attached to worker (IRSA for EKS, instance profile for EC2) | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` env vars |
| Azure | Managed Identity attached to worker | `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET` + `AZURE_TENANT_ID` |
| GCP | Workload Identity Federation | `GOOGLE_APPLICATION_CREDENTIALS` pointing to service account JSON |
| Kubernetes | In-cluster `ServiceAccount` with read access | `KUBECONFIG` env var |

For static key management (non-recommended), use HashiCorp Vault as documented in `specs/credential-model.md`.

---

## Discovery Schedule

Discovery runs automatically via Celery Beat on the following schedule:

| Provider | Default interval | Configurable via |
|---|---|---|
| AWS, Azure, GCP | Every 6 hours | `tenant_config.schedule_interval` |
| Kubernetes | Every 1 hour | `tenant_config.schedule_interval` |

The first discovery runs immediately after registration. Subsequent runs are incremental (upsert — no truncate), so existing findings linked to resources are preserved across re-runs.

---

## Troubleshooting

**Discovery job dispatched but no resources appear after 10 minutes**

1. Check Celery worker logs: `docker compose logs worker`.
2. Verify credentials: the worker process must have access to the provider API.
3. Check rate limits: discovery backs off exponentially on 429 / Throttling errors but will eventually succeed.
4. Check the job status via Flower (Celery monitoring UI) at `http://localhost:5555`.

**`validate_connection` returns 422 for AWS**

The backend attempted `ec2:DescribeRegions` and it failed. Common causes:
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` not set in the worker environment.
- IAM role not attached to the backend container.
- Region in the `regions` array is invalid or not opted-in.

Set `"validate_connection": false` to skip the pre-flight check and verify connectivity separately.

**Provider stuck in `pending` status**

The Celery worker did not successfully complete the discovery task. Check worker logs and re-trigger via:

```http
POST /api/v1/providers/{provider_id}/discover
```
