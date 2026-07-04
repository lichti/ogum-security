# Scanning Guide

This guide covers how to run CSPM and IaC scans in Ogum Security.

## CSPM Scanning (Ogum.Static)

CSPM scans use [Prowler v5](https://github.com/prowler-cloud/prowler) to check cloud configurations
against compliance frameworks. Scans run as Celery tasks in the background.

### Trigger a CSPM Scan

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: <your-tenant-id>" \
  -d '{
    "provider_id": "<provider-id>",
    "frameworks": ["CIS-AWS-2.0", "PCI_DSS_v4", "SOC2"]
  }'
```

Response:
```json
{"data": {"job_id": "abc123", "status": "queued"}}
```

### Poll Scan Status

```bash
curl http://localhost:8000/api/v1/scans/<job_id> \
  -H "X-Tenant-Id: <your-tenant-id>"
```

Status values: `queued` → `running` → `completed` | `failed`

### Supported Frameworks

| Framework | ID |
|---|---|
| CIS AWS Foundations Benchmark v2.0 | `CIS-AWS-2.0` |
| PCI DSS v4.0 | `PCI_DSS_v4` |
| SOC 2 Type II | `SOC2` |
| NIST 800-53 | `NIST_800_53` |
| ISO 27001 | `ISO27001` |
| LGPD | `LGPD` |

Pass an empty list `[]` to run all available checks:

```json
{"provider_id": "<id>", "frameworks": []}
```

### Scan Schedule

Scans are automatically triggered every 6 hours per connected provider.
Manual trigger via the API runs immediately (does not reset the schedule).

---

## IaC Scanning (Ogum.Static — Checkov)

IaC scans use [Checkov](https://github.com/bridgecrewio/checkov) to analyze Infrastructure as Code
repositories. Supported formats: Terraform (`.tf`), CloudFormation (`.yaml`/`.json`), Helm Charts,
and Kubernetes manifests.

### Trigger an IaC Scan

```bash
curl -X POST http://localhost:8000/api/v1/scans/iac \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: <your-tenant-id>" \
  -d '{
    "repo_url": "https://github.com/your-org/infra",
    "branch": "main",
    "path": "terraform/aws",
    "account_id": "111111111111",
    "repo_token": "ghp_your_github_token"
  }'
```

Response:
```json
{"data": {"job_id": "xyz789", "status": "queued"}}
```

**Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `repo_url` | ✓ | Git HTTPS or SSH URL |
| `branch` | ✗ | Branch to scan (default: `main`) |
| `path` | ✗ | Sub-directory within repo (default: `.`) |
| `account_id` | ✗ | Logical account label for findings (default: `iac`) |
| `repo_token` | ✗ | GitHub/GitLab token for private repos (never stored) |

### IaC Findings in the UI

IaC findings appear in the `/findings` page alongside CSPM findings.
Use the **Source** filter to show only IaC findings:

- **Source = cspm** — Prowler findings
- **Source = iac** — Checkov findings

IaC findings display the source file and line range in the detail panel.

### Security Notes

- Repository tokens are passed per-request and **never stored** in Ogum's database.
- Cloned repositories are deleted immediately after the scan completes (ephemeral temp directory).
- Scans run with read-only git access (`--depth=1` shallow clone).

---

## Exporting Findings

Export findings to CSV or JSON (OCSF-aligned) with active filters:

```bash
# Export all CRITICAL findings as CSV
curl "http://localhost:8000/api/v1/findings/export?format=csv&severity=CRITICAL" \
  -H "X-Tenant-Id: <your-tenant-id>" \
  -o findings_critical.csv

# Export IaC findings as JSON
curl "http://localhost:8000/api/v1/findings/export?format=json&source=iac" \
  -H "X-Tenant-Id: <your-tenant-id>" \
  -o findings_iac.json
```

Supported export filters: `severity`, `status`, `provider`, `framework`, `region`,
`account_id`, `resource_type`, `source`, `q` (full-text search).

The response streams the data — safe for large exports (100k+ findings).

### CSV Fields

`check_id`, `title`, `severity`, `status`, `provider`, `resource_type`, `resource_id`,
`resource_arn`, `account_id`, `region`, `source`, `framework_mapping` (pipe-separated),
`remediation`, `detected_at`, `updated_at`

### JSON Format

Follows an OCSF-compatible structure. Each finding object includes all fields from the
`Finding` model plus relationship metadata.
