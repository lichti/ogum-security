# Manual QA Scenarios

This directory holds manual/exploratory test scenarios that complement the automated suite
(`pytest -m unit/integration/security`, frontend component tests). They exist for end-to-end
flows that are expensive or awkward to assert automatically — connecting a real cloud account,
verifying that a scan's output is consistent across Inventory, Compliance, and Attack Paths at
once, or confirming a job actually shows up correctly in the Admin UI.

Each scenario is written as: **pre-conditions → steps → expected result → what to check if it
fails**. Follow them in order; later steps usually depend on data created by earlier ones.

## When to run these

- **Before cutting a release** — run every scenario below against a real (or Terraform-seeded
  test) cloud account.
- **After changing a module** — run at minimum the scenario file for that module. Example: any
  change to `backend/app/services/prowler_inventory.py`, `graph/resource_edges.py`, or
  `prowler_service.py` → run [`cspm-compliance.md`](./cspm-compliance.md) in full, since those
  files feed Inventory, Compliance, and Attack Paths simultaneously.
- **After a bug fix in this area** — re-run the specific scenario the bug affected, not just the
  automated regression test, since the automated test typically covers the unit that was fixed,
  not the full pipeline the user actually experiences.

## Scenario index

| File | Covers | Depends on |
|---|---|---|
| [`inventory.md`](./inventory.md) | Connecting an AWS account, discovery/scan populating the resource graph | A real or test AWS account with credentials |
| [`cspm-compliance.md`](./cspm-compliance.md) | Full CSPM scan: findings, inventory, compliance dashboard, and attack paths staying consistent with each other | `inventory.md` completed (account connected) |
| [`attack-paths.md`](./attack-paths.md) | Attack path detection (toxic combinations, privilege escalation) and the graph visualization | `cspm-compliance.md` completed (findings + graph edges exist) |
| [`side-scanning.md`](./side-scanning.md) | Deep file-system scanning for EC2, Lambda, container images, and Kubernetes pods | `inventory.md` completed; provider-specific setup per scenario |
| [`admin.md`](./admin.md) | Admin panel: job visibility, forcing/retrying jobs, log streaming, worker/queue status | At least one job (from any scenario above) already exists |

## Environment setup

All scenarios assume the local Docker Compose stack is running:

```bash
docker compose up -d
```

And a tenant header is available for API calls — scenarios use `X-Tenant-Id: <your-tenant-id>`
(or `X-Tenant-ID` for the legacy inventory endpoints — see [`getting-started.md`](../getting-started.md)
if the two headers confuse you, that inconsistency is tracked as tech debt).

Where a scenario needs a real cloud account, prefer the Terraform fixtures under
`infra/terraform/test-fixtures/` over a production account — several scenarios intentionally
create findings (public S3 bucket, wildcard IAM policy) that you do not want in a real
environment.

## Reporting a failure

If a step's expected result doesn't match:

1. Check the specific collection/query listed under "what to check if it fails" directly in
   ArangoDB (`docker compose exec arangodb arangosh`) — the UI and API are downstream of the
   graph, so confirming the data is correct in ArangoDB first isolates whether the bug is in
   extraction/persistence or in a query/rendering layer.
2. Check `docker compose logs worker` / `docker compose logs backend` for the relevant time
   window.
3. File the discrepancy as a bug with the scenario name, step number, and the actual vs.
   expected result — that's enough for someone else to reproduce without re-deriving the scenario.
