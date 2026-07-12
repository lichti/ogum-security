# AWSGoat — Vendored Vulnerable Applications

`module-1/`, `module-2/`, `policy/`, and `attack-manuals/` are vendored **unmodified** from
[ine-labs/AWSGoat](https://github.com/ine-labs/AWSGoat) @ `b24869ad455ed8d1393d00ecdc15ee638d1c1332`
(2025-05-20), MIT License (Copyright (c) 2022 INE — see `LICENSE` in this directory).

This complements `../test-fixtures/`, which deploys synthetic misconfigurations (no running
application, cheap, safe to leave up). AWSGoat instead deploys **real, deliberately vulnerable
applications** with app-layer bugs (XSS, SQLi, IDOR, SSRF) chained into cloud-layer privilege
escalation (IAM, S3, ECS). Use it to validate Ogum end-to-end against an actual exploitation
chain — Ogum.Dynamic finding the app-layer vulnerability, Ogum.Pulse/CDR detecting the resulting
IAM/API activity, Ogum.Graph reconstructing the attack path — not just CSPM misconfiguration
detection.

## What's here

| Module | Stack | Escalation path | Attack manual |
|---|---|---|---|
| `module-1/` | Lambda + API Gateway + DynamoDB + S3 (serverless blog) | XSS → SQLi → IDOR → sensitive data exposure → Lambda SSRF → IMDS credential theft → IAM privilege escalation | `attack-manuals/module-1/` |
| `module-2/` | ECS/Fargate + PHP (HR payroll app) | SQLi → file upload → ECS task metadata → container breakout → IAM privilege escalation | `attack-manuals/module-2/` |

`policy/policy.json` is the minimum IAM policy upstream documents for the AWS credentials used to
deploy (not the vulnerable app's own roles — those are intentionally overprivileged, that's the
point).

`module-1/resources/s3/shared/.../keys/*.pem` are **fake decoy SSH keys** planted by upstream as
part of the IDOR training scenario — not real credentials, do not treat a scan hit on them as an
incident.

## Deliberately NOT vendored

- Upstream's `.github/workflows/` (auto-deploy via `workflow_dispatch` + AWS secrets in Actions).
  Deploy manually instead (below) — consistent with `../test-fixtures/`, this repo does not wire
  CI to deploy live cloud infrastructure.
- `defence-manuals/` (generic AWS security service walkthroughs, not specific to AWSGoat) and
  `AWSGoat.pdf` (conference slide deck) — available upstream if needed, low relevance here.

## Usage

Each module is its own root Terraform module — deploy from inside it, same as upstream:

```bash
cd infra/terraform/awsgoat/module-1   # or module-2
terraform init
terraform apply
# ... test / validate Ogum against it ...
terraform destroy
```

Unlike `../test-fixtures/`, these modules have **no `suffix` variable** — resource names are
fixed, as upstream ships them. Deploy in a dedicated, empty sandbox AWS account, one module at a
time, never alongside other workloads.

## Security note — read before deploying

These are **real, exploitable applications**, not simulated findings:

- **Never deploy in a production account or one with other resources.** Use a dedicated,
  disposable sandbox account.
- **The apps are meant to be internet-reachable by design** — that is the whole point of a
  black-box target. Do not treat public exposure as a bug to fix; treat it as a reason to isolate
  the account.
- **Destroy immediately after each test session** (`terraform destroy`). Do not leave these
  running.
- Estimated cost while running (per upstream, `us-east-1`, on-demand): Module 1 ~$0.0125/hour,
  Module 2 ~$0.0505/hour.

## Updating

To pull upstream changes, re-clone `ine-labs/AWSGoat` at the desired commit and replace
`module-1/`, `module-2/`, `policy/policy.json`, and `attack-manuals/` wholesale — treat this as
vendored third-party code, not something to hand-edit in place. Record the new commit SHA and
date at the top of this file.
