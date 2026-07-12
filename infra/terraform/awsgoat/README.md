# AWSGoat — Vendored Vulnerable Applications

`module-1/`, `module-2/`, `policy/`, and `attack-manuals/` are vendored from
[ine-labs/AWSGoat](https://github.com/ine-labs/AWSGoat) @ `b24869ad455ed8d1393d00ecdc15ee638d1c1332`
(2025-05-20), MIT License (Copyright (c) 2022 INE — see `LICENSE` in this directory), with a
small set of documented local patches (below) so they can be deployed together with
`../test-fixtures/` from a single `terraform apply`.

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
  Deploy manually instead (below) — this repo does not wire CI to deploy live cloud
  infrastructure.
- `defence-manuals/` (generic AWS security service walkthroughs, not specific to AWSGoat) and
  `AWSGoat.pdf` (conference slide deck) — available upstream if needed, low relevance here.

## Local patches applied on top of upstream

Both modules originally shipped as **independent Terraform root modules**, each with its own
`provider "aws"` block. They are now called as **child modules** from
`../test-fixtures/awsgoat.tf` so that one `terraform apply` from `test-fixtures/` can deploy
everything together. A module invoked with `count`/`for_each` cannot declare its own provider,
which required three kinds of changes — reapply the same three if re-vendoring from upstream:

1. **Removed `terraform { required_providers {...} }` / `provider "aws" {...}` from both
   `module-1/main.tf` and `module-2/main.tf`.** Both now inherit the `aws` provider (and its
   `~> 5.0` version constraint) from `test-fixtures/main.tf`. Note upstream pinned module-2 to
   `aws ~> 3.27` (module-1 to `~> 5.24.0`) — running module-2 under the newer provider produces a
   few harmless `deprecated argument` warnings (e.g. `aws_api_gateway_deployment.stage_name`) but
   `terraform validate`/`plan` succeed; no breaking schema changes were hit.
2. **Prefixed local file paths in `module-1/main.tf` with `${path.module}/`** (`source_dir`,
   `output_path`, `filename`, `fileset()`/`source` for S3 uploads, and `working_dir = path.module`
   on every `local-exec` provisioner). Unqualified relative paths resolve against the *root*
   module's working directory, not the child module's directory — they broke the moment this
   stopped being a standalone root module. `module-2/main.tf` already used `${path.module}/...`
   throughout, so it needed no path changes.
3. **Renamed the `bucket_tf_files` S3 bucket** in both modules — upstream gives both modules the
   *identical* literal name (`do-not-delete-awsgoat-state-files-<account_id>`), which is unused by
   either module but collides if both run in the same account. Now
   `do-not-delete-awsgoat-module1-state-files-...` / `...-module2-...`.

Everything else (resources, IAM policies, app source under `src/`, vulnerable logic) is untouched.

**Known upstream quirk carried over unmodified:** several `local-exec` provisioners `sed -i` the
checked-out resource files in place (bucket names, IPs, URLs get written directly into e.g.
`resources/dynamodb/blog-posts.json` and the pre-built React bundle) as part of deploying —
expect `git status` to show those files as modified after `terraform apply`/`destroy`. Discard
those changes (`git checkout -- module-1/resources`) rather than committing them.

## Usage

Deploy from `../test-fixtures/`, not from inside `module-1/`/`module-2/` — they are no longer
standalone root modules and have no provider of their own:

```bash
cd infra/terraform/test-fixtures
terraform apply -var="create_awsgoat_module1=true" -var="create_awsgoat_module2=true"
# ... test / validate Ogum against it ...
terraform apply -var="create_awsgoat_module1=false" -var="create_awsgoat_module2=false"  # tear down just AWSGoat
```

Entry-point URLs are in the `awsgoat_urls` output. Each module still builds its own self-contained
VPC — no shared networking with `test-fixtures`' own resources. Neither module has a `suffix`
variable (fixed resource names, as upstream ships them): running the *same* module twice in one
account will collide, so deploy in a dedicated, disposable sandbox account, not one already
running other workloads.

## Security note — read before deploying

These are **real, exploitable applications**, not simulated findings:

- **Never deploy in a production account or one with other resources.** Use a dedicated,
  disposable sandbox account.
- **The apps are meant to be internet-reachable by design** — that is the whole point of a
  black-box target. Do not treat public exposure as a bug to fix; treat it as a reason to isolate
  the account.
- **Destroy immediately after each test session.** Do not leave these running.
- Estimated cost while running (per upstream, `us-east-1`, on-demand): module-1 ~$0.0125/hour,
  module-2 ~$0.0505/hour.

## Updating

To pull upstream changes, re-clone `ine-labs/AWSGoat` at the desired commit, replace `module-1/`,
`module-2/`, `policy/policy.json`, and `attack-manuals/` wholesale, then reapply the three local
patches listed above (they're small and mechanical — grep for `path.module` and
`do-not-delete-awsgoat-module` in the current files to see exactly what changed). Record the new
commit SHA and date at the top of this file.
