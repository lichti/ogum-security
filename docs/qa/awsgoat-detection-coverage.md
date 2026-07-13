# AWSGoat Detection Coverage

Unlike the scenario files in this directory, this is a **coverage reference**, not a step-by-step
walkthrough: it maps every vulnerability in the vendored AWSGoat modules
(`infra/terraform/awsgoat/`) to the Ogum module/mechanism that should detect it, and marks
explicit gaps where nothing today does. Use it to plan a live end-to-end validation session
(deploy AWSGoat → run Ogum → check that every row marked "Detected" actually produced a
finding/attack path) and to prioritize backlog items for the rows marked "GAP".

Source: `attack-manuals/module-1/`, `attack-manuals/module-2/` (upstream ine-labs walkthroughs)
plus a read of the vendored Terraform (`module-1/main.tf`, `module-2/main.tf`,
`module-2/resources/ecs/task_definition.json`) for infrastructure-layer issues the app-layer
manuals don't call out.

## How to read the tables

- **Detected today** — an existing Ogum module/check, as implemented in this codebase right now,
  produces a finding or attack path for this specific vulnerability.
- **GAP** — no current Ogum capability catches this, with the specific reason why.
- Module column refers to the AWSGoat module (1 or 2), not an Ogum module.

---

## Module 1 — Serverless blog (Lambda + API Gateway + DynamoDB + S3)

Attack chain: XSS → SQLi → IDOR → sensitive data exposure → Lambda SSRF → IMDS credential theft →
IAM privilege escalation.

| # | Vulnerability | Ogum module | Mechanism | Status |
|---|---|---|---|---|
| 1 | Reflected XSS in the blog search field (`01-Reflected XSS.md`) | — | — | **GAP** — application-layer logic flaw (unescaped output), not a cloud misconfiguration or a known-CVE dependency. Neither Ogum.Static (CSPM) nor Ogum.Dynamic (Trivy/YARA) perform application-layer DAST/SAST of custom app code. Out of scope for the current module set; would require a dedicated SAST/DAST capability not on the roadmap. |
| 2 | SQL injection in the `list-users` Lambda endpoint via `value`/`authlevel` params (`02-SQL Injection.md`) | — | — | **GAP** — same reasoning as #1: this is a query-construction bug in `lambda_ba_data`'s own code, not a CVE in a dependency. `scan_lambda_function` runs Trivy against the deployed Lambda artifact for known-vulnerable dependencies and hardcoded secrets, not custom business-logic injection flaws. |
| 3 | IDOR — changing another user's password via a client-controlled `id` parameter (`03-Insecure Direct Object Reference.md`) | — | — | **GAP** — authorization logic bug, not a dependency CVE or infra misconfiguration. No Ogum module performs business-logic/authz testing of application endpoints. |
| 4 | Sensitive data exposure — unauthenticated `list-posts`-adjacent endpoint returns all users' PII (emails, passwords, addresses) when fuzzed (`04-Sensitive Data Exposure.md`) | — | — | **GAP** — same class as above (missing authz check on an API Gateway route). Ogum.Graph's `STORES_SENSITIVE_DATA` edges model *which resources* hold sensitive data once discovered, but nothing here maps an unauthenticated API route to unintended data exposure. |
| 5 | SSRF via `file://` URL scheme in the "image URL" field of Newpost, reading `/etc/passwd` and `/proc/self/environ` from the Lambda execution environment (`05-SSRF Part 1.md`, `06-SSRF Part 2.md`) | — | — | **GAP** at the vulnerability level (app-layer input validation), but see #6 — once the SSRF is exploited to steal Lambda role credentials, downstream misuse of those credentials is partially covered. |
| 6 | `blog_app_lambda_data` execution role has effectively unrestricted permissions (`s3:*`, `dynamodb:*`, `lambda:*`, `cloudwatch:*`, `logs:*`, `sns:*`, `dax:*`, `autoscaling:Describe*` — `lambda_data_policies`, `module-1/main.tf:3125-3156`) | Ogum.Graph (CIEM) | `ciem_service.analyze_dangerous_permissions` flags `s3:*`, `lambda:UpdateFunctionCode`, `lambda:AddPermission` as dangerous wildcard/exact-match grants on this identity (`DANGEROUS_PERMISSIONS` in `ciem_service.py`). `find_assume_role_chains`/TC-03 (`attack_path_service._detect_tc03_overpermissioned_to_db`) can surface this role reaching DynamoDB (`blog-users`/`blog-posts`) as an overpermissioned-identity-to-DB toxic combination once graph edges exist. | **Detected today** (the overprivileged-role finding itself) — the *SSRF-to-credential-theft* exploitation path itself is not simulated; Ogum flags the standing risk (this role is overpermissioned), not the live attack. |
| 7 | Attacker writes a forged admin user directly into the `blog-users` DynamoDB table using stolen Lambda credentials (`06-SSRF Part 2.md`, steps 9-14) | Ogum.Pulse (NRT) | Would require CloudTrail/API-activity ingestion correlating an unusual `dynamodb:PutItem` from a Lambda-assumed identity against a per-principal behavioral baseline + a matching TTP (Signal Score design, ADR-011) | **GAP in this environment** — Ogum.Pulse's NRT pipeline (Redpanda/Flink CEP) needs live CloudTrail ingestion wired to a running tenant; AWSGoat is deployed ad hoc into a disposable sandbox account, typically without Ogum.Pulse's log forwarders (Vector.dev/Fluent Bit → Redpanda) provisioned. The *capability* exists in the codebase; it is a **deployment/environment gap for this specific test fixture**, not a missing Ogum feature. |
| 8 | `AWS_GOAT_ROLE` (EC2 instance role) has `AmazonS3FullAccess` (managed policy) plus a custom policy (`dev-ec2-lambda-policies`) with broad `lambda:*Function*`/`lambda:AddPermission`/`lambda:InvokeFunction` (`module-1/main.tf:3513-3540ish`) | Ogum.Graph (CIEM) | Same `analyze_dangerous_permissions` mechanism as #6 — `s3:*`-equivalent (`AmazonS3FullAccess` is a managed policy Prowler exposes with its full document) and `lambda:AddPermission`/`lambda:UpdateFunctionCode` are exact-match dangerous entries. | **Detected today** |
| 9 | `AWS_GOAT_sg` security group allows SSH (port 22) from `0.0.0.0/0` (`module-1/main.tf:3466-3486`) | Ogum.Static (Prowler CSPM) | Prowler's EC2/security-group checks (open-port-to-internet family) flag `0.0.0.0/0` ingress on sensitive ports including 22. | **Detected today** |
| 10 | `dev`/`bucket_upload`/`bucket_temp` S3 buckets are public (`block_public_acls/block_public_policy = false`, `acl = "public-read"`, `module-1/main.tf:3201-3395`) | Ogum.Static (Prowler CSPM) | Prowler's S3 public-access checks (`_list_s3_buckets`/`is_public` logic per `CHANGELOG.md`) flag buckets with no public-access-block or a public-read ACL. | **Detected today** — flags the buckets as publicly readable. |
| 11 | The `dev` bucket's public objects include `resources/s3/shared/.../keys/*.pem` (decoy SSH private keys, planted intentionally) and a `config.txt` listing internal host IPs and keyfile paths (`07-IAM Privilege Escalation.md`) — the actual secret-content exposure, distinct from #10's "bucket is public" structural finding | — | — | **GAP** — Ogum.Dynamic (Trivy/YARA secrets+malware scanning) covers EC2 EBS snapshots, Lambda artifacts, and container filesystems/images, but has **no S3 object-content scanner**. Ogum.Static's CSPM check (#10) only asserts "this bucket is public," not "and it contains private key material." A public bucket holding real secrets is a materially different (and more urgent) finding than a public bucket holding static assets; today Ogum cannot distinguish the two. **Recommended backlog item**: extend Ogum.Dynamic (or a new lightweight Ogum.Static sub-check) to sample/scan public bucket object contents for secrets (Trivy's secret detector already runs elsewhere in the pipeline and could be pointed at downloaded S3 objects). |
| 12 | `blog_app_lambda_data`'s IAM policy document itself, once fetched via stolen credentials, reveals `lambda:*` + `execute-api:Invoke`/`ManageConnections` on `*` (`07-IAM Privilege Escalation.md`, mid-manual `aws iam get-policy-version` steps) | Ogum.Graph (CIEM) | Same mechanism as #6/#8 — this is the same `lambda_data_policies` document already modeled. | **Detected today** (as a standing finding; not simulated as a live credential-theft replay) |
| 13 | Attacker creates a new managed policy with `{"Action":"*","Resource":"*"}` and attaches it to `blog_app_lambda_data`, then creates an admin IAM user (`07-IAM Privilege Escalation.md`, `full_policy.json`/`escalation_policy` steps) | — | — | **GAP as a live event** — same class as #7: this is new IAM API activity (`iam:CreatePolicy`, `iam:AttachRolePolicy`, `iam:CreateUser`, `iam:AttachUserPolicy`) that Ogum.Pulse's Signal Score is designed to catch via behavioral-baseline + TTP matching, contingent on CloudTrail being wired up in the sandbox account (see #7). On the *next* CSPM re-scan after the attack, though, the newly created `hacker` user with `AdministratorAccess` **would** be caught structurally — a fresh admin identity is exactly what `has_admin_policy`-based CIEM/TC-03 detection flags. |

## Module 2 — HR payroll app (ECS on EC2 + RDS MySQL + ALB + PHP)

Attack chain: SQLi → file upload → ECS task metadata → container breakout → IAM privilege
escalation (permission-boundary bypass via `iam:PassRole` + `ec2:RunInstances` + SSM).

| # | Vulnerability | Ogum module | Mechanism | Status |
|---|---|---|---|---|
| 1 | SQL injection in the login form's `Email` field (`'or '1'='1'#`), allowing login as arbitrary users including admin via `ORDER BY`/`LIMIT` manipulation (`01-SQL Injection.md`) | — | — | **GAP** — application-layer logic bug in the vendored PHP app, same reasoning as module-1 #1/#2. No SAST/DAST capability in Ogum today. |
| 2 | Hardcoded RDS root password in Terraform source (`password = "T2kVB3zgeN3YbrKS"`, `module-2/main.tf:132`) | Ogum.Static (Checkov IaC scan) | Checkov's hardcoded-secret/credential checks scan Terraform source for literal password/secret values before deployment. | **Detected today** — this is an IaC-time finding (scanning the Terraform file itself), independent of runtime discovery. |
| 3 | File upload with no extension/content-type restriction on the Manager "Payslips" page, allowing a PHP reverse shell upload later executable via the Normal User "Payslips" page (`02-File Upload and Task Metadata.md`) | — | — | **GAP** — application-layer authz/validation bug (inconsistent restriction between user roles), not a dependency CVE. Once the shell is live and dropped to the container filesystem, see #4 for what *is* covered. |
| 4 | The dropped PHP reverse shell itself, if captured by a filesystem/image scan (e.g. if Ogum.Dynamic scanned the running container's filesystem after exploitation) | Ogum.Dynamic (YARA) | YARA malware-signature scanning (`_run_yara_via_scoped_mount` in `app/workers/tasks/side_scanning.py`) is designed to catch webshells/malware dropped onto disk. | **Conditional / untested** — YARA scanning today runs against **EC2 EBS snapshots** (`scan_ec2_instance_v2`) via a scoped mount, and separately against **K8s container filesystems** (`scan_k8s_container`). Module-2's app runs in an **ECS-on-EC2** container (not raw EC2, not K8s) — whether a webshell dropped inside that Docker container is visible to a snapshot-based EC2 scan of the *host* EBS volume (as opposed to the container's own writable layer) has not been verified and should be confirmed in a live test session; it is plausible but not confirmed by reading the code alone. |
| 5 | ECS task definition grants `SYS_PTRACE` Linux capability plus `pid_mode: host` and mounts `/lib/modules`/`/usr/src/kernels` from the host (`module-2/resources/ecs/task_definition.json`), directly enabling the container-breakout technique in `03-ECS Breakout and Instance Metadata.md` | — | — | **GAP** — Ogum has no ECS task-definition-level CSPM check for dangerous `linuxParameters.capabilities`/`pidMode: host`/host-path volume mounts in this codebase today (Prowler upstream has some ECS checks, but coverage of this specific combination was not confirmed by reading `app/services/prowler_inventory.py`). **Recommended backlog item**: this is a textbook container-escape-enabling misconfiguration and a strong CSPM candidate if not already covered by the current Prowler check subset in use. |
| 6 | `sudo -l` reveals passwordless `vim` as root on `/var/www/html/documents`, used to spawn a root shell (`03-ECS Breakout...`, escalation-to-root step) | — | — | **GAP** — host/container OS-level misconfiguration (sudoers entry), not visible to any current Ogum module; this is closer to a CIS-benchmark host-hardening check than a cloud API-visible misconfiguration, and Ogum's side-scanning does not currently audit `/etc/sudoers`. |
| 7 | IMDS reachable from the EC2 host after container breakout, returning instance role credentials (`03-ECS Breakout...`) — no IMDSv2 enforcement visible in `module-2/main.tf`'s launch template | Ogum.Static (Prowler CSPM) | Prowler's EC2 metadata-service checks (IMDSv2 enforcement family) flag instances/launch templates that don't require `http_tokens = "required"`. | **Detected today** *if* the corresponding Prowler check is in the active check set — `aws_launch_template.ecs_launch_template` (`module-2/main.tf:344-355`) has no `metadata_options` block at all, so it inherits the account/region default; whether the specific IMDSv2-enforcement check is enabled was not independently confirmed by reading `prowler_inventory.py` for this check ID. |
| 8 | `ecs-instance-role` is attached `IAMFullAccess` directly (`module-2/main.tf:191-194`), separate from its permission boundary | Ogum.Graph (CIEM) | `IAMFullAccess` is a managed policy; Prowler exposes its full document, and `analyze_dangerous_permissions` matches its `iam:*`-equivalent wildcard actions against `DANGEROUS_PERMISSIONS`. | **Detected today** |
| 9 | `aws-goat-instance-boundary-policy` (the permission boundary itself) grants `iam:PassRole` + `ec2:RunInstances` + `iam:List*`/`iam:Get*` (`module-2/main.tf:221-247`) — the exact combination that enables the boundary bypass in `04-IAM Privilege Escalation.md` | Ogum.Graph (CIEM) | `iam:PassRole` is an exact-match entry in `DANGEROUS_PERMISSIONS` (`ciem_service.py`), so the identity carrying this permission (via its boundary) is flagged as dangerous. | **Partially detected** — the *flat* dangerous-permission flag on `iam:PassRole` fires, but Ogum.Graph has **no `PASSES_ROLE` edge type** (`build_iam_edges` only materializes `STS_ASSUMEROLE_ALLOW`/`ASSUMES`/`ATTACHED_POLICY`). The specific **chained** escalation this manual demonstrates — pass `ec2Deployer-role` (admin-equivalent, via `ec2_deployer_admin_policy`, `Action: "*"`) to a *new* EC2 instance via `ec2:RunInstances`, then retrieve its credentials via SSM — is not modeled as a graph traversal/attack path today; it is visible only as two independent flat findings ("this role has `iam:PassRole`" and "this other role has `Action:*`"), not as a connected path between them. **Recommended backlog item**: add a `PASSES_ROLE` edge (identity → identity, derived from `iam:PassRole`-bearing policies plus resource-creation actions like `ec2:RunInstances`/`iam:PassRole` pairing) so TC-03-style traversal can surface this as a single toxic combination, matching how `ASSUMES_ROLE` already models the more common AssumeRole-based escalation chain. |
| 10 | `ec2Deployer-role`'s attached policy (`ec2_deployer_admin_policy`) grants `Action: "*"`, `Resource: "*"` (`module-2/main.tf:272-292`) — full admin | Ogum.Graph (CIEM) | `iam:*`/wildcard-equivalent full-admin detection (`has_admin_policy`/`DANGEROUS_PERMISSIONS`). | **Detected today** |
| 11 | RDS instance is `publicly_accessible`-adjacent risk via its security group allowing 3306 only from `ecs_sg` (this one is actually *correctly* scoped — included here as a negative control) | Ogum.Static (Prowler CSPM) | Prowler's RDS/security-group checks would correctly **not** flag this, since ingress is restricted to the ECS security group, not `0.0.0.0/0`. | **Correctly not flagged** — included to confirm Ogum doesn't over-alert on this resource. |
| 12 | `load_balancer_security_group` allows HTTP (port 80) from `0.0.0.0/0` (`module-2/main.tf:142-163`) | Ogum.Static (Prowler CSPM) | Same open-ingress check family as module-1 #9, though port 80 on a public-facing ALB is often accepted/suppressed by default rulesets as intentional for a public web app — worth confirming this isn't silently excluded. | **Detected today, but likely low-signal by design** — flagging a public ALB's port 80 as "open to the internet" is technically correct but expected for any public web app; verify in a live run that this doesn't drown out the higher-value findings above. |

---

## Summary of gaps (backlog candidates, in priority order)

1. **No S3 object-content secret scanning** (Module 1, #11) — the highest-value gap: a public
   bucket holding real secrets is a fundamentally different risk than a public bucket holding
   static assets, and Ogum can't currently tell them apart.
2. **No `PASSES_ROLE` graph edge for `iam:PassRole`-based escalation chains** (Module 2, #9) — the
   `ec2:RunInstances`/`iam:PassRole`/SSM-credential-theft pattern is a well-known AWS privilege
   escalation technique (distinct from `sts:AssumeRole` chaining, which Ogum already models) and
   is not surfaced as a connected attack path today, only as disconnected flat findings.
3. **No ECS task-definition CSPM check for dangerous `linuxParameters`** (Module 2, #5) —
   `SYS_PTRACE` + `pidMode: host` + host-path volume mounts is a textbook container-escape enabler;
   confirm whether the active Prowler check subset already covers this before treating it as a
   true gap.
4. **Application-layer vulnerabilities (XSS, SQLi, IDOR, broken authz, SSRF, unrestricted file
   upload)** — 8 of the 20 total findings across both modules are pure app-layer logic bugs.
   These are explicitly out of scope for Ogum's current module set (CSPM + side-scanning +
   attack-path graph + NRT); no backlog item is implied unless a SAST/DAST module is added to the
   roadmap.
5. **Ogum.Pulse coverage depends on the sandbox account having log forwarders wired up** (Module
   1, #7/#13) — not a code gap, but a reminder that live end-to-end verification of the NRT/CDR
   path requires deploying Vector.dev/Fluent Bit → Redpanda into the disposable AWSGoat account,
   which is easy to forget since AWSGoat's own Terraform doesn't provision it.

Several "Detected today" rows above are based on reading `ciem_service.py`/`attack_path_service.py`
logic and are high-confidence; a few "Detected today, if..." rows note specific Prowler check IDs
that were not independently verified against the active check subset in `prowler_inventory.py` and
should be confirmed in a live deployment before relying on this document as a compliance guarantee.
Also note: `CLAUDE.md`/`README.md` describe the side-scanning stack as "Trivy + YARA + Gitleaks,"
but no `gitleaks` invocation exists in `app/` today — secret detection in the current pipeline runs
entirely through Trivy's built-in secret scanner (`_normalise_trivy_secret`), not a separate
Gitleaks pass. This doesn't change any row above (Trivy's secret scanner is what's cited throughout)
but is worth reconciling in the docs separately.
