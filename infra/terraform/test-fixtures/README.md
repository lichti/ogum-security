# Test Fixtures — Terraform

AWS resources intentionally configured with known misconfigurations to validate Ogum.Static (CSPM) and Ogum.Inventory discovery.

Also deploys (opt-in) [AWSGoat](../awsgoat/README.md) — real exploitable applications for end-to-end validation (app-layer bug → cloud privilege escalation) rather than synthetic misconfigurations. See the "AWSGoat" section below.

## What gets deployed

| Resource | Scenario | Expected CSPM findings |
|---|---|---|
| `aws_instance.public_exposed` | EC2 in public subnet, open SG, overprivileged IAM, IMDSv2 optional | IMDSv2 not required |
| `aws_instance.private_clean` | EC2 in private subnet, restricted SG, IMDSv2 required | None (compliant baseline) |
| `aws_security_group.open_ssh` | SSH + RDP open to 0.0.0.0/0 | CIS 5.2, CIS 5.4 |
| `aws_security_group.restricted` | HTTPS only from private CIDR | None |
| `aws_s3_bucket.public_data` | No block public access, no versioning, no encryption | 3 findings |
| `aws_s3_bucket.private_compliant` | Fully locked down, versioned, KMS encrypted | None |
| `aws_iam_role.overprivileged` | Inline policy with `Action: *` + `Resource: *` | Wildcard IAM policy |
| `aws_iam_role.least_privilege` | AmazonSSMManagedInstanceCore only | None |
| `aws_iam_user.test_user_with_key` | IAM user with active access key | Active IAM access key |
| `aws_cloudtrail.test_trail` | Single-region trail | Not multi-region |
| `aws_subnet.public` | `map_public_ip_on_launch = true` | Public IPs assigned by default |

## Known-vulnerable applications (optional, off by default)

Real, known-vulnerable targets for validating Ogum.Dynamic (side-scanning: Trivy/YARA/Gitleaks) against actual CVEs and secrets — as opposed to the synthetic misconfigurations above. Both are disabled by default and, when enabled, deploy into the **private subnet with no public ingress**.

| Resource | Scenario | Enable with |
|---|---|---|
| `aws_instance.metasploitable` | Metasploitable (real, intentionally vulnerable services) | `create_metasploitable_ec2 = true` |
| `aws_instance.dvwa` | DVWA (Damn Vulnerable Web App) via Docker | `create_dvwa_ec2 = true` |

**Metasploitable setup:** Rapid7 does not publish a redistributable AWS AMI — its license restricts Metasploitable to isolated local VM use. Build your own AMI first (e.g. with the official [Metasploitable3 Packer templates](https://github.com/rapid7/metasploitable3)), tag it, and either set `metasploitable_ami_id` directly or leave it empty and adjust `metasploitable_ami_name` to match your tag. Skip this if you only need DVWA.

**Access:** both instances live in the private subnet with a security group that has **no ingress rules by default**. Reach them via AWS Systems Manager Session Manager (an IAM role + instance profile with `AmazonSSMManagedInstanceCore` is attached automatically), or add your own IP to `vulnerable_apps_allowed_cidrs` — never `0.0.0.0/0`, enforced by a Terraform validation rule.

## AWSGoat (optional, off by default)

Two real, deliberately vulnerable applications vendored in `../awsgoat/` — a serverless blog (Lambda/API Gateway/DynamoDB/S3) and an ECS/Fargate HR payroll app — each chaining an app-layer bug into cloud IAM privilege escalation. Unlike the resources above, these are actual running, exploitable, internet-reachable apps, not synthetic misconfigurations. Off by default; enable with `create_awsgoat_module1` / `create_awsgoat_module2`. **Read `../awsgoat/README.md` before enabling** — dedicated sandbox account only, never alongside production workloads.

```bash
terraform apply -var="suffix=yourname" -var="create_awsgoat_module1=true" -var="create_awsgoat_module2=true"
terraform output awsgoat_urls
```

## Prerequisites

- AWS CLI configured with credentials that have permissions to create the resources above
- Terraform >= 1.6

## Usage

```bash
cd infra/terraform/test-fixtures

# Initialize
terraform init

# Preview
terraform plan -var="suffix=yourname"

# Deploy
terraform apply -var="suffix=yourname"

# View expected findings
terraform output expected_findings

# Destroy after testing
terraform destroy -var="suffix=yourname"
```

## After deploying

1. Add the AWS account as a provider in Ogum (`POST /api/v1/providers`)
2. Trigger discovery (`POST /api/v1/providers/{id}/discover`)
3. Trigger CSPM scan (`POST /api/v1/scans`)
4. Verify the findings listed in `terraform output expected_findings` appear in the findings UI

## Cost estimate

All resources are minimal (`t3.micro`, no NAT Gateway, no RDS). Estimated cost: **< $0.05/hour** while running. Always run `terraform destroy` after testing.

## Security note

These resources are intentionally misconfigured. **Never deploy in a production account.** Use a dedicated test/sandbox AWS account.

The optional Metasploitable/DVWA instances are **actually exploitable**, not just CSPM-flagged — keep `vulnerable_apps_allowed_cidrs` empty (SSM-only access) unless you explicitly need direct network access, and never set it to `0.0.0.0/0`.

The optional AWSGoat modules go further — real applications meant to be internet-reachable by design. See `../awsgoat/README.md` before enabling either one.
