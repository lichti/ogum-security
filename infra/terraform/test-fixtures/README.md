# Test Fixtures — Terraform

AWS resources intentionally configured with known misconfigurations to validate Ogum.Static (CSPM) and Ogum.Inventory discovery.

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
