output "vpc_id" {
  description = "VPC ID — use this as inventory discovery scope"
  value       = aws_vpc.main.id
}

output "account_id" {
  description = "AWS account ID where test resources were deployed"
  value       = data.aws_caller_identity.current.account_id
}

output "region" {
  description = "AWS region of test resources"
  value       = var.aws_region
}

output "test_resources" {
  description = "Summary of test resources and their expected CSPM behavior"
  value = {
    ec2 = {
      exposed  = aws_instance.public_exposed.id
      clean    = aws_instance.private_clean.id
    }
    s3 = {
      public_bucket    = aws_s3_bucket.public_data.bucket
      compliant_bucket = aws_s3_bucket.private_compliant.bucket
    }
    iam = {
      overprivileged_role  = aws_iam_role.overprivileged.name
      least_privilege_role = aws_iam_role.least_privilege.name
      test_user            = aws_iam_user.test_user_with_key.name
    }
    security_groups = {
      open_ssh   = aws_security_group.open_ssh.id
      restricted = aws_security_group.restricted.id
    }
  }
}

output "expected_findings" {
  description = "CSPM findings expected to be detected by Ogum.Static after scanning these resources"
  value = [
    "EC2 IMDSv2 not required on ${aws_instance.public_exposed.id}",
    "Security Group allows SSH from 0.0.0.0/0 — ${aws_security_group.open_ssh.id}",
    "Security Group allows RDP from 0.0.0.0/0 — ${aws_security_group.open_ssh.id}",
    "S3 bucket public access block not enabled — ${aws_s3_bucket.public_data.bucket}",
    "S3 bucket versioning not enabled — ${aws_s3_bucket.public_data.bucket}",
    "S3 bucket encryption not configured — ${aws_s3_bucket.public_data.bucket}",
    "IAM policy allows wildcard actions — ${aws_iam_role.overprivileged.name}",
    "IAM access key active for user — ${aws_iam_user.test_user_with_key.name}",
    "CloudTrail not multi-region — ${aws_cloudtrail.test_trail.name}",
    "Subnet assigns public IPs by default — ${aws_subnet.public.id}",
  ]
}

data "aws_caller_identity" "current" {}
