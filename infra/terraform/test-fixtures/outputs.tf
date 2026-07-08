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
      exposed = try(aws_instance.public_exposed[0].id, null)
      clean   = try(aws_instance.private_clean[0].id, null)
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
    lambda = {
      clean_function = aws_lambda_function.hello_clean.function_name
    }
    ecr = {
      app_repository       = aws_ecr_repository.app.repository_url
      compliant_repository = aws_ecr_repository.compliant_app.repository_url
    }
    ogum_scanner = {
      role_arn         = aws_iam_role.ogum_scanner.arn
      external_id      = "ogum-dev-${var.suffix}"
      instance_profile = aws_iam_instance_profile.ogum_scanner.name
    }
    privesc_chain = {
      dev_user        = aws_iam_user.dev_user.name
      devops_role     = aws_iam_role.devops_role.name
      admin_target    = aws_iam_role.privesc_admin_target.name
      privesc_03_role = aws_iam_role.privesc_create_policy_version.name
      privesc_05_role = aws_iam_role.privesc_attach_role_policy.name
      privesc_10_role = aws_iam_role.privesc_passrole_ec2.name
    }
  }
}

output "expected_findings" {
  description = "CSPM and side-scanning findings expected after scanning these resources"
  value = concat(
    var.create_ec2_instances ? [
      "EC2 IMDSv2 not required on ${aws_instance.public_exposed[0].id}",
    ] : [],
    [
      "Security Group allows SSH from 0.0.0.0/0 — ${aws_security_group.open_ssh.id}",
      "Security Group allows RDP from 0.0.0.0/0 — ${aws_security_group.open_ssh.id}",
      "S3 bucket public access block not enabled — ${aws_s3_bucket.public_data.bucket}",
      "S3 bucket versioning not enabled — ${aws_s3_bucket.public_data.bucket}",
      "S3 bucket encryption not configured — ${aws_s3_bucket.public_data.bucket}",
      "IAM policy allows wildcard actions — ${aws_iam_role.overprivileged.name}",
      "IAM access key active for user — ${aws_iam_user.test_user_with_key.name}",
      "CloudTrail not multi-region — ${aws_cloudtrail.test_trail.name}",
      "Subnet assigns public IPs by default — ${aws_subnet.public.id}",
      # Lambda
      # ECR
      "ECR repository encryption not configured — ${aws_ecr_repository.app.name}",
      # IAM PRIVESC (Epic 02 detectors)
      "PRIVESC-01: ${aws_iam_user.dev_user.name} → ${aws_iam_role.devops_role.name} → ${aws_iam_role.privesc_admin_target.name} (2-hop chain to AdministratorAccess)",
      "PRIVESC-03: iam:CreatePolicyVersion on ${aws_iam_role.privesc_create_policy_version.name}",
      "PRIVESC-05: iam:AttachRolePolicy on ${aws_iam_role.privesc_attach_role_policy.name}",
      "PRIVESC-10: iam:PassRole + ec2:RunInstances on ${aws_iam_role.privesc_passrole_ec2.name}",
    ]
  )
}

output "ogum_scanner_config" {
  description = "Values to configure in the Ogum provider connection for this test account"
  value = {
    role_arn    = aws_iam_role.ogum_scanner.arn
    external_id = "ogum-dev-${var.suffix}"
    region      = var.aws_region
    account_id  = data.aws_caller_identity.current.account_id
  }
}

data "aws_caller_identity" "current" {}
