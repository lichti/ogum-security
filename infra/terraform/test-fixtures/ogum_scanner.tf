# ── Ogum Scanner Role ─────────────────────────────────────────────────────────
# Assumed by the Ogum backend to scan the customer account.
# Trust policy: allows self-assumption from same account (dev) and EC2 instance profile.
# In production: replace the AllowSameAccount principal with the Ogum SaaS account ID.

resource "aws_iam_role" "ogum_scanner" {
  name        = "${local.prefix}-ogum-scanner"
  description = "Role assumed by Ogum Security to scan this account"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEC2"
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      },
      {
        Sid       = "AllowSameAccount"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "sts:AssumeRole"
        Condition = {
          StringEquals = { "sts:ExternalId" = "ogum-dev-${var.suffix}" }
        }
      }
    ]
  })

  tags = {
    Name    = "${local.prefix}-ogum-scanner"
    Purpose = "ogum-security-scanner"
  }
}

# Discovery & CSPM — read-only enumeration of all supported resource types
resource "aws_iam_role_policy" "ogum_discovery" {
  name = "ogum-discovery"
  role = aws_iam_role.ogum_scanner.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ReadOnlyInventory"
      Effect = "Allow"
      Action = [
        # EC2 / VPC
        "ec2:Describe*", "ec2:List*", "ec2:Get*",
        # S3
        "s3:ListAllMyBuckets", "s3:GetBucketAcl", "s3:GetBucketLocation",
        "s3:GetBucketLogging", "s3:GetBucketNotification", "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock", "s3:GetBucketTagging", "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration",
        # IAM — identity graph and attack path construction
        "iam:Get*", "iam:List*", "iam:GenerateServiceLastAccessedDetails",
        # Lambda
        "lambda:ListFunctions", "lambda:GetFunction",
        "lambda:ListTags", "lambda:GetFunctionConfiguration",
        # ECR
        "ecr:DescribeRepositories", "ecr:DescribeImages",
        "ecr:ListTagsForResource", "ecr:GetAuthorizationToken",
        # KMS
        "kms:ListKeys", "kms:DescribeKey", "kms:GetKeyRotationStatus",
        # CloudTrail
        "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
        # Config / CloudWatch
        "config:Describe*", "cloudwatch:DescribeAlarms",
        # RDS (future Epic)
        "rds:Describe*",
        # EKS (future Epic)
        "eks:Describe*", "eks:List*",
        # SSM / SNS / SQS
        "ssm:Describe*", "sns:List*",
        "sqs:List*", "sqs:GetQueueAttributes",
        # Account
        "account:GetAlternateContact",
      ]
      Resource = "*"
    }]
  })
}

# Side-scanning — EBS Direct API (Epic 03 Sprint 2) + Lambda artifact + ECR pull
resource "aws_iam_role_policy" "ogum_side_scanning" {
  name = "ogum-side-scanning"
  role = aws_iam_role.ogum_scanner.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EBSDirectAPI"
        Effect = "Allow"
        Action = [
          "ebs:ListSnapshotBlocks",
          "ebs:GetSnapshotBlock",
          "ebs:ListChangedBlocks",
        ]
        Resource = "*"
      },
      {
        Sid    = "EBSSnapshotLifecycle"
        Effect = "Allow"
        Action = [
          "ec2:CreateSnapshot",
          "ec2:DeleteSnapshot",
          "ec2:DescribeSnapshots",
          "ec2:CreateTags",
        ]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:RequestedRegion" = var.aws_region }
        }
      },
      {
        Sid      = "LambdaArtifact"
        Effect   = "Allow"
        Action   = ["lambda:GetFunction"]
        Resource = "*"
      },
      {
        Sid    = "ECRPull"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ogum_scanner" {
  name = "${local.prefix}-ogum-scanner-profile"
  role = aws_iam_role.ogum_scanner.name
}
