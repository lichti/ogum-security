terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

# ── Cost estimate (us-east-1, on-demand, no free tier) ───────────────────────
# EC2:              2x t3.micro   ~$0.021/h  ~$15/month  (disable with create_ec2_instances=false)
# EBS:              2x 8GB gp3    ~$0.80/month per volume
# Lambda:           free tier (1M requests/month)
# ECR:              free up to 500MB/month
# S3:               free up to 5GB/month
# KMS:              $1/month per CMK
# CloudTrail:       free for management events
# DynamoDB:         ~$0 on-demand (PAY_PER_REQUEST, no traffic)
# Secrets Manager:  $0.40/month per secret (1 secret)
# SSM Parameter:    free (Standard tier)
# Total:            ~$21/month with EC2  |  ~$6/month without (create_ec2_instances=false)
# Vulnerable apps:   off by default. Metasploitable (t3.small) ~$0.02/h, DVWA (t3.micro) ~$0.01/h — opt-in via
#                    create_metasploitable_ec2 / create_dvwa_ec2.
# AWSGoat:           off by default, opt-in via create_awsgoat_module1 / create_awsgoat_module2.
#   module-1: EC2 t2.micro (always on) + DynamoDB provisioned (2 tables) ~$0.015/h  ~$11/month
#   module-2: EC2 t2.micro (ASG) + RDS db.t3.micro + ALB (biggest cost) ~$0.052/h  ~$38/month
#   Full per-resource breakdown and Free Tier caveats: ../awsgoat/README.md#cost-estimate-us-east-1-on-demand-no-free-tier
# ─────────────────────────────────────────────────────────────────────────────

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "ogum-security-test"
      Environment = "test"
      ManagedBy   = "terraform"
    }
  }
}

locals {
  prefix = "ogum-test-${var.suffix}"
}

# ── VPC ───────────────────────────────────────────────────────────────────────
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = { Name = "${local.prefix}-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.prefix}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true # CSPM finding: subnet assigns public IPs by default

  tags = { Name = "${local.prefix}-public-subnet" }
}

resource "aws_subnet" "private" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.2.0/24"

  tags = { Name = "${local.prefix}-private-subnet" }
}

# ── Security Groups ───────────────────────────────────────────────────────────

# Intentionally overly permissive — triggers CSPM findings
resource "aws_security_group" "open_ssh" {
  name        = "${local.prefix}-open-ssh"
  description = "Test SG: SSH open to the world (triggers CSPM)"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # CSPM: CIS 5.2 — SSH must not be open to the world
  }

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # CSPM: CIS 5.4 — RDP must not be open to the world
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.prefix}-open-ssh", TestScenario = "overpermissive-sg" }
}

resource "aws_security_group" "restricted" {
  name        = "${local.prefix}-restricted"
  description = "Test SG: correctly restricted (should produce no CSPM findings)"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS only from corporate CIDR"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.prefix}-restricted", TestScenario = "compliant-sg" }
}

# ── EC2 Instances ─────────────────────────────────────────────────────────────
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

# Public-facing instance with open SG — should appear in Attack Paths
resource "aws_instance" "public_exposed" {
  count                  = var.create_ec2_instances ? 1 : 0
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.open_ssh.id]
  iam_instance_profile   = aws_iam_instance_profile.overprivileged.name

  # No IMDSv2 enforcement — triggers CSPM finding
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional" # CSPM: IMDSv2 not required
    http_put_response_hop_limit = 2
  }

  tags = {
    Name         = "${local.prefix}-public-exposed"
    TestScenario = "internet-exposed-overprivileged"
  }
}

# Private instance with restricted SG — clean baseline
resource "aws_instance" "private_clean" {
  count                  = var.create_ec2_instances ? 1 : 0
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.restricted.id]

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 enforced — compliant
    http_put_response_hop_limit = 1
  }

  tags = {
    Name         = "${local.prefix}-private-clean"
    TestScenario = "compliant-baseline"
  }
}

# ── S3 Buckets ────────────────────────────────────────────────────────────────

# Public bucket — multiple CSPM findings
resource "aws_s3_bucket" "public_data" {
  bucket        = "${local.prefix}-public-data-${random_id.bucket_suffix.hex}"
  force_destroy = true

  tags = { Name = "${local.prefix}-public-data", TestScenario = "public-s3-bucket" }
}

resource "aws_s3_bucket_public_access_block" "public_data" {
  bucket = aws_s3_bucket.public_data.id

  block_public_acls       = false # CSPM: S3 public access block not enabled
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# No versioning — triggers CSPM finding
# resource "aws_s3_bucket_versioning" intentionally omitted

# No server-side encryption — triggers CSPM finding
# resource "aws_s3_bucket_server_side_encryption_configuration" intentionally omitted

# Private compliant bucket
resource "aws_s3_bucket" "private_compliant" {
  bucket        = "${local.prefix}-private-compliant-${random_id.bucket_suffix.hex}"
  force_destroy = true

  tags = { Name = "${local.prefix}-private-compliant", TestScenario = "compliant-s3" }
}

resource "aws_s3_bucket_public_access_block" "private_compliant" {
  bucket = aws_s3_bucket.private_compliant.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "private_compliant" {
  bucket = aws_s3_bucket.private_compliant.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "private_compliant" {
  bucket = aws_s3_bucket.private_compliant.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# ── IAM ───────────────────────────────────────────────────────────────────────

# Overprivileged role — attached to public EC2 — triggers CSPM + Attack Path
resource "aws_iam_role" "overprivileged" {
  name = "${local.prefix}-overprivileged-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { TestScenario = "overprivileged-iam" }
}

# Wildcard admin policy — triggers CSPM: IAM policy allows * actions
resource "aws_iam_role_policy" "overprivileged_inline" {
  name = "wildcard-admin"
  role = aws_iam_role.overprivileged.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*" # CSPM: IAM policy with wildcard actions
      Resource = "*"
    }]
  })
}

resource "aws_iam_instance_profile" "overprivileged" {
  name = "${local.prefix}-overprivileged-profile"
  role = aws_iam_role.overprivileged.name
}

# Least-privilege role — clean baseline
resource "aws_iam_role" "least_privilege" {
  name = "${local.prefix}-least-privilege-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { TestScenario = "compliant-iam" }
}

resource "aws_iam_role_policy_attachment" "least_privilege" {
  role       = aws_iam_role.least_privilege.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# IAM user with access keys — triggers CSPM: root/user access keys active
resource "aws_iam_user" "test_user_with_key" {
  name = "${local.prefix}-test-user"
  tags = { TestScenario = "iam-user-with-key" }
}

resource "aws_iam_access_key" "test_user_key" {
  user = aws_iam_user.test_user_with_key.name
  # CSPM: IAM access key active — should rotate or use roles instead
}

# ── KMS ───────────────────────────────────────────────────────────────────────
resource "aws_kms_key" "test_key" {
  description             = "Ogum test KMS key"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = { Name = "${local.prefix}-kms-key" }
}

# ── CloudTrail (required for CSPM checks) ────────────────────────────────────
resource "aws_cloudtrail" "test_trail" {
  name                          = "${local.prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.private_compliant.id
  include_global_service_events = true
  is_multi_region_trail         = false # CSPM: CloudTrail not multi-region
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.cloudtrail_policy]

  tags = { Name = "${local.prefix}-trail" }
}

resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.private_compliant.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.private_compliant.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.private_compliant.arn}/AWSLogs/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}
