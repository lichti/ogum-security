# ── Data Assets — Crown Jewels and Toxic Combination targets ─────────────────
#
# Attack path narrative:
#   [Internet] --SSH (0.0.0.0/0)--> [public_exposed EC2]
#       --> [overprivileged_role (Action:*)]
#           --> [customer_data DynamoDB table  (Crown Jewel)]
#           --> [db_credentials SecretsManager (Crown Jewel)]
#           --> [api_config SSM Parameter      (Crown Jewel)]
#
# This is a classic Toxic Combination: internet-exposed compute with direct
# IAM path to sensitive data assets. Ogum.Graph should flag this as CRITICAL.
#
# Cost: DynamoDB on-demand ~$0 (no reads/writes in test), SSM free,
#       SecretsManager $0.40/month per secret.

# ── DynamoDB — customer_data (Crown Jewel) ────────────────────────────────────

resource "aws_dynamodb_table" "customer_data" {
  name         = "${local.prefix}-customer-data"
  billing_mode = "PAY_PER_REQUEST" # ~$0 when idle
  hash_key     = "customer_id"

  attribute {
    name = "customer_id"
    type = "S"
  }

  # No encryption at rest configured with CMK — triggers CSPM finding
  # (default AWS-owned key is used instead of customer-managed KMS key)

  # No point-in-time recovery — triggers CSPM finding
  point_in_time_recovery {
    enabled = false
  }

  tags = {
    Name           = "${local.prefix}-customer-data"
    Classification = "confidential"
    CrownJewel     = "true"
    DataType       = "pii"
    TestScenario   = "crown-jewel-dynamodb"
  }
}

# Seed one item so the table appears non-empty in the Ogum inventory
resource "aws_dynamodb_table_item" "sample_customer" {
  table_name = aws_dynamodb_table.customer_data.name
  hash_key   = aws_dynamodb_table.customer_data.hash_key

  item = jsonencode({
    customer_id = { S = "test-customer-001" }
    name        = { S = "Test Customer" }
    email       = { S = "test@example.com" }
    plan        = { S = "enterprise" }
  })
}

# Compliant DynamoDB table — encrypted + PITR enabled (clean baseline)
resource "aws_dynamodb_table" "audit_log" {
  name         = "${local.prefix}-audit-log"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "event_id"

  attribute {
    name = "event_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.test_key.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name         = "${local.prefix}-audit-log"
    CrownJewel   = "false"
    TestScenario = "compliant-dynamodb"
  }
}

# ── Secrets Manager — DB credentials (Crown Jewel) ───────────────────────────

resource "aws_secretsmanager_secret" "db_credentials" {
  name                    = "${local.prefix}/db/credentials"
  description             = "Production DB credentials (test fixture for Ogum Crown Jewel detection)"
  recovery_window_in_days = 0 # immediate deletion on terraform destroy

  # No KMS CMK — uses AWS-managed key (triggers CSPM finding)
  # kms_key_id intentionally omitted

  tags = {
    Name           = "${local.prefix}-db-credentials"
    Classification = "confidential"
    CrownJewel     = "true"
    TestScenario   = "crown-jewel-secret"
  }
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id

  secret_string = jsonencode({
    username = "ogum_test_user"
    password = "test-placeholder-not-real"
    host     = "db.example.internal"
    port     = 5432
    dbname   = "ogum_test"
  })
}

# ── SSM Parameter Store — API config (Crown Jewel) ───────────────────────────

resource "aws_ssm_parameter" "api_config" {
  name        = "/${local.prefix}/api/config"
  type        = "SecureString"
  value       = "{\"api_endpoint\": \"https://api.example.internal\", \"api_version\": \"v1\"}"
  description = "API configuration (test fixture for Ogum Crown Jewel detection)"
  key_id      = aws_kms_key.test_key.arn

  tags = {
    Name         = "${local.prefix}-api-config"
    CrownJewel   = "true"
    TestScenario = "crown-jewel-ssm"
  }
}

# ── IAM: grant Lambda execution role access to Crown Jewels ──────────────────
# Simulates a Lambda that can read sensitive data — if Lambda is exposed or
# its code has vulnerabilities, this becomes part of the attack path.

resource "aws_iam_role_policy" "lambda_crown_jewel_access" {
  name = "crown-jewel-read"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadCustomerData"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan",
        ]
        Resource = aws_dynamodb_table.customer_data.arn
      },
      {
        Sid    = "ReadDbCredentials"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
        ]
        Resource = aws_secretsmanager_secret.db_credentials.arn
      },
      {
        Sid    = "ReadApiConfig"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
        ]
        Resource = aws_ssm_parameter.api_config.arn
      }
    ]
  })
}
