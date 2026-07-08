# ── PRIVESC-01/02: Developer → DevOpsRole → AdminRole ────────────────────────
# dev_user can assume devops_role; devops_role can assume privesc_admin_target.
# Expected: PRIVESC-01 (2-hop assume chain reaching AdministratorAccess).

resource "aws_iam_user" "dev_user" {
  name = "${local.prefix}-dev-user"
  tags = {
    TestScenario = "privesc-01-source"
    PrivescChain = "developer-to-admin"
  }
}

resource "aws_iam_role" "devops_role" {
  name        = "${local.prefix}-devops-role"
  description = "Mid-tier role: assumable by dev_user, can assume admin role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_user.dev_user.arn }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    TestScenario = "privesc-01-hop"
    PrivescChain = "developer-to-admin"
  }
}

resource "aws_iam_role_policy" "devops_can_assume_admin" {
  name = "can-assume-admin"
  role = aws_iam_role.devops_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.privesc_admin_target.arn
    }]
  })
}

resource "aws_iam_role" "privesc_admin_target" {
  name        = "${local.prefix}-privesc-admin"
  description = "Admin role reachable via assume-role chain (PRIVESC-01/02 target)"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.devops_role.arn }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    TestScenario = "privesc-01-target"
    PrivescChain = "developer-to-admin"
  }
}

resource "aws_iam_role_policy_attachment" "privesc_admin_policy" {
  role       = aws_iam_role.privesc_admin_target.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ── PRIVESC-03: iam:CreatePolicyVersion ──────────────────────────────────────

resource "aws_iam_role" "privesc_create_policy_version" {
  name        = "${local.prefix}-privesc-cpv"
  description = "Role with iam:CreatePolicyVersion (PRIVESC-03 detector target)"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { TestScenario = "privesc-03-create-policy-version" }
}

resource "aws_iam_role_policy" "privesc_create_policy_version_inline" {
  name = "dangerous-create-policy-version"
  role = aws_iam_role.privesc_create_policy_version.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:CreatePolicyVersion"] # PRIVESC-03
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "*"
      }
    ]
  })
}

# ── PRIVESC-05: iam:AttachRolePolicy ─────────────────────────────────────────

resource "aws_iam_role" "privesc_attach_role_policy" {
  name        = "${local.prefix}-privesc-arp"
  description = "Role with iam:AttachRolePolicy (PRIVESC-05 detector target)"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { TestScenario = "privesc-05-attach-role-policy" }
}

resource "aws_iam_role_policy" "privesc_attach_role_policy_inline" {
  name = "dangerous-attach-role-policy"
  role = aws_iam_role.privesc_attach_role_policy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:AttachRolePolicy"] # PRIVESC-05
      Resource = "*"
    }]
  })
}

# ── PRIVESC-10: iam:PassRole + ec2:RunInstances ───────────────────────────────

resource "aws_iam_role" "privesc_passrole_ec2" {
  name        = "${local.prefix}-privesc-passrole"
  description = "Role with iam:PassRole + ec2:RunInstances (PRIVESC-10 detector target)"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { TestScenario = "privesc-10-passrole-ec2" }
}

resource "aws_iam_role_policy" "privesc_passrole_ec2_inline" {
  name = "dangerous-passrole-ec2"
  role = aws_iam_role.privesc_passrole_ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "iam:PassRole",         # PRIVESC-10: can pass any role to a new EC2
        "ec2:RunInstances",     # PRIVESC-10: combined with PassRole → launch EC2 with admin role
        "ec2:DescribeInstances",
      ]
      Resource = "*"
    }]
  })
}
