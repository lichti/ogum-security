# US-13.01 — equivalente Terraform do template CloudFormation aws-scan-role.cfn.yml.
# Validado no CI com `terraform init -backend=false && terraform validate`
# (.github/workflows/ci.yml, job iac-validation).

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
  # Sem backend: o tenant aplica localmente; state fica com o cliente.
}

variable "ogum_account_id" {
  type        = string
  description = "Account ID da Ogum (trusted entity do AssumeRole)"
  validation {
    condition     = can(regex("^[0-9]{12}$", var.ogum_account_id))
    error_message = "ogum_account_id deve ter 12 dígitos."
  }
}

variable "external_id" {
  type        = string
  description = "External ID único por tenant (anti confused-deputy)"
  sensitive   = true
  validation {
    condition     = length(var.external_id) >= 8
    error_message = "external_id deve ter ao menos 8 caracteres."
  }
}

variable "role_name" {
  type    = string
  default = "ogum-scanner-role"
}

data "aws_iam_policy" "security_audit" {
  arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

data "aws_iam_policy" "view_only_access" {
  arn = "arn:aws:iam::aws:policy/view-only-access"
}

# Nota: este módulo é aplicado NA CONTA DO CLIENTE apontando trusted para a
# conta da Ogum — ao aplicar, configure o provider para a conta do cliente.
resource "aws_iam_role" "ogum_scanner" {
  name                 = var.role_name
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.ogum_account_id}:root" }
        Action    = "sts:AssumeRole"
        Condition = {
          StringEquals = { "sts:ExternalId" = var.external_id }
        }
      }
    ]
  })

  managed_policy_arns = [
    data.aws_iam_policy.security_audit.arn,
    data.aws_iam_policy.view_only_access.arn,
  ]
}

output "role_arn" {
  description = "ARN da role a ser registrada no Ogum (role_arn)"
  value       = aws_iam_role.ogum_scanner.arn
}
