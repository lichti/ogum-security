variable "aws_region" {
  description = "AWS region to deploy test resources"
  type        = string
  default     = "us-east-1"
}

variable "suffix" {
  description = "Short unique suffix to avoid naming collisions between test runs (e.g. 'dev', 'ci', your username)"
  type        = string
  default     = "dev"

  validation {
    condition     = can(regex("^[a-z0-9-]{1,10}$", var.suffix))
    error_message = "suffix must be lowercase alphanumeric with hyphens, max 10 chars."
  }
}

variable "create_ec2_instances" {
  description = "Set to false to skip EC2 instance creation and save ~$15/month. Side-scanning tests will use Lambda and ECR instead."
  type        = bool
  default     = true
}

variable "create_metasploitable_ec2" {
  description = "Deploy a Metasploitable EC2 instance (real known-vulnerable target) for side-scanning validation. Off by default — requires a self-owned AMI, see metasploitable_ami_id/metasploitable_ami_name. Never expose to the public internet."
  type        = bool
  default     = false
}

variable "create_dvwa_ec2" {
  description = "Deploy an EC2 instance running DVWA (Damn Vulnerable Web App) via Docker for side-scanning validation. Off by default. Never expose to the public internet."
  type        = bool
  default     = false
}

variable "vulnerable_apps_allowed_cidrs" {
  description = "CIDR blocks allowed to reach the Metasploitable/DVWA security group. Empty by default (no ingress — access only via SSM Session Manager). Never set to 0.0.0.0/0."
  type        = list(string)
  default     = []

  validation {
    condition     = !contains(var.vulnerable_apps_allowed_cidrs, "0.0.0.0/0")
    error_message = "vulnerable_apps_allowed_cidrs must not include 0.0.0.0/0 — these instances run real, exploitable vulnerabilities."
  }
}

variable "metasploitable_ami_id" {
  description = "AMI ID of a self-built Metasploitable image. Takes precedence over metasploitable_ami_name lookup. Leave empty to look up by name instead."
  type        = string
  default     = ""
}

variable "metasploitable_ami_name" {
  description = "Name filter used to look up a self-owned Metasploitable AMI when metasploitable_ami_id is not set. Build the AMI yourself (e.g. via https://github.com/rapid7/metasploitable3) and tag it with this name."
  type        = string
  default     = "metasploitable3*"
}
