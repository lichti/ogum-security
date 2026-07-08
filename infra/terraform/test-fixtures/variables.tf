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
