# ── Known-Vulnerable Test Applications (Side-Scanning validation) ────────────
# Real, known-vulnerable targets used to validate Ogum.Dynamic
# (Trivy/YARA/Gitleaks side-scanning) against actual CVEs and exposed secrets,
# as opposed to the synthetic misconfigurations in main.tf.
#
# SECURITY: both instances are OFF by default (create_metasploitable_ec2 /
# create_dvwa_ec2 = false). When enabled they live in the private subnet with
# no ingress from 0.0.0.0/0 — access is only via SSM Session Manager or the
# CIDRs explicitly listed in var.vulnerable_apps_allowed_cidrs. Never expose
# these to the public internet; they are intentionally exploitable.

resource "aws_security_group" "vulnerable_apps" {
  count       = (var.create_metasploitable_ec2 || var.create_dvwa_ec2) ? 1 : 0
  name        = "${local.prefix}-vulnerable-apps"
  description = "Test SG: known-vulnerable apps, ingress restricted to explicit CIDRs only"
  vpc_id      = aws_vpc.main.id

  dynamic "ingress" {
    for_each = var.vulnerable_apps_allowed_cidrs
    content {
      description = "Restricted access to vulnerable test app"
      from_port   = 0
      to_port     = 65535
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.prefix}-vulnerable-apps", TestScenario = "known-vulnerable-app" }
}

resource "aws_iam_role" "vulnerable_apps_ssm" {
  count = (var.create_metasploitable_ec2 || var.create_dvwa_ec2) ? 1 : 0
  name  = "${local.prefix}-vulnerable-apps-ssm-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { TestScenario = "known-vulnerable-app-access" }
}

resource "aws_iam_role_policy_attachment" "vulnerable_apps_ssm" {
  count      = (var.create_metasploitable_ec2 || var.create_dvwa_ec2) ? 1 : 0
  role       = aws_iam_role.vulnerable_apps_ssm[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "vulnerable_apps_ssm" {
  count = (var.create_metasploitable_ec2 || var.create_dvwa_ec2) ? 1 : 0
  name  = "${local.prefix}-vulnerable-apps-ssm-profile"
  role  = aws_iam_role.vulnerable_apps_ssm[0].name
}

# ── Metasploitable ────────────────────────────────────────────────────────────
# Rapid7 does not publish a redistributable AWS AMI for Metasploitable — its
# license restricts distribution to isolated local VM use. Build one yourself
# with the official Packer templates (Metasploitable3:
# https://github.com/rapid7/metasploitable3) or your own Metasploitable2
# image, tag it so this data source can find it, and either leave
# metasploitable_ami_id empty (lookup by name) or set it directly.
data "aws_ami" "metasploitable" {
  count       = var.create_metasploitable_ec2 && var.metasploitable_ami_id == "" ? 1 : 0
  most_recent = true
  owners      = ["self"]

  filter {
    name   = "name"
    values = [var.metasploitable_ami_name]
  }
}

resource "aws_instance" "metasploitable" {
  count                  = var.create_metasploitable_ec2 ? 1 : 0
  ami                    = var.metasploitable_ami_id != "" ? var.metasploitable_ami_id : data.aws_ami.metasploitable[0].id
  instance_type          = "t3.small"
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.vulnerable_apps[0].id]
  iam_instance_profile   = aws_iam_instance_profile.vulnerable_apps_ssm[0].name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = {
    Name         = "${local.prefix}-metasploitable"
    TestScenario = "known-vulnerable-app-metasploitable"
  }
}

# ── DVWA (Damn Vulnerable Web App) ───────────────────────────────────────────
# Runs the official `vulnerables/web-dvwa` Docker image via user_data — no
# custom AMI needed.
resource "aws_instance" "dvwa" {
  count                  = var.create_dvwa_ec2 ? 1 : 0
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.vulnerable_apps[0].id]
  iam_instance_profile   = aws_iam_instance_profile.vulnerable_apps_ssm[0].name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  user_data = <<-EOF
    #!/bin/bash
    dnf install -y docker
    systemctl enable --now docker
    docker run -d --name dvwa --restart unless-stopped -p 80:80 vulnerables/web-dvwa
  EOF

  tags = {
    Name         = "${local.prefix}-dvwa"
    TestScenario = "known-vulnerable-app-dvwa"
  }
}
