resource "aws_ecr_repository" "app" {
  name                 = "${local.prefix}/app"
  image_tag_mutability = "MUTABLE"

  # No scan on push — Ogum handles scanning
  image_scanning_configuration {
    scan_on_push = false
  }

  # No encryption — triggers CSPM finding
  tags = {
    Name         = "${local.prefix}-ecr-app"
    TestScenario = "ecr-repository"
  }
}

resource "aws_ecr_repository" "compliant_app" {
  name                 = "${local.prefix}/compliant-app"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = false # Ogum handles scanning
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.test_key.arn
  }

  tags = {
    Name         = "${local.prefix}-ecr-compliant"
    TestScenario = "compliant-ecr"
  }
}

# Expire old images automatically — avoids storage cost accumulation
resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep only last 5 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 5
      }
      action = { type = "expire" }
    }]
  })
}
