data "archive_file" "lambda_hello" {
  type        = "zip"
  output_path = "${path.module}/lambda_hello.zip"

  source {
    content  = <<-PYTHON
      import json

      def handler(event, context):
          return {"statusCode": 200, "body": json.dumps({"message": "hello from ogum test lambda"})}
    PYTHON
    filename = "handler.py"
  }
}

resource "aws_iam_role" "lambda_exec" {
  name = "${local.prefix}-lambda-exec"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { TestScenario = "lambda-exec-role" }
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Clean Lambda — compliant baseline
resource "aws_lambda_function" "hello_clean" {
  function_name    = "${local.prefix}-hello-clean"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_hello.output_path
  source_code_hash = data.archive_file.lambda_hello.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = { ENV = "test" }
  }

  tags = {
    Name         = "${local.prefix}-hello-clean"
    TestScenario = "compliant-lambda"
  }
}

# Note: a Lambda function with hardcoded test credentials (for Trivy secret scanner testing)
# is intentionally not managed by Terraform to avoid triggering GitHub secret push protection.
# To test secret detection manually: create a Lambda ZIP containing a file with test patterns
# (e.g., generic password strings) and upload it via AWS Console or CLI.
