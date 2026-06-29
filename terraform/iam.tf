data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${local.name}-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

# Managed policy that grants the ENI permissions a VPC-attached Lambda needs.
resource "aws_iam_role_policy_attachment" "vpc_access" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Least-privilege inline policy: write logs, read the one secret, send to the DLQ,
# and (only when using Bedrock) invoke the model.
data "aws_iam_policy_document" "lambda_inline" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  statement {
    sid       = "ReadIntegrationSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.integrations.arn]
  }

  statement {
    sid       = "SendToDLQ"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }

  dynamic "statement" {
    for_each = var.llm_provider == "bedrock" ? [1] : []
    content {
      sid     = "InvokeBedrock"
      actions = ["bedrock:InvokeModel"]
      # Cross-region inference profiles resolve to multiple region ARNs; tighten
      # to specific model/profile ARNs if your org's guardrails require it.
      resources = ["*"]
    }
  }
}

resource "aws_iam_role_policy" "lambda_inline" {
  name   = "${local.name}-lambda-policy"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_inline.json
}
