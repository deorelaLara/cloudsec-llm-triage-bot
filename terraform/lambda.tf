resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.name}-processor"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

# Dead-letter queue. Findings that exhaust retries land here for inspection instead
# of being silently dropped — the failure mode the handler change in REVIEW.md B1
# is designed to surface.
resource "aws_sqs_queue" "dlq" {
  name                      = "${local.name}-dlq"
  message_retention_seconds = var.dlq_retention_seconds
  tags                      = local.tags
}

# Allow EventBridge to dead-letter failed deliveries into the DLQ.
data "aws_iam_policy_document" "dlq_policy" {
  statement {
    sid       = "AllowEventBridgeToDLQ"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values = [
        aws_cloudwatch_event_rule.guardduty.arn,
        aws_cloudwatch_event_rule.inspector.arn,
      ]
    }
  }
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy    = data.aws_iam_policy_document.dlq_policy.json
}

resource "aws_lambda_function" "processor" {
  function_name    = "${local.name}-processor"
  role             = aws_iam_role.lambda.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  filename         = var.lambda_package_path
  source_code_hash = filebase64sha256(var.lambda_package_path)
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_mb

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      ENVIRONMENT               = var.environment
      PROJECT_NAME              = var.project_name
      LLM_PROVIDER              = var.llm_provider
      SECRET_NAME               = aws_secretsmanager_secret.integrations.name
      CONFLUENCE_SPACE_KEY      = var.confluence_space_key
      CONFLUENCE_PARENT_PAGE_ID = var.confluence_parent_page_id
      LOG_LEVEL                 = var.log_level
      OPENAI_MODEL              = var.openai_model
      OPENAI_BASE_URL           = var.openai_base_url
      BEDROCK_MODEL_ID          = var.bedrock_model_id
      SUPPRESSION_ALLOWLIST     = var.suppression_allowlist

      LLM_SELF_CONSISTENCY_SAMPLES = tostring(var.llm_self_consistency_samples)
      DEDUP_TABLE_NAME             = aws_dynamodb_table.dedup.name
      DEDUP_TTL_SECONDS            = tostring(var.dedup_ttl_seconds)
    }
  }

  tags       = local.tags
  depends_on = [aws_cloudwatch_log_group.lambda, aws_iam_role_policy.lambda_inline]
}

# Function-level async retry + DLQ. EventBridge invokes the Lambda asynchronously,
# so when the handler raises (a transient/un-processable finding) Lambda retries and
# then routes the event here on exhaustion.
resource "aws_lambda_function_event_invoke_config" "processor" {
  function_name                = aws_lambda_function.processor.function_name
  maximum_retry_attempts       = var.event_max_retry_attempts
  maximum_event_age_in_seconds = var.event_max_age_seconds

  destination_config {
    on_failure {
      destination = aws_sqs_queue.dlq.arn
    }
  }
}
