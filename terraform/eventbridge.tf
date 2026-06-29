# EventBridge rules that route real GuardDuty and Inspector findings to the Lambda.
# Each target also retries and dead-letters delivery failures.

resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "${local.name}-guardduty"
  description = "Route GuardDuty findings to the triage Lambda."

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })

  tags = local.tags
}

resource "aws_cloudwatch_event_rule" "inspector" {
  name        = "${local.name}-inspector"
  description = "Route Inspector2 findings to the triage Lambda."

  event_pattern = jsonencode({
    source        = ["aws.inspector2"]
    "detail-type" = ["Inspector2 Finding"]
  })

  tags = local.tags
}

resource "aws_cloudwatch_event_target" "guardduty" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "triage-lambda"
  arn       = aws_lambda_function.processor.arn

  retry_policy {
    maximum_retry_attempts       = var.event_max_retry_attempts
    maximum_event_age_in_seconds = var.event_max_age_seconds
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

resource "aws_cloudwatch_event_target" "inspector" {
  rule      = aws_cloudwatch_event_rule.inspector.name
  target_id = "triage-lambda"
  arn       = aws_lambda_function.processor.arn

  retry_policy {
    maximum_retry_attempts       = var.event_max_retry_attempts
    maximum_event_age_in_seconds = var.event_max_age_seconds
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

resource "aws_lambda_permission" "guardduty" {
  statement_id  = "AllowGuardDutyRule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty.arn
}

resource "aws_lambda_permission" "inspector" {
  statement_id  = "AllowInspectorRule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.inspector.arn
}
