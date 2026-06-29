output "lambda_function_name" {
  description = "Name of the triage Lambda."
  value       = aws_lambda_function.processor.function_name
}

output "lambda_function_arn" {
  value = aws_lambda_function.processor.arn
}

output "dlq_url" {
  description = "Dead-letter queue URL — inspect here for findings that failed processing."
  value       = aws_sqs_queue.dlq.url
}

output "dlq_arn" {
  value = aws_sqs_queue.dlq.arn
}

output "integration_secret_name" {
  description = "Secrets Manager secret to load real integration credentials into."
  value       = aws_secretsmanager_secret.integrations.name
}

output "vpc_id" {
  value = aws_vpc.this.id
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.lambda.name
}
