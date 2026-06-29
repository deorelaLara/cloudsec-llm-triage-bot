# Placeholder secret. Real integration values are loaded out-of-band after apply
# (README "Cómo configurar Secrets Manager"); we ignore drift so terraform never
# overwrites them.

resource "aws_secretsmanager_secret" "integrations" {
  name        = "${local.name}/integrations"
  description = "Integration credentials for ${local.name}. Load real values after apply."
  tags        = local.tags
}

resource "aws_secretsmanager_secret_version" "integrations" {
  secret_id = aws_secretsmanager_secret.integrations.id

  secret_string = jsonencode({
    openai_api_key       = ""
    slack_webhook_url    = ""
    confluence_base_url  = ""
    confluence_email     = ""
    confluence_api_token = ""
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}
