# Dedup table (REVIEW.md B6): records processed finding IDs so re-emitted findings
# don't create duplicate Confluence pages / Slack messages. TTL auto-expires old
# entries; on-demand billing keeps it cheap at low volume.
resource "aws_dynamodb_table" "dedup" {
  name         = "${local.name}-processed-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = local.tags
}
