variable "aws_region" {
  type        = string
  description = "AWS region to deploy into."
  default     = "ap-southeast-2"
}

variable "project_name" {
  type    = string
  default = "cloudsec-llm-triage-bot"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
}

variable "availability_zones" {
  type        = list(string)
  description = "Three AZs, one per public/private subnet pair."
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.40.0.0/24", "10.40.1.0/24", "10.40.2.0/24"]
}

variable "private_subnet_cidrs" {
  type    = list(string)
  default = ["10.40.10.0/24", "10.40.11.0/24", "10.40.12.0/24"]
}

variable "llm_provider" {
  type    = string
  default = "bedrock"

  validation {
    condition     = contains(["bedrock", "openai"], var.llm_provider)
    error_message = "llm_provider must be 'bedrock' or 'openai'."
  }
}

variable "bedrock_model_id" {
  type        = string
  description = "Bedrock inference profile ID/ARN (NOT the base model id)."
  default     = "au.anthropic.claude-sonnet-4-6"
}

variable "openai_model" {
  type    = string
  default = "gpt-4.1-mini"
}

variable "openai_base_url" {
  type    = string
  default = "https://api.openai.com/v1"
}

variable "confluence_space_key" {
  type    = string
  default = "SECOPS"
}

variable "confluence_parent_page_id" {
  type    = string
  default = ""
}

variable "suppression_allowlist" {
  type    = string
  default = "Recon:EC2/PortProbeUnprotectedPort,Software and Configuration Checks/Package Vulnerability"
}

variable "log_level" {
  type    = string
  default = "INFO"
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "lambda_package_path" {
  type        = string
  description = "Path to the manually-built Lambda deployment ZIP (see README)."
}

variable "lambda_timeout" {
  type    = number
  default = 60
}

variable "lambda_memory_mb" {
  type    = number
  default = 512
}

variable "dlq_retention_seconds" {
  type        = number
  description = "DLQ message retention. Default 14 days (the SQS maximum)."
  default     = 1209600
}

variable "event_max_retry_attempts" {
  type    = number
  default = 2
}

variable "event_max_age_seconds" {
  type    = number
  default = 3600
}

variable "dedup_ttl_seconds" {
  type        = number
  description = "How long a processed finding is remembered for dedup. Default 1 day."
  default     = 86400
}

variable "llm_self_consistency_samples" {
  type        = number
  description = "LLM samples per finding for self-consistency confidence (1 = off)."
  default     = 1
}
