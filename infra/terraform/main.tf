terraform {
  required_version = ">= 1.5.0"
  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "~> 2.4"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

variable "environment" {
  type        = string
  default     = "local-dev"
  description = "Target deployment environment (local-dev, staging, prod)"
}

variable "app_name" {
  type        = string
  default     = "secureship"
  description = "Application name"
}

variable "backend_port" {
  type        = number
  default     = 8000
  description = "SecureShip backend service port"
}

# Generate deployment token
resource "random_password" "deployment_token" {
  length  = 32
  special = false
}

# Local environment configuration file
resource "local_file" "environment_config" {
  filename = "${path.module}/generated_env_${var.environment}.json"
  content = jsonencode({
    app_name         = var.app_name
    environment      = var.environment
    backend_port     = var.backend_port
    deployment_token = random_password.deployment_token.result
    provisioned_at   = timestamp()
    iac_engine       = "Terraform"
  })
}

output "config_file_path" {
  value       = local_file.environment_config.filename
  description = "Path to the provisioned environment configuration"
}

output "deployment_token" {
  value       = random_password.deployment_token.result
  sensitive   = true
  description = "Auto-generated secure deployment authentication token"
}
