# SecureShip Infrastructure as Code (Terraform)

This module demonstrates declarative Infrastructure as Code (IaC) for SecureShip.

## 1. Local Lifecycle Execution

Run the lifecycle commands inside `infra/terraform`:

```bash
# 1. Initialize providers
terraform init

# 2. Check formatting
terraform fmt -check

# 3. Validate syntax
terraform validate

# 4. Preview execution plan
terraform plan

# 5. Apply changes (zero cloud cost local execution)
terraform apply -auto-approve
```

## 2. Adaptation to Cloud (Azure Example)

To transition from local deployment to Azure Container Apps or Azure Kubernetes Service (AKS), replace the `local` provider with `hashicorp/azurerm`:

```hcl
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "secureship_rg" {
  name     = "rg-secureship-${var.environment}"
  location = "eastus"
}

resource "azurerm_container_app_environment" "secureship_env" {
  name                = "env-secureship"
  location            = azurerm_resource_group.secureship_rg.location
  resource_group_name = azurerm_resource_group.secureship_rg.name
}
```
