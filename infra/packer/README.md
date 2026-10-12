# SecureShip Image Automation (Packer)

Packer automates the creation of hardened, repeatable machine images for SecureShip.

## Validation & Build Lifecycle

```bash
cd infra/packer

# 1. Format template
packer fmt secureship.pkr.hcl

# 2. Initialize plugins
packer init secureship.pkr.hcl

# 3. Validate template syntax
packer validate secureship.pkr.hcl

# 4. Build image
packer build secureship.pkr.hcl
```
