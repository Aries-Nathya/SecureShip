# SecureShip Configuration Management (Ansible & Ansible Vault)

This module automates server preparation and demonstrates secret encryption using Ansible Vault.

## 1. Running the Playbook

```bash
cd infra/ansible
ansible-playbook -i inventory.ini playbook.yml
```

## 2. Protecting Secrets with Ansible Vault

To prevent plaintext API keys or certificates from being committed to Git:

```bash
# Encrypt a secrets file
ansible-vault encrypt group_vars/vault.yml

# View encrypted contents
ansible-vault view group_vars/vault.yml

# Run playbook with vault decryption prompt
ansible-playbook -i inventory.ini playbook.yml --ask-vault-pass
```

*Note: Never commit `.vault_password` or secret encryption keys into version control.*
