# HashiCorp Vault for GitHub Apps

Python library for using [HashiCorp Vault][1]'s [Transit Engine][2] to
manage a GitHub App's private RSA key. More precisely, the library
provides the following pieces of functionality.

* Perform initial one-way import of the App's private key into Vault
* Issue (short-lived) GitHub Access Token
  * Have Vault sign a JWT using the App's private key
  * Exchange that JWT for a GitHub Access Token

Conceptually Vault here fills the role of an HSM or a Cloud KMS.

See [Authenticating as a GitHub App installation (GitHub Docs)][3] for context.

## Installation

```shell
pip install hv4gha
```

## Usage

In addition to the examples below see also the
[hv4gha/entry.py](https://github.com/andreaso/hv4gha/blob/main/hv4gha/entry.py) docstrings.

### Import App key

```python
from hv4gha import import_app_key

with open("/path/to/github-app.private-key.pem", "r") as akh:
    my_app_key = akh.read()

response = import_app_key(
    pem_key=my_app_key,
    key_name="my-github-app",
    vault_addr="https://vault.example.com:8200",
    vault_token="...",
)

key_version = response["key_version"]
```

### Issue Access Token

```python
from hv4gha import issue_access_token

response = issue_access_token(
    key_name="my-github-app",
    vault_addr="https://vault.example.com:8200",
    vault_token="...",
    app_client_id="Iv1.bc01362e9d72c72a",
    account="andreaso",
)

access_token = response["access_token"]
token_expiry = response["expires_at"]
```

### Issue scoped Access Token

```python
from hv4gha import issue_access_token

response = issue_access_token(
    key_name="my-github-app",
    vault_addr="https://vault.example.com:8200",
    vault_token="...",
    app_client_id="Iv1.bc01362e9d72c72a",
    account="andreaso",
    permissions={"contents": "read"},
    repositories=["world-domination"],
)

access_token = response["access_token"]
token_expiry = response["expires_at"]
```

## Vault requirements

Somewhat simplified, this is what's required Vault wise.

### Transit secrets engine

First of all, the [Transit Engine][2] needs to be enabled.

```shell
vault secrets enable transit
```

Here we are sticking to the default `transit/` mount point.

### Import policy

```HCL
path "transit/wrapping_key" {
  capabilities = ["read"]
}

path "transit/keys/my-github-app" {
  capabilities = ["read"]
}

path "transit/keys/my-github-app/import" {
  capabilities = ["update"]
}

path "transit/keys/my-github-app/import_version" {
  capabilities = ["update"]
}
```

### Issue policy

```HCL
path "transit/sign/my-github-app" {
  capabilities = ["update"]
}
```

### Vault Token

For obtaining the initial Vault Token, see the [hvac][4] Python
library and its [Auth Methods][5] documentation.


[1]: https://www.vaultproject.io/
[2]: https://developer.hashicorp.com/vault/docs/secrets/transit
[3]: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation
[4]: https://github.com/hvac/hvac
[5]: https://hvac.readthedocs.io/en/stable/usage/auth_methods/
