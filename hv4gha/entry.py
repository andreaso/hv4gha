"""Top-level functions"""

from .gh import GitHubApp, TokenResponse
from .vault import VaultTransit


def import_app_key(
    # pylint: disable=too-many-arguments
    pem_key: bytes | str,
    key_name: str,
    vault_addr: str,
    vault_token: str,
    transit_backend: str = "transit",
    revoke_vault_token: bool = False,
) -> None:
    """
    Import GitHub App key into Vault's Transit engine

    :param pem_key: The App's PEM formated private RSA key.
    :param key_name: Name which Vault's Transit Engine will know the key by.
    :param vault_addr: Vault instance VAULT_ADDR.
    :param vault_token: Vault instance VAULT_TOKEN.
    :param transit_backend: Transit backend mount path. Defaults to "transit".
    :param revoke_vault_token: Revoke `vault_token` once done? Defaults to False.
    """

    if isinstance(pem_key, str):
        pem_key = pem_key.encode()

    transit = VaultTransit(vault_addr, vault_token, transit_backend)
    transit.import_key(key_name, pem_key)

    if revoke_vault_token:
        transit.revoke_token()


def issue_access_token(
    # pylint: disable=too-many-arguments
    key_name: str,
    vault_addr: str,
    vault_token: str,
    app_id: int | str,
    account: str,
    permissions: None | dict[str, str] = None,
    repositories: None | list[str] = None,
    transit_backend: str = "transit",
    revoke_vault_token: bool = False,
) -> TokenResponse:
    """
    Issue GitHub Access Token

    :param key_name: Name which Vault's Transit Engine knows the App key by.
    :param vault_addr: Vault instance VAULT_ADDR.
    :param vault_token: Vault instance VAULT_TOKEN.
    :param app_id: GitHub App ID.
    :param account: GitHub account to access, where the App is installed.
    :param permissions: Optionally scope (down) token permissions.
    :param repositories: Optionally limit accessible repositories.
    :param transit_backend: Vault Transit backend mount path. Defaults to "transit".
    :param revoke_vault_token: Revoke `vault_token` once done? Defaults to False.

    :return: The requested access token; together with its expiry
        time, permission scope and optionally covered repositories.
    """

    if isinstance(app_id, int):
        app_id = str(app_id)

    transit = VaultTransit(vault_addr, vault_token, transit_backend)
    jwt: str = transit.sign_jwt(key_name, app_id)

    ghapp = GitHubApp(account, jwt)
    access_token: TokenResponse = ghapp.issue_token(permissions, repositories)

    if revoke_vault_token:
        transit.revoke_token()

    return access_token
