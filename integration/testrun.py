#!/usr/bin/env python3
"""Integration testing"""

import os
import sys
from base64 import b64decode

from hv4gha import TokenResponse, import_app_key, issue_access_token
from hv4gha.gh import TokenPermissions


def _check_perms(requested: dict[str, str], result: TokenPermissions) -> None:
    result.pop("metadata")  # Clear default permission
    complaint = "Returned permissions does not match requested permissions"
    assert requested == result, complaint


def _check_repos(requested: list[str], result: list[str]) -> None:
    sanitized_request = sorted([repo.lower() for repo in requested])
    sanitized_result = sorted([repo.lower() for repo in result])
    complaint = "Returned repositories does not match requested repositories"
    assert sanitized_request == sanitized_result, complaint


def key_import() -> None:
    """Import App key into Vault"""

    import_app_key(
        pem_key=b64decode(os.environ["HV4GHA_REVOKED_APP_KEY_B64"]),
        key_name=os.environ["HV4GHA_KEYNAME"],
        vault_addr=os.environ["HV4GHA_VAULT_ADDR"],
        vault_token=os.environ["HVGHA_VAULT_IMPORT_TOKEN"],
    )

    import_app_key(
        pem_key=b64decode(os.environ["HV4GHA_APP_KEY_B64"]),
        key_name=os.environ["HV4GHA_KEYNAME"],
        vault_addr=os.environ["HV4GHA_VAULT_ADDR"],
        vault_token=os.environ["HVGHA_VAULT_IMPORT_TOKEN"],
    )


def issue() -> None:
    """Issue an access token"""

    issue_access_token(
        key_name=os.environ["HV4GHA_KEYNAME"],
        vault_addr=os.environ["HV4GHA_VAULT_ADDR"],
        vault_token=os.environ["HVGHA_VAULT_SIGN_TOKEN"],
        app_client_id=os.environ["HV4GHA_APP_CLIENT_ID"],
        account=os.environ["HV4GHA_ACCOUNT"],
    )


def issue_scoped() -> None:
    """Issue a scoped access token, and verify its properties"""

    req_perms = {"statuses": "read"}

    access_token: TokenResponse = issue_access_token(
        key_name=os.environ["HV4GHA_KEYNAME"],
        vault_addr=os.environ["HV4GHA_VAULT_ADDR"],
        vault_token=os.environ["HVGHA_VAULT_SIGN_TOKEN"],
        app_client_id=os.environ["HV4GHA_APP_CLIENT_ID"],
        account=os.environ["HV4GHA_ACCOUNT"],
        permissions=req_perms,
        repositories=[os.environ["HV4GHA_TEST_REPO"]],
    )

    _check_perms(req_perms, access_token["permissions"])
    _check_repos([os.environ["HV4GHA_TEST_REPO"]], access_token["repositories"])


def main() -> None:
    """Parse args, run tests"""

    sys.argv.pop(0)
    if not sys.argv:
        print("No test commands provided", file=sys.stderr)
        sys.exit(1)

    for arg in sys.argv:
        if arg == "import":
            key_import()
        elif arg == "issue":
            issue()
        elif arg == "issue-scoped":
            issue_scoped()
        else:
            print(f"Unknown test command: {arg}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
