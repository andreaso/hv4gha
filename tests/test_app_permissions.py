import requests
from pydantic import TypeAdapter

from hv4gha.gh import TokenPermissions

OpenApiPerms = dict[str, dict[str, str | list[str]]]


def openapi_perms() -> OpenApiPerms:
    openapi_url = "/".join(
        [
            "https://raw.githubusercontent.com",
            "github/rest-api-description",
            "refs/heads/main",
            "descriptions/api.github.com",
            "api.github.com.2026-03-10.json",
        ]
    )

    response = requests.get(openapi_url, timeout=10)
    schemas = response.json()["components"]["schemas"]
    permissions: OpenApiPerms = schemas["app-permissions"]["properties"]

    return permissions


def test_token_permissions() -> None:
    tpa = TypeAdapter(TokenPermissions)
    available = {perm: desc["enum"][0] for perm, desc in openapi_perms().items()}
    allowed = tpa.validate_python(available)
    assert available == allowed
