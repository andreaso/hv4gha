"""GitHub specific code"""

import json
from datetime import datetime
from typing import Annotated, Final, Literal

import requests
from pydantic import BaseModel, Field, TypeAdapter, ValidationError
from typing_extensions import NotRequired, TypedDict

PermARW = Literal["admin", "read", "write"]
PermRW = Literal["read", "write"]
PermR = Literal["read"]
PermW = Literal["write"]


class GitHubAPIError(Exception):
    """Any error response from the GitHub API"""


class InstallationLookupError(GitHubAPIError):
    """Failure to lookup the GitHub App installation ID"""


class TokenIssueError(GitHubAPIError):
    """Failure to issue GitHub Access Token"""


class NotInstalledError(Exception):
    """The GitHub App isn't installed in the specified account"""


class GitHubErrors(BaseModel):
    """
    https://docs.github.com/en/rest/overview/resources-in-the-rest-api?apiVersion=2022-11-28
    """

    message: str


class AccountInfo(TypedDict):
    """Part of Installation"""

    login: Annotated[
        str, Field(max_length=39, pattern=r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$")
    ]


class Installation(BaseModel):
    """
    https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#list-installations-for-the-authenticated-app
    """

    id: int
    account: AccountInfo


class TokenPermissions(TypedDict, total=False):
    """Part of AccessToken"""

    # Repository permissions
    actions: PermRW
    administration: PermRW
    checks: PermRW
    contents: PermRW
    deployments: PermRW
    environments: PermRW
    issues: PermRW
    metadata: PermRW
    packages: PermRW
    pages: PermRW
    pull_requests: PermRW
    repository_hooks: PermRW
    repository_projects: PermARW
    secret_scanning_alerts: PermRW
    secrets: PermRW
    security_events: PermRW
    single_file: PermRW
    statuses: PermRW
    vulnerability_alerts: PermRW
    workflows: PermW
    # Organizational permissions
    members: PermRW
    organization_administration: PermRW
    organization_custom_roles: PermRW
    organization_announcement_banners: PermRW
    organization_hooks: PermRW
    organization_personal_access_tokens: PermRW
    organization_personal_access_token_requests: PermRW
    organization_plan: PermR
    organization_projects: PermARW
    organization_packages: PermRW
    organization_secrets: PermRW
    organization_self_hosted_runners: PermRW
    organization_user_blocking: PermRW
    team_discussions: PermRW


class Repository(TypedDict):
    """Part of AccessToken"""

    name: Annotated[str, Field(max_length=100, pattern=r"^[a-zA-Z0-9_\-\.]+$")]


class AccessToken(BaseModel):
    """
    https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app
    """

    token: str
    expires_at: datetime
    permissions: TokenPermissions
    repositories: None | list[Repository] = None


class TokenResponse(TypedDict):
    """Typing for customized Access Token response"""

    access_token: str
    expires_at: datetime
    permissions: TokenPermissions
    repositories: NotRequired[list[str]]


class GitHubApp:
    """GitHub App Access Tokens, etc"""

    def __init__(self, *, account: str, jwt_token: str):
        """
        :param app_id: GitHub App ID.
        :param jwt_token: GitHub App JWT token
        """

        self.account: Final[str] = account
        self.auth_headers: Final[dict[str, str]] = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {jwt_token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def __find_installation(self) -> str:
        lookup_url = "https://api.github.com/app/installations"

        pagination_params = {
            "page": 1,
            "per_page": 100,
        }

        more = True
        while more:
            more = False
            try:
                response = requests.get(
                    lookup_url,
                    headers=self.auth_headers,
                    params=pagination_params,
                    timeout=10,
                )
                response.raise_for_status()
            except requests.exceptions.HTTPError as http_error:
                error_message = "<Failed to parse GitHub API error response>"
                try:
                    if http_error.response is not None:
                        errors_bm = GitHubErrors(**http_error.response.json())
                        error_message = errors_bm.message
                except Exception:
                    pass
                raise InstallationLookupError(error_message) from http_error

            try:
                ita = TypeAdapter(list[Installation])
                installations = ita.validate_python(response.json())
            except ValidationError as validation_error:
                error_message = "<Failed to parse Installations API response>"
                raise InstallationLookupError(error_message) from validation_error

            for installation in installations:
                if installation.account["login"].lower() == self.account.lower():
                    return str(installation.id)

            if "next" in response.links:
                pagination_params["page"] += 1
                more = True

        failure = f'App appear not to be installed in the "{self.account}" account'
        raise NotInstalledError(failure)

    def issue_token(
        self,
        *,
        permissions: None | dict[str, str] = None,
        repositories: None | list[str] = None,
    ) -> TokenResponse:
        """
        Issue GitHub Access Token

        :param permissions: Optionally scope (down) token permissions.
        :param repositories: Optionally limit accessible repositories.

        :return: The requested access token; together with its expiry
            time, permission scope and optionally covered repositories.
        """

        params: dict[str, dict[str, str] | list[str]] = {}
        if permissions:
            params.update({"permissions": permissions})
        if repositories:
            params.update({"repositories": repositories})

        installation_id: str = self.__find_installation()
        issue_url = "/".join(
            [
                "https://api.github.com/app/installations",
                installation_id,
                "access_tokens",
            ]
        )

        try:
            response = requests.post(
                issue_url,
                headers=self.auth_headers,
                data=json.dumps(params),
                timeout=10,
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as http_error:
            error_message = "<Failed to parse GitHub API error response>"
            try:
                if http_error.response is not None:
                    errors_bm = GitHubErrors(**http_error.response.json())
                    error_message = errors_bm.message
            except Exception:
                pass
            raise TokenIssueError(error_message) from http_error

        try:
            access_token_bm = AccessToken(**response.json())
        except ValidationError as validation_error:
            error_message = "<Failed to parse Token Issue API response>"
            raise TokenIssueError(error_message) from validation_error

        access_token: TokenResponse = {
            "access_token": access_token_bm.token,
            "expires_at": access_token_bm.expires_at,
            "permissions": access_token_bm.permissions,
        }

        if access_token_bm.repositories is not None:
            access_token["repositories"] = sorted(
                [repo["name"] for repo in access_token_bm.repositories]
            )

        return access_token
