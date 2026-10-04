"""GitHub specific code"""

from datetime import datetime
from typing import Annotated, Final, Literal

import requests
from pydantic import BaseModel, Field, TypeAdapter
from typing_extensions import NotRequired, TypedDict

PermARW = Literal["admin", "read", "write"]
PermRW = Literal["read", "write"]
PermR = Literal["read"]
PermW = Literal["write"]

RepoName = Annotated[str, Field(max_length=100, pattern=r"^[a-zA-Z0-9_\-\.]+$")]


class ArgumentError(ValueError):
    """Used to raise specific argument errors"""


class NotInstalledError(Exception):
    """The GitHub App isn't installed in the specified account"""


class AccountInfo(TypedDict):
    """Part of Installation"""

    login: Annotated[
        str, Field(max_length=39, pattern=r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$")
    ]


class Installation(BaseModel):
    """
    https://docs.github.com/en/rest/apps/apps?apiVersion=2026-03-10#list-installations-for-the-authenticated-app
    """

    id: int
    account: AccountInfo


class TokenPermissions(TypedDict, total=False):
    """Part of AccessTokenResponse and AccessTokenRequest"""

    # Repository permissions
    actions: PermRW
    administration: PermRW
    artifact_metadata: PermRW
    attestations: PermRW
    checks: PermRW
    code_quality: PermRW
    codespaces: PermRW
    contents: PermRW
    dependabot_secrets: PermRW
    deployments: PermRW
    discussions: PermRW
    environments: PermRW
    issues: PermRW
    merge_queues: PermRW
    metadata: PermRW
    packages: PermRW
    pages: PermRW
    pull_requests: PermRW
    repository_custom_properties: PermRW
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
    custom_properties_for_organizations: PermRW
    members: PermRW
    organization_administration: PermRW
    organization_custom_roles: PermRW
    organization_custom_org_roles: PermRW
    organization_custom_properties: PermARW
    organization_copilot_seat_management: PermRW
    organization_copilot_agent_settings: PermRW
    organization_external_properties_for_repos: PermARW
    organization_announcement_banners: PermRW
    organization_events: PermR
    organization_hooks: PermRW
    organization_personal_access_tokens: PermRW
    organization_personal_access_token_requests: PermRW
    organization_plan: PermR
    organization_projects: PermARW
    organization_packages: PermRW
    organization_secrets: PermRW
    organization_self_hosted_runners: PermRW
    organization_user_blocking: PermRW
    # Account permissions
    email_addresses: PermRW
    followers: PermRW
    git_ssh_keys: PermRW
    gpg_keys: PermRW
    interaction_limits: PermRW
    profile: PermW
    starring: PermRW
    # Enterprise permissions
    enterprise_custom_properties_for_organizations: PermARW


class Repository(TypedDict):
    """Part of AccessTokenResponse"""

    name: RepoName


class AccessTokenResponse(BaseModel):
    """
    https://docs.github.com/en/rest/apps/apps?apiVersion=2026-03-10#create-an-installation-access-token-for-an-app
    """

    token: str
    expires_at: datetime
    permissions: TokenPermissions
    repositories: None | list[Repository] = None


class AccessTokenRequest(BaseModel, validate_assignment=True, extra="forbid"):
    """
    https://docs.github.com/en/rest/apps/apps?apiVersion=2026-03-10#create-an-installation-access-token-for-an-app
    """

    permissions: None | TokenPermissions = None
    repositories: None | list[RepoName] = None


class TokenResponse(TypedDict):
    """Typing for customized Access Token response"""

    access_token: str
    expires_at: datetime
    permissions: TokenPermissions
    repositories: NotRequired[list[str]]


class GitHubApp:
    """GitHub App Access Tokens, etc"""

    def __init__(
        self,
        *,
        account: None | str,
        installation_id: None | str,
        jwt_token: str,
    ):
        """
        :param account: GitHub account to access. It or installation_id is required.
        :param installation_id: App Installation ID for the GitHub account to access.
        :param jwt_token: GitHub App JWT token
        """

        self.auth_headers: Final[dict[str, str]] = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {jwt_token}",
            "X-GitHub-Api-Version": "2026-03-10",
        }

        self.installation_id: str
        if installation_id:
            self.installation_id = installation_id
        elif account:
            self.installation_id = self.__find_installation(account)
        else:
            raise ArgumentError("Specify either account or installation_id")

    def __find_installation(self, account: str) -> str:
        lookup_url = "https://api.github.com/app/installations"

        pagination_params = {
            "page": 1,
            "per_page": 100,
        }

        more = True
        while more:
            more = False
            response = requests.get(
                lookup_url,
                headers=self.auth_headers,
                params=pagination_params,
                timeout=10,
            )
            response.raise_for_status()

            ita = TypeAdapter(list[Installation])
            installations = ita.validate_python(response.json())

            for installation in installations:
                if installation.account["login"].lower() == account.lower():
                    return str(installation.id)

            if "next" in response.links:
                pagination_params["page"] += 1
                more = True

        failure = f'App appear not to be installed in the "{account}" account'
        raise NotInstalledError(failure)

    def issue_token(
        self,
        *,
        permissions: None | TokenPermissions = None,
        repositories: None | list[RepoName] = None,
    ) -> TokenResponse:
        """
        Issue GitHub Access Token

        :param permissions: Optionally scope (down) token permissions.
        :param repositories: Optionally limit accessible repositories.

        :return: The requested access token; together with its expiry
            time, permission scope and optionally covered repositories.
        """

        params_bm = AccessTokenRequest()
        if permissions:
            params_bm.permissions = permissions
        if repositories:
            params_bm.repositories = repositories

        issue_url = "/".join(
            [
                "https://api.github.com/app/installations",
                self.installation_id,
                "access_tokens",
            ]
        )

        response = requests.post(
            issue_url,
            headers=self.auth_headers,
            data=params_bm.model_dump_json(exclude_unset=True),
            timeout=10,
        )
        response.raise_for_status()

        access_token_bm = AccessTokenResponse(**response.json())
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
