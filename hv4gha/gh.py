"""GitHub specific code"""

import json
from datetime import datetime, timezone
from typing import Final, TypedDict

import requests


class TokenResponse(TypedDict, total=False):
    """Typing for customized Access Token response"""

    access_token: str
    expires_at: datetime
    permissions: dict[str, str]
    repositories: list[str]


class GitHubAPIError(Exception):
    """Error response from the GitHub API"""


class NotInstalledError(Exception):
    """The GitHub App isn't installed in the specified account"""


class GitHubApp:
    """GitHub App Access Tokens, etc"""

    def __init__(self, account: str, jwt_token: str):
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
                error_message: str
                try:
                    error_message = http_error.response.json()["message"]
                except Exception:  # pylint: disable=broad-exception-caught
                    error_message = "<Failed to parse GitHub API error response>"
                raise GitHubAPIError(error_message) from http_error

            for installation in response.json():
                if installation["account"]["login"].lower() == self.account.lower():
                    return str(installation["id"])

            if "next" in response.links.keys():
                pagination_params["page"] += 1
                more = True

        failure = f'App appear not to be installed in the "{self.account}" account'
        raise NotInstalledError(failure)

    def issue_token(
        self,
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
            error_message: str
            try:
                error_message = http_error.response.json()["message"]
            except Exception:  # pylint: disable=broad-exception-caught
                error_message = "<Failed to parse GitHub API error response>"
            raise GitHubAPIError(error_message) from http_error

        expiry = datetime.strptime(
            response.json()["expires_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)

        access_token: TokenResponse = {
            "access_token": response.json()["token"],
            "expires_at": expiry,
            "permissions": response.json()["permissions"],
        }

        if "repositories" in response.json().keys():
            access_token["repositories"] = sorted(
                [repo["name"] for repo in response.json()["repositories"]]
            )

        return access_token
