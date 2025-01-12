"""Vault specific code"""

import base64
import json
import re
from datetime import datetime, timezone
from typing import Any, Final

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import BaseModel, ValidationError
from typing_extensions import TypedDict

from .helpers import b64str, prepare_gh_app_jwt, private_pem_to_der, vault_wrap_key


class VaultAPIError(Exception):
    """Any error response from the Vault API"""


class AppKeyImportError(VaultAPIError):
    """Failure to upload/import the wrapped GitHub App key into Vault"""


class JWTSigningError(VaultAPIError):
    """Failure to have Vault sign a GitHub App JWT token"""


class TokenRevokeError(VaultAPIError):
    """Failure to self-revoke the Vault token"""


class VersionLookupError(VaultAPIError):
    """Failure to lookup the version of the imported key version"""


class WrappingKeyDownloadError(VaultAPIError):
    """Failure to download the Vault Transit wrapping key"""


class VaultErrors(BaseModel):
    """
    https://developer.hashicorp.com/vault/api-docs#error-response
    """

    errors: list[str]


class VersionData(TypedDict):
    """Part of KeyLookup"""

    latest_version: int


class KeyLookup(BaseModel):
    """
    https://developer.hashicorp.com/vault/api-docs/secret/transit#read-key
    """

    data: VersionData


class JWTData(TypedDict):
    """Part of SignedJWT"""

    signature: str


class SignedJWT(BaseModel):
    """
    https://developer.hashicorp.com/vault/api-docs/secret/transit#sign-data
    """

    data: JWTData


class KeyData(TypedDict):
    """Part of WrappingKey"""

    public_key: str


class WrappingKey(BaseModel):
    """
    https://developer.hashicorp.com/vault/api-docs/secret/transit#get-wrapping-key
    """

    data: KeyData


class ImportResponse(TypedDict):
    """Typing for key import response"""

    key_version: int


class VaultTransit:
    """Interact with Vault's Transit Secrets Engine"""

    def __init__(self, *, vault_addr: str, vault_token: str, transit_backend: str):
        """
        :param vault_addr: Vault instance VAULT_ADDR.
        :param vault_token: Vault instance VAULT_TOKEN.
        :param transit_backend: Transit backend mount path.
        """
        self.vault_addr: Final[str] = vault_addr.rstrip("/")
        self.auth_headers: Final[dict[str, str]] = {"X-Vault-Token": vault_token}
        self.transit_backend: Final[str] = transit_backend.strip("/")

    def __api_read(
        self,
        api_path: str,
    ) -> requests.models.Response:
        read_url = self.vault_addr + api_path

        response = requests.get(
            read_url,
            headers=self.auth_headers,
            timeout=10,
        )
        response.raise_for_status()

        return response

    def __api_write(
        self,
        api_path: str,
        payload: None | dict[str, Any] = None,
    ) -> requests.models.Response:
        update_url = self.vault_addr + api_path

        if payload is None:
            payload = {}

        response = requests.post(
            update_url,
            headers=self.auth_headers,
            data=json.dumps(payload),
            timeout=10,
        )
        response.raise_for_status()

        return response

    def __download_wrapping_key(self) -> rsa.RSAPublicKey:
        api_path = f"/v1/{self.transit_backend}/wrapping_key"

        try:
            response: requests.models.Response = self.__api_read(api_path)
        except requests.exceptions.HTTPError as http_error:
            raise WrappingKeyDownloadError(http_error.response.text) from http_error

        try:
            wrapping_key_bm = WrappingKey(**response.json())
        except ValidationError as validation_error:
            error_message = "<Failed to parse Wrapping Key API response>"
            raise WrappingKeyDownloadError(error_message) from validation_error

        wrapping_pem_key = wrapping_key_bm.data["public_key"].encode()
        wrapping_key = serialization.load_pem_public_key(wrapping_pem_key)

        if not isinstance(wrapping_key, rsa.RSAPublicKey):
            raise ValueError("Unexpected wrappingkey format")

        return wrapping_key

    def __lookup_version(self, *, key_name: str) -> int:
        api_path = f"/v1/{self.transit_backend}/keys/{key_name}"

        try:
            response: requests.models.Response = self.__api_read(api_path)
        except requests.exceptions.HTTPError as http_error:
            raise VersionLookupError(http_error.response.text) from http_error

        try:
            key_lookup_bm = KeyLookup(**response.json())
        except ValidationError as validation_error:
            error_message = "<Failed to parse key lookup API response>"
            raise VersionLookupError(error_message) from validation_error

        return key_lookup_bm.data["latest_version"]

    @staticmethod
    def __check_import_version_error(http_error: requests.exceptions.HTTPError) -> bool:
        try:
            errors_bm = VaultErrors(**http_error.response.json())
        except ValidationError:
            return False
        return "use import-version" in errors_bm.errors[0]

    def __import_version(self, *, key_name: str, wrapped_b64: str) -> int:
        api_path = f"/v1/{self.transit_backend}/keys/{key_name}/import_version"
        payload = {
            "ciphertext": wrapped_b64,
            "hash_function": "SHA256",
        }

        try:
            self.__api_write(api_path, payload)
        except requests.exceptions.HTTPError as http_error:
            raise AppKeyImportError(http_error.response.text) from http_error

        key_version: int = self.__lookup_version(key_name=key_name)
        return key_version

    def import_key(self, *, key_name: str, pem_app_key: bytes) -> ImportResponse:
        """
        Import GitHub App key

        :param key_name: Name the Transit Engine will know the key by.
        :param pem_app_key: The App's PEM formated private RSA key.
        """
        der_app_key: bytes = private_pem_to_der(pem_app_key)
        wrapping_key: rsa.RSAPublicKey = self.__download_wrapping_key()
        wrapped_b64: str = vault_wrap_key(der_app_key, wrapping_key)

        api_path = f"/v1/{self.transit_backend}/keys/{key_name}/import"
        payload = {
            "ciphertext": wrapped_b64,
            "hash_function": "SHA256",
            "type": "rsa-2048",
            "exportable": False,
            "allow_plaintext_backup": False,
        }

        key_import: ImportResponse = {"key_version": 1}
        try:
            self.__api_write(api_path, payload)
            return key_import
        except requests.exceptions.HTTPError as http_error:
            if not self.__check_import_version_error(http_error):
                raise AppKeyImportError(http_error.response.text) from http_error

            key_version: int = self.__import_version(
                key_name=key_name, wrapped_b64=wrapped_b64
            )
            key_import["key_version"] = key_version

        return key_import

    def sign_jwt(self, *, key_name: str, key_version: int, app_client_id: str) -> str:
        """
        Sign JWT token to authenticate towards GitHub

        :param key_name: Transit Engine key name.
        :param key_version: Transit Engine key version.
        :param app_client_id: GitHub App client ID.


        :return: GitHub App JWT token
        """

        now = datetime.now(timezone.utc)
        header_and_claims = prepare_gh_app_jwt(app_client_id, now)

        api_path = f"/v1/{self.transit_backend}/sign/{key_name}"
        payload = {
            "input": b64str(header_and_claims),
            "hash_algorithm": "sha2-256",
            "signature_algorithm": "pkcs1v15",
            "key_version": key_version,
        }

        try:
            response: requests.models.Response = self.__api_write(api_path, payload)
        except requests.exceptions.HTTPError as http_error:
            raise JWTSigningError(http_error.response.text) from http_error

        try:
            signature_bm = SignedJWT(**response.json())
        except ValidationError as validation_error:
            error_message = "<Failed to parse Sign JWT API response>"
            raise JWTSigningError(error_message) from validation_error

        signature = re.sub(r"^vault:v[0-9]+:", "", signature_bm.data["signature"])
        signature = b64str(base64.b64decode(signature), urlsafe=True)

        jwt_token = header_and_claims + "." + signature
        return jwt_token

    def revoke_token(self) -> None:
        """Vault Token self-revoke"""

        api_path = "/v1/auth/token/revoke-self"

        try:
            self.__api_write(api_path)
        except requests.exceptions.HTTPError as http_error:
            raise TokenRevokeError(http_error.response.text) from http_error
