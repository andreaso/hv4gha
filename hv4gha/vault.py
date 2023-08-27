"""Vault specific code"""

import base64
import json
import os
from datetime import datetime, timezone
from typing import Any, Final

import requests
from cryptography.hazmat.primitives import hashes, keywrap, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import BaseModel, ValidationError

from .helpers import b64str, private_pem_to_der


class VaultAPIError(Exception):
    """Any error response from the Vault API"""


class AppKeyImportError(VaultAPIError):
    """Failure to upload/import the wrapped GitHub App key into Vault"""


class JWTSigningError(VaultAPIError):
    """Failure to have Vault sign a GitHub App JWT token"""


class TokenRevokeError(VaultAPIError):
    """Failure to self-revoke the Vault token"""


class WrappingKeyDownloadError(VaultAPIError):
    """Failure to download the Vault Transit wrapping key"""


class VaultErrors(BaseModel):
    """
    https://developer.hashicorp.com/vault/api-docs#error-response
    """

    errors: list[str]


class JWTData(BaseModel):
    """Part of SignedJWT"""

    signature: str


class SignedJWT(BaseModel):
    """
    https://developer.hashicorp.com/vault/api-docs/secret/transit#sign-data
    """

    data: JWTData


class KeyData(BaseModel):
    """Part of WrappingKey"""

    public_key: str


class WrappingKey(BaseModel):
    """
    https://developer.hashicorp.com/vault/api-docs/secret/transit#get-wrapping-key
    """

    data: KeyData


class VaultTransit:
    """Interact with Vault's Transit Secrets Engine"""

    def __init__(self, vault_addr: str, vault_token: str, transit_backend: str):
        """
        :param vault_addr: Vault instance VAULT_ADDR.
        :param vault_token: Vault instance VAULT_TOKEN.
        :param transit_backend: Transit backend mount path.
        """
        self.vault_addr: Final[str] = vault_addr.rstrip("/")
        self.auth_headers: Final[dict[str, str]] = {"X-Vault-Token": vault_token}
        self.transit_backend: Final[str] = transit_backend.strip("/")

    def __download_wrapping_key(self) -> rsa.RSAPublicKey:
        wrapping_key_url = self.vault_addr + f"/v1/{self.transit_backend}/wrapping_key"

        try:
            response = requests.get(
                wrapping_key_url,
                headers=self.auth_headers,
                timeout=10,
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as http_error:
            try:
                errors_bm = VaultErrors(**http_error.response.json())
                error_message = "\n".join(errors_bm.errors)
            except Exception:  # pylint: disable=broad-exception-caught
                error_message = "<Failed to parse Vault API error response>"
            raise WrappingKeyDownloadError(error_message) from http_error

        try:
            wrapping_key_bm = WrappingKey(**response.json())
        except ValidationError as validation_error:
            error_message = "<Failed to parse Wrapping Key API response>"
            raise WrappingKeyDownloadError(error_message) from validation_error

        wrapping_pem_key = wrapping_key_bm.data.public_key.encode()
        wrapping_key = serialization.load_pem_public_key(wrapping_pem_key)

        if not isinstance(wrapping_key, rsa.RSAPublicKey):
            raise ValueError("Unexpected wrappingkey format")

        return wrapping_key

    @staticmethod
    def __wrap_key(der_app_key: bytes, wrapping_key: rsa.RSAPublicKey) -> str:
        aes_key = os.getrandom(32)

        wrapped_app_key = keywrap.aes_key_wrap_with_padding(aes_key, der_app_key)
        wrapped_aes_key = wrapping_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        wrapped_b64 = b64str(wrapped_aes_key + wrapped_app_key)
        return wrapped_b64

    def __api_write(
        self,
        api_path: str,
        payload: None | dict[str, Any] = None,
        vault_exception: type[Exception] = VaultAPIError,
    ) -> requests.models.Response:
        update_url = self.vault_addr + api_path

        if payload is None:
            payload = {}

        try:
            response = requests.post(
                update_url,
                headers=self.auth_headers,
                data=json.dumps(payload),
                timeout=10,
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as http_error:
            try:
                errors_bm = VaultErrors(**http_error.response.json())
                error_message = "\n".join(errors_bm.errors)
            except Exception:  # pylint: disable=broad-exception-caught
                error_message = "<Failed to parse Vault API error response>"
            raise vault_exception(error_message) from http_error

        return response

    def import_key(self, key_name: str, pem_app_key: bytes) -> None:
        """
        Import GitHub App key

        :param key_name: Name the Transit Engine will know the key by.
        :param pem_app_key: The App's PEM formated private RSA key.
        """
        der_app_key: bytes = private_pem_to_der(pem_app_key)
        wrapping_key: rsa.RSAPublicKey = self.__download_wrapping_key()
        wrapped_b64: str = self.__wrap_key(der_app_key, wrapping_key)

        api_path = f"/v1/{self.transit_backend}/keys/{key_name}/import"
        payload = {
            "ciphertext": wrapped_b64,
            "hash_function": "SHA256",
            "type": "rsa-2048",
            "exportable": False,
            "allow_plaintext_backup": False,
        }

        self.__api_write(api_path, payload, AppKeyImportError)

    @staticmethod
    def __prepare_jwt(app_id: str, now: datetime) -> str:
        timestamp = int(now.timestamp())
        expire = timestamp + 60

        header = {
            "alg": "RS256",
            "typ": "JWT",
        }

        claims = {
            "iat": timestamp,
            "exp": expire,
            "iss": app_id,
        }

        b64_header = b64str(json.dumps(header), urlsafe=True)
        b64_claims = b64str(json.dumps(claims), urlsafe=True)

        header_and_claims = b64_header + "." + b64_claims
        return header_and_claims

    def sign_jwt(self, key_name: str, app_id: str) -> str:
        """
        Sign JWT token to authenticate towards GitHub

        :param key_name: Transit Engine key name.
        :param app_id: GitHub App ID.


        :return: GitHub App JWT token
        """

        now = datetime.now(timezone.utc)
        header_and_claims = self.__prepare_jwt(app_id, now)

        api_path = f"/v1/{self.transit_backend}/sign/{key_name}"
        payload = {
            "input": b64str(header_and_claims),
            "hash_algorithm": "sha2-256",
            "signature_algorithm": "pkcs1v15",
        }

        response: requests.models.Response = self.__api_write(
            api_path, payload, JWTSigningError
        )

        try:
            signature_bm = SignedJWT(**response.json())
        except ValidationError as validation_error:
            error_message = "<Failed to parse Sign JWT API response>"
            raise JWTSigningError(error_message) from validation_error

        signature = signature_bm.data.signature.removeprefix("vault:v1:")
        signature = b64str(base64.b64decode(signature), urlsafe=True)

        jwt_token = header_and_claims + "." + signature
        return jwt_token

    def revoke_token(self) -> None:
        """Vault Token self-revoke"""

        api_path = "/v1/auth/token/revoke-self"
        self.__api_write(api_path, vault_exception=TokenRevokeError)
