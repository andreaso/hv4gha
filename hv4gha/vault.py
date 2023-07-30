"""Vault specific code"""

import base64
import json
import os
from datetime import datetime
from typing import Any, Final

import requests
from cryptography.hazmat.primitives import hashes, keywrap, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class VaultAPIError(Exception):
    """Error response from the Vault API"""


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

    @staticmethod
    def __b64str(string: bytes | str, urlsafe: bool = False) -> str:
        if isinstance(string, str):
            string = string.encode()

        if urlsafe:
            return base64.urlsafe_b64encode(string).decode().rstrip("=")
        return base64.b64encode(string).decode()

    @staticmethod
    def __private_pem_to_der(private_pem: bytes) -> bytes:
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        private_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return private_der

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
            error_message: str
            try:
                error_message = "\n".join(http_error.response.json()["errors"])
            except Exception:  # pylint: disable=broad-exception-caught
                error_message = "<Failed to parse Vault API error response>"
            raise VaultAPIError(error_message) from http_error

        wrapping_pem_key = response.json()["data"]["public_key"].encode()
        wrapping_key = serialization.load_pem_public_key(wrapping_pem_key)

        if not isinstance(wrapping_key, rsa.RSAPublicKey):
            raise ValueError("Unexpected wrappingkey format")

        return wrapping_key

    def __wrap_key(self, der_app_key: bytes, wrapping_key: rsa.RSAPublicKey) -> str:
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

        wrapped_b64 = self.__b64str(wrapped_aes_key + wrapped_app_key)
        return wrapped_b64

    def __api_write(
        self, api_path: str, payload: None | dict[str, Any] = None
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
            error_message: str
            try:
                error_message = "\n".join(http_error.response.json()["errors"])
            except Exception:  # pylint: disable=broad-exception-caught
                error_message = "<Failed to parse Vault API error response>"
            raise VaultAPIError(error_message) from http_error

        return response

    def import_key(self, key_name: str, pem_app_key: bytes) -> None:
        """
        Import GitHub App key

        :param key_name: Name the Transit Engine will know the key by.
        :param pem_app_key: The App's PEM formated private RSA key.
        """
        der_app_key: bytes = self.__private_pem_to_der(pem_app_key)
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

        self.__api_write(api_path, payload)

    def __prepare_jwt(self, app_id: str) -> str:
        now = int(datetime.now().strftime("%s"))
        expire = now + 60

        header = {
            "alg": "RS256",
            "typ": "JWT",
        }

        claims = {
            "iat": now,
            "exp": expire,
            "iss": app_id,
        }

        b64_header = self.__b64str(json.dumps(header), urlsafe=True)
        b64_claims = self.__b64str(json.dumps(claims), urlsafe=True)

        header_and_claims = b64_header + "." + b64_claims
        return header_and_claims

    def sign_jwt(self, key_name: str, app_id: str) -> str:
        """
        Sign JWT token to authenticate towards GitHub

        :param key_name: Transit Engine key name.
        :param app_id: GitHub App ID.


        :return: GitHub App JWT token
        """

        header_and_claims = self.__prepare_jwt(app_id)

        api_path = f"/v1/{self.transit_backend}/sign/{key_name}"
        payload = {
            "input": self.__b64str(header_and_claims),
            "hash_algorithm": "sha2-256",
            "signature_algorithm": "pkcs1v15",
        }

        response: requests.models.Response = self.__api_write(api_path, payload)

        signature: str = response.json()["data"]["signature"].removeprefix("vault:v1:")
        signature = self.__b64str(base64.b64decode(signature), urlsafe=True)

        jwt_token = header_and_claims + "." + signature
        return jwt_token

    def revoke_token(self) -> None:
        """Vault Token self-revoke"""

        api_path = "/v1/auth/token/revoke-self"
        self.__api_write(api_path)
