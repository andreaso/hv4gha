"""Helper functions"""

import base64
import json
import os
from datetime import datetime

from cryptography.hazmat.primitives import hashes, keywrap, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def b64str(data: bytes | str, urlsafe: bool = False) -> str:
    """
    A more type helpful b64encode wrapper function

    :param data: Input to base64 encode
    :param urlsafe: Whatever to make the output JWT URL-safe or not

    :return: Base64 encoded result
    """
    if isinstance(data, str):
        data = data.encode()

    if urlsafe:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")
    return base64.b64encode(data).decode()


def prepare_gh_app_jwt(app_id: str, now: datetime) -> str:
    """
    Prepares the JWT payload needed to authenticate as a GitHub App

    :param app_id: The GitHub App's ID
    :param now: Current UTC time

    :return: The header-and-claims part of a JWT token
    """
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


def private_pem_to_der(private_pem: bytes) -> bytes:
    """
    Converts private key from PEM to DER

    :param private_pem: PEM encoded private key

    :return: DER encoded private key
    """
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_der


def vault_wrap_key(der_app_key: bytes, wrapping_key: rsa.RSAPublicKey) -> str:
    """
    Wrap a private key the way Vault wants it wrapped

    :param der_app_key: DER encoded private key
    :param wrapping_key: Vault provided wrapping key

    :return: Wrapped key
    """

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
