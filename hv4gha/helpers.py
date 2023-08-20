"""Helper functions"""

import base64

from cryptography.hazmat.primitives import serialization


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
