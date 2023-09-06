"""Testing of helper functions"""

# pylint: disable=missing-function-docstring

import json
from base64 import b64decode
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, keywrap, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from hv4gha.helpers import (
    b64str,
    prepare_gh_app_jwt,
    private_pem_to_der,
    vault_wrap_key,
)


def vault_unwrap_key(wrapped_app_key: str) -> bytes:
    raw_wrapped = b64decode(wrapped_app_key.encode())
    wrapped_aes_key = raw_wrapped[:512]
    wrapped_app_der = raw_wrapped[512:]

    with open("./tests/data/dummy_wrapping_private_key.pem", "rb") as pwkfh:
        wrapping_private_pem = pwkfh.read()

    rsa_unwrapper = serialization.load_pem_private_key(
        wrapping_private_pem, password=None
    )
    if not isinstance(rsa_unwrapper, rsa.RSAPrivateKey):
        raise ValueError("Unexpected wrappingkey format")

    aes_key = rsa_unwrapper.decrypt(
        wrapped_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    unwrapped_app_der = keywrap.aes_key_unwrap_with_padding(aes_key, wrapped_app_der)
    return unwrapped_app_der


def test_pem_to_dir() -> None:
    with open("./tests/data/dummy_private_key.pem", "rb") as pfh:
        private_pem = pfh.read()
    with open("./tests/data/dummy_private_key.der", "rb") as dfh:
        original_private_der = dfh.read()

    converted_private_der = private_pem_to_der(private_pem)

    assert converted_private_der == original_private_der


def test_bytes_to_b64_str() -> None:
    with open("./tests/data/dummy_blob", "rb") as bfh:
        binary_blob = bfh.read()

    resulted_b64 = b64str(binary_blob)
    expected_b64 = "FSMiLXMuvIJ6howEmPrsDLWa5ls="

    assert resulted_b64 == expected_b64


def test_str_to_b64_str() -> None:
    resulted_b64 = b64str("Hello World")
    expected_b64 = "SGVsbG8gV29ybGQ="

    assert resulted_b64 == expected_b64


def test_str_to_b64_safe_str() -> None:
    data = json.dumps({"name": "Reynolds", "ship": "Serenity"})
    resulted_b64 = b64str(data, urlsafe=True)

    expected_b64 = "eyJuYW1lIjogIlJleW5vbGRzIiwgInNoaXAiOiAiU2VyZW5pdHkifQ"
    assert resulted_b64 == expected_b64


def test_prepare_jwt_1() -> None:
    app_id = "10465"
    utctime = datetime(
        year=2019,
        month=5,
        day=21,
        hour=7,
        minute=0,
        tzinfo=timezone.utc,
    )

    resulted_payload = prepare_gh_app_jwt(app_id, utctime)
    expected_payload = ".".join(
        [
            "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCJ9",
            "eyJpYXQiOiAxNTU4NDIyMDAwLCAiZXhwIjogMTU1ODQyMjA2MCwgImlzcyI6ICIxMDQ2NSJ9",
        ]
    )

    assert resulted_payload == expected_payload


def test_prepare_jwt_2() -> None:
    app_id = "368468"
    utctime = datetime(
        year=2023,
        month=8,
        day=28,
        hour=18,
        minute=14,
        second=31,
        microsecond=776991,
        tzinfo=timezone.utc,
    )

    resulted_payload = prepare_gh_app_jwt(app_id, utctime)
    expected_payload = ".".join(
        [
            "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCJ9",
            "eyJpYXQiOiAxNjkzMjQ2NDcxLCAiZXhwIjogMTY5MzI0NjUzMSwgImlzcyI6ICIzNjg0NjgifQ",
        ]
    )

    assert resulted_payload == expected_payload


def test_vault_wrap() -> None:
    with open("./tests/data/dummy_private_key.der", "rb") as akfh:
        app_key_der = akfh.read()

    with open("./tests/data/dummy_wrapping_public_key.pem", "rb") as pwkfh:
        wrapping_public_pem = pwkfh.read()

    wrapping_key = serialization.load_pem_public_key(wrapping_public_pem)
    if not isinstance(wrapping_key, rsa.RSAPublicKey):
        raise ValueError("Unexpected wrappingkey format")

    wrapped_app_key = vault_wrap_key(app_key_der, wrapping_key)

    unwrapped_app_der = vault_unwrap_key(wrapped_app_key)

    assert app_key_der == unwrapped_app_der
