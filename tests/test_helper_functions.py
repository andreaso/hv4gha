"""Testing of helper functions"""

# pylint: disable=missing-function-docstring

import json

from hv4gha.helpers import b64str, private_pem_to_der


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
