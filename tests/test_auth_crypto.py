"""Tests for envelope encryption used by the keystore."""
import os
import base64
import pytest

from illumio_mcp.auth.crypto import EnvelopeCipher, generate_kek, load_kek_from_env, MissingKEKError


def test_round_trip():
    kek = generate_kek()
    cipher = EnvelopeCipher(kek)
    blob = cipher.encrypt(b"PCE_API_SECRET_xyz_42", aad=b"user-42|https://idp.test/o")
    plaintext = cipher.decrypt(blob, aad=b"user-42|https://idp.test/o")
    assert plaintext == b"PCE_API_SECRET_xyz_42"


def test_decrypt_with_wrong_aad_fails():
    kek = generate_kek()
    cipher = EnvelopeCipher(kek)
    blob = cipher.encrypt(b"secret", aad=b"correct-aad")
    with pytest.raises(Exception):
        cipher.decrypt(blob, aad=b"wrong-aad")


def test_decrypt_with_wrong_kek_fails():
    cipher_a = EnvelopeCipher(generate_kek())
    cipher_b = EnvelopeCipher(generate_kek())
    blob = cipher_a.encrypt(b"secret", aad=b"x")
    with pytest.raises(Exception):
        cipher_b.decrypt(blob, aad=b"x")


def test_tampered_ciphertext_rejected():
    kek = generate_kek()
    cipher = EnvelopeCipher(kek)
    blob = bytearray(cipher.encrypt(b"secret", aad=b"x"))
    # Flip a byte deep inside the ciphertext
    blob[-5] ^= 0x01
    with pytest.raises(Exception):
        cipher.decrypt(bytes(blob), aad=b"x")


def test_each_encryption_uses_a_fresh_data_key_and_nonce():
    """Two encrypts of the same plaintext + AAD produce different ciphertexts."""
    kek = generate_kek()
    cipher = EnvelopeCipher(kek)
    a = cipher.encrypt(b"same", aad=b"x")
    b = cipher.encrypt(b"same", aad=b"x")
    assert a != b


def test_load_kek_from_env_happy_path(monkeypatch):
    raw = os.urandom(32)
    monkeypatch.setenv("MCP_KEK", base64.b64encode(raw).decode())
    kek = load_kek_from_env()
    assert kek == raw


def test_load_kek_from_env_missing_raises(monkeypatch):
    monkeypatch.delenv("MCP_KEK", raising=False)
    with pytest.raises(MissingKEKError):
        load_kek_from_env()


def test_load_kek_from_env_wrong_length_raises(monkeypatch):
    monkeypatch.setenv("MCP_KEK", base64.b64encode(b"only-16-bytes-aaa").decode())
    with pytest.raises(ValueError, match="32"):
        load_kek_from_env()
