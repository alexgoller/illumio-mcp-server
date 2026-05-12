"""Envelope encryption for the per-user PCE keystore.

Two-tier:
  - Each record has a fresh 32-byte AES-256 data key (DK).
  - The DK is encrypted ("wrapped") by the KEK loaded from MCP_KEK at startup.

Wire format (single bytes blob):
  nonce_dk(12) || dk_ciphertext(48) || nonce_payload(12) || payload_ciphertext(N+16)
                                                            \\-- includes GCM tag --/

Both layers use AES-256-GCM with AAD binding. Tampering anywhere is detected.

KEK rotation is not implemented in this phase but the layout supports it: rotate
KEK, re-wrap each row's `dk_ciphertext` (no payload re-encryption needed).
"""
from __future__ import annotations

import base64
import os
from secrets import token_bytes

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class MissingKEKError(RuntimeError):
    """Raised when MCP_KEK is not set and DEV_INSECURE is off."""


_KEY_BYTES = 32      # AES-256
_NONCE_BYTES = 12    # standard for GCM


def generate_kek() -> bytes:
    """Return 32 random bytes suitable for use as a KEK."""
    return token_bytes(_KEY_BYTES)


def load_kek_from_env() -> bytes:
    """Read base64-encoded 32-byte KEK from MCP_KEK. Raise on absence or wrong length."""
    raw = os.getenv("MCP_KEK")
    if not raw:
        raise MissingKEKError(
            "MCP_KEK env var is required (32-byte base64 KEK). "
            "Generate with: python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())'"
        )
    try:
        kek = base64.b64decode(raw)
    except Exception as e:
        raise ValueError(f"MCP_KEK is not valid base64: {e}") from e
    if len(kek) != _KEY_BYTES:
        raise ValueError(f"MCP_KEK must decode to exactly 32 bytes, got {len(kek)}")
    return kek


class EnvelopeCipher:
    """AES-256-GCM envelope cipher. Stateless after construction."""

    def __init__(self, kek: bytes):
        if len(kek) != _KEY_BYTES:
            raise ValueError(f"KEK must be {_KEY_BYTES} bytes, got {len(kek)}")
        self._kek = AESGCM(kek)

    def encrypt(self, plaintext: bytes, *, aad: bytes) -> bytes:
        """Encrypt with a fresh data key, wrap the data key under KEK, return the
        single concatenated blob."""
        dk = token_bytes(_KEY_BYTES)
        nonce_dk = token_bytes(_NONCE_BYTES)
        dk_ciphertext = self._kek.encrypt(nonce_dk, dk, aad)

        nonce_payload = token_bytes(_NONCE_BYTES)
        payload_ciphertext = AESGCM(dk).encrypt(nonce_payload, plaintext, aad)
        return nonce_dk + dk_ciphertext + nonce_payload + payload_ciphertext

    def decrypt(self, blob: bytes, *, aad: bytes) -> bytes:
        """Inverse of `encrypt`. Raises on any integrity failure."""
        # Layout: 12 + 48 + 12 + (N+16). We know dk_ciphertext is 48 bytes
        # (32-byte DK + 16-byte GCM tag).
        if len(blob) < _NONCE_BYTES + 48 + _NONCE_BYTES + 16:
            raise ValueError("ciphertext too short")
        nonce_dk = blob[:_NONCE_BYTES]
        dk_ciphertext = blob[_NONCE_BYTES:_NONCE_BYTES + 48]
        nonce_payload = blob[_NONCE_BYTES + 48:_NONCE_BYTES + 48 + _NONCE_BYTES]
        payload_ciphertext = blob[_NONCE_BYTES + 48 + _NONCE_BYTES:]
        dk = self._kek.decrypt(nonce_dk, dk_ciphertext, aad)
        return AESGCM(dk).decrypt(nonce_payload, payload_ciphertext, aad)
