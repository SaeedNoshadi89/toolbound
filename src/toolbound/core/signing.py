"""Expiring tokens for cursors, approval requests and approval grants.

* :meth:`Signer.sign` makes integrity-protected tokens (HMAC-SHA256). Their
  payload is **readable** by anyone holding the token. Used for grants, which
  hold only ids and digests.
* :meth:`Signer.seal` makes authenticated **encrypted** tokens (AES-256-GCM).
  Used for cursors (which reach the model) and approval requests (which hold
  arguments and trusted bound values).

Both kinds expire and are bound to a purpose prefix, so a token minted for one
purpose is never accepted for another.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import ConfigurationError

_MIN_SECRET_BYTES = 32
_DEFAULT_MAX_TOKEN = 8192
_NONCE_BYTES = 12


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical_digest(value: Any) -> str:
    """SHA-256 over canonical JSON (sorted keys, no whitespace)."""
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


class Signer:
    """Signs small JSON payloads. Tokens look like ``<prefix>.<payload>.<mac>``.

    Tokens are integrity-protected, not encrypted: never put secrets in them.
    """

    def __init__(self, secret: bytes | str | None) -> None:
        if secret is None:
            key = secrets.token_bytes(32)
            self.ephemeral = True
        else:
            key = secret.encode() if isinstance(secret, str) else bytes(secret)
            self.ephemeral = False
        if len(key) < _MIN_SECRET_BYTES:
            raise ConfigurationError("Gateway secret must be at least 32 bytes")
        self._key = key
        # Separate keys per primitive, derived from the configured secret.
        self._mac_key = hmac.new(key, b"toolbound/v1/mac", hashlib.sha256).digest()
        self._aead = AESGCM(hmac.new(key, b"toolbound/v1/seal", hashlib.sha256).digest())

    def seal(self, prefix: str, payload: dict[str, Any], ttl_seconds: float) -> str:
        """Encrypt and authenticate ``payload``; the prefix is bound as associated data."""
        body = dict(payload)
        body["exp"] = int(time.time() + ttl_seconds)
        plaintext = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        nonce = secrets.token_bytes(_NONCE_BYTES)
        ciphertext = self._aead.encrypt(nonce, plaintext, prefix.encode())
        return f"{prefix}.{_b64(nonce + ciphertext)}"

    def unseal(
        self, prefix: str, token: Any, *, max_length: int = _DEFAULT_MAX_TOKEN
    ) -> dict[str, Any] | None:
        """Return the payload, or None if malformed, forged, for another purpose, or expired."""
        if not isinstance(token, str) or len(token) > max_length:
            return None
        head, sep, data = token.partition(".")
        if not sep or head != prefix or "." in data:
            return None
        try:
            raw = _unb64(data)
        except ValueError:
            return None
        if len(raw) <= _NONCE_BYTES:
            return None
        try:
            plaintext = self._aead.decrypt(raw[:_NONCE_BYTES], raw[_NONCE_BYTES:], prefix.encode())
            payload = json.loads(plaintext)
        except (InvalidTag, ValueError, UnicodeDecodeError):
            return None
        return _unexpired(payload)

    def sign(self, prefix: str, payload: dict[str, Any], ttl_seconds: float) -> str:
        body = dict(payload)
        body["exp"] = int(time.time() + ttl_seconds)
        encoded = _b64(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
        mac = self._mac(prefix, encoded)
        return f"{prefix}.{encoded}.{mac}"

    def verify(
        self, prefix: str, token: Any, *, max_length: int = _DEFAULT_MAX_TOKEN
    ) -> dict[str, Any] | None:
        """Return the payload, or None if the token is malformed, forged or expired."""
        if not isinstance(token, str) or len(token) > max_length:
            return None
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != prefix:
            return None
        expected = self._mac(prefix, parts[1])
        if not hmac.compare_digest(expected, parts[2]):
            return None
        try:
            payload = json.loads(_unb64(parts[1]))
        except (ValueError, UnicodeDecodeError):
            return None
        return _unexpired(payload)

    def _mac(self, prefix: str, encoded: str) -> str:
        digest = hmac.new(self._mac_key, f"{prefix}.{encoded}".encode(), hashlib.sha256).digest()
        return _b64(digest[:24])

    def __repr__(self) -> str:
        return f"Signer(ephemeral={self.ephemeral})"


def _unexpired(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, dict) or not isinstance(payload.get("exp"), int):
        return None
    if payload["exp"] < time.time():
        return None
    return payload
