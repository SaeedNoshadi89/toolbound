"""Expiring tokens for cursors, approval requests and approval grants.

* :meth:`Signer.sign` makes integrity-protected tokens (HMAC-SHA256). Their
  payload is **readable** by anyone holding the token. Used for grants, which
  hold only ids and digests.
* :meth:`Signer.seal` makes authenticated **encrypted** tokens (AES-256-GCM).
  Used for cursors (which reach the model) and approval requests (which hold
  arguments and trusted bound values).

Both kinds expire and are bound to a purpose prefix, so a token minted for one
purpose is never accepted for another.

Key rotation: the secret may be a list. The first key signs and seals every new
token; every key in the list is accepted when a token is verified or unsealed. To
rotate, put the new key first and keep the old one until the longest-lived token
it issued has expired (approval requests at most 7 days), then drop it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Sequence
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import ConfigurationError

_MIN_SECRET_BYTES = 32
_DEFAULT_MAX_TOKEN = 8192
_NONCE_BYTES = 12
_MAX_KEYS = 8

Secret = bytes | str


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical_digest(value: Any) -> str:
    """SHA-256 over canonical JSON (sorted keys, no whitespace)."""
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def _key_bytes(secret: Secret) -> bytes:
    if isinstance(secret, str):
        key = secret.encode()
    elif isinstance(secret, (bytes, bytearray)):
        key = bytes(secret)
    else:
        raise ConfigurationError("Gateway secret must be bytes or str, or a list of them")
    if len(key) < _MIN_SECRET_BYTES:
        raise ConfigurationError("Gateway secret must be at least 32 bytes")
    return key


class _Keys:
    """The primitives derived from one secret (separate keys per primitive)."""

    def __init__(self, key: bytes) -> None:
        self.mac = hmac.new(key, b"toolbound/v1/mac", hashlib.sha256).digest()
        self.aead = AESGCM(hmac.new(key, b"toolbound/v1/seal", hashlib.sha256).digest())


class Signer:
    """Signs and seals small JSON payloads. Signed tokens look like
    ``<prefix>.<payload>.<mac>`` and are readable; sealed tokens are encrypted.

    ``secret`` is one secret or a list (current first, then previous ones still
    accepted). Each is at least 32 bytes.
    """

    def __init__(self, secret: Secret | Sequence[Secret] | None) -> None:
        if secret is None:
            raw = [secrets.token_bytes(32)]
            self.ephemeral = True
        else:
            items = [secret] if isinstance(secret, (str, bytes, bytearray)) else list(secret)
            if not items:
                raise ConfigurationError("Gateway secret list is empty")
            if len(items) > _MAX_KEYS:
                raise ConfigurationError(f"at most {_MAX_KEYS} gateway secrets are accepted")
            raw = [_key_bytes(item) for item in items]
            if len(set(raw)) != len(raw):
                raise ConfigurationError("Gateway secrets must be distinct")
            self.ephemeral = False
        self._keys = [_Keys(key) for key in raw]
        self._current = self._keys[0]

    def seal(self, prefix: str, payload: dict[str, Any], ttl_seconds: float) -> str:
        """Encrypt and authenticate ``payload``; the prefix is bound as associated data."""
        body = dict(payload)
        body["exp"] = int(time.time() + ttl_seconds)
        plaintext = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        nonce = secrets.token_bytes(_NONCE_BYTES)
        ciphertext = self._current.aead.encrypt(nonce, plaintext, prefix.encode())
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
        for keys in self._keys:
            try:
                plaintext = keys.aead.decrypt(
                    raw[:_NONCE_BYTES], raw[_NONCE_BYTES:], prefix.encode()
                )
            except InvalidTag:
                continue
            try:
                payload = json.loads(plaintext)
            except (ValueError, UnicodeDecodeError):
                return None
            return _unexpired(payload)
        return None

    def sign(self, prefix: str, payload: dict[str, Any], ttl_seconds: float) -> str:
        body = dict(payload)
        body["exp"] = int(time.time() + ttl_seconds)
        encoded = _b64(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
        mac = self._mac(self._current, prefix, encoded)
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
        if not any(
            hmac.compare_digest(self._mac(keys, prefix, parts[1]), parts[2]) for keys in self._keys
        ):
            return None
        try:
            payload = json.loads(_unb64(parts[1]))
        except (ValueError, UnicodeDecodeError):
            return None
        return _unexpired(payload)

    @staticmethod
    def _mac(keys: _Keys, prefix: str, encoded: str) -> str:
        digest = hmac.new(keys.mac, f"{prefix}.{encoded}".encode(), hashlib.sha256).digest()
        return _b64(digest[:24])

    def __repr__(self) -> str:
        return f"Signer(ephemeral={self.ephemeral}, keys={len(self._keys)})"


def _unexpired(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, dict) or not isinstance(payload.get("exp"), int):
        return None
    if payload["exp"] < time.time():
        return None
    return payload
