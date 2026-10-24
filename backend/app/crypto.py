from __future__ import annotations

import base64
import hashlib
import hmac

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

PREFIX = "enc:v1:"


class SecretBox:
    """Encrypts with the first key; decrypts and matches HMACs with any key."""

    def __init__(self, master: str, *fallbacks: str):
        masters = list(dict.fromkeys(item for item in (master, *fallbacks) if item))
        if not masters:
            raise ValueError("SecretBox needs a key")
        self._peppers = [hashlib.sha256(item.encode("utf-8")).digest() for item in masters]
        self._fernet = MultiFernet([Fernet(base64.urlsafe_b64encode(digest)) for digest in self._peppers])

    def encrypt(self, plaintext: str) -> str:
        token = self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")
        return f"{PREFIX}{token}"

    def decrypt(self, value: str) -> str:
        if not value.startswith(PREFIX):
            return value
        try:
            return self._fernet.decrypt(value[len(PREFIX) :].encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("Unable to decrypt secret") from exc

    def hmac_hex(self, value: str) -> str:
        return self._hmac(self._peppers[0], value)

    def hmac_candidates(self, value: str) -> list[str]:
        return [self._hmac(pepper, value) for pepper in self._peppers]

    @staticmethod
    def _hmac(pepper: bytes, value: str) -> str:
        return hmac.new(pepper, value.encode("utf-8"), hashlib.sha256).hexdigest()
