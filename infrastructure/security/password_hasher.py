"""
Bcrypt Cryptographic Security Infrastructure Module.

Implements the structural IPasswordHasher adapter interface utilizing the bcrypt library primitive.
Isolates low-level key derivation scheduling and salt generation mechanisms into a swappable, 
thread-safe infrastructure block.
"""

from __future__ import annotations

from typing import Final, Optional

import bcrypt

from config.settings import get_settings
from core.interfaces.security import IPasswordHasher


class BcryptPasswordHasher(IPasswordHasher):
    """
    Adapter component executing adaptive one-way hashing algorithms.
    
    Provides runtime string encoding, automated cryptographic salting, and defensive verification 
    routines to securely store identity profiles while preventing brute-force attacks.
    """

    def __init__(self, rounds: Optional[int] = None) -> None:
        """
        Initializes the cryptographic provider, establishing algorithm execution work factors.
        """
        settings = get_settings()
        self._rounds: Final[int] = rounds or settings.bcrypt_rounds

    def hash(self, plain_password: str) -> str:
        """
        Derives a cryptographically salted one-way hash using the configured work factor.

        Args:
            plain_password: The raw target credentials string to transform.

        Returns:
            A securely encoded UTF-8 printable string representation of the password hash.
        """
        salt: Final[bytes] = bcrypt.gensalt(rounds=self._rounds)
        hashed_bytes: Final[bytes] = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
        return hashed_bytes.decode("utf-8")

    def verify(self, plain_password: str, password_hash: str) -> bool:
        """
        Validates a plaintext credential string against a known valid cryptographic signature.
    
        Gracefully intercept parsing errors stemming from malformed or corrupted database signatures,
        ensuring an invalid authorization evaluation occurs instead of a runtime application crash.
    
        Args:
            plain_password: The unverified candidate credentials string.
            password_hash: The target verification signature string extracted from storage.
    
        Returns:
            True if the credentials string matches the target cryptographic hash, otherwise False.
        """
        if plain_password is None or password_hash is None:
            return False
        try:
            return bcrypt.checkpw(
                plain_password.encode("utf-8"),
                password_hash.encode("utf-8")
            )
        except (TypeError, ValueError):
            return False