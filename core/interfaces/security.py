"""
Security Interfaces Module.

Establishes the boundary abstractions for application security workflows, adhering to the 
Dependency Inversion Principle. Decouples core identity management logic from specific 
low-level cryptographic hashing primitives and library dependencies.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class IPasswordHasher(ABC):
    """
    Cryptographic password hashing interface contract.
    
    Defines the standard lifecycle signatures required by authentication adapters to execute
    secure one-way password derivations and verification matches.
    """

    @abstractmethod
    def hash(self, plain_password: str) -> str:
        """
        Derives a secure, cryptographically salted one-way hash from a plaintext string.

        Args:
            plain_password: The unhashed target password value.

        Returns:
            The securely encoded cryptographic hash value.
        """

    @abstractmethod
    def verify(self, plain_password: str, password_hash: str) -> bool:
        """
        Validates an unverified plaintext string against an existing stored secure hash.

        Args:
            plain_password: The unhashed target password to evaluate.
            password_hash: The baseline verified cryptographic hash to match against.

        Returns:
            True if the plaintext credentials match the cryptographic signature, otherwise False.
        """