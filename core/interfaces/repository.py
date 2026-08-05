"""
Generic Repository Interface Module.

Establishes the foundational CRUD structural contract for behavioral repositories 
adhering to the Dependency Inversion Principle. Abstractly decoupling domain services from 
underlying infrastructure engines or physical relational persistence layers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, List, Optional, TypeVar

# Type Variable representing a bound Domain Entity Instance
TEntity = TypeVar("TEntity")


class IRepository(ABC, Generic[TEntity]):
    """
    Generic Data Access Layer Abstract Interface Contract.
    
    Defines foundational collection-oriented interaction rules that concrete database mapping 
    adapters (e.g., SQLite repositories) must implement uniformly.
    """

    @abstractmethod
    def add(self, entity: TEntity) -> TEntity:
        """
        Commits a newly instantiated domain entity to persistent structural storage.

        Args:
            entity: The unbound domain entity payload to write.

        Returns:
            The bound domain entity record appended with its unique backend identifier.
        """

    @abstractmethod
    def get_by_id(self, entity_id: int) -> Optional[TEntity]:
        """
        Queries storage to resolve a target entity matching the provided primary identifier.

        Args:
            entity_id: The primary identifier key value to search.

        Returns:
            The hydrated entity object if located, otherwise None.
        """

    @abstractmethod
    def get_all(self) -> List[TEntity]:
        """
        Retrieves the entire active un-filtered index collection for the entity context.

        Returns:
            A list containing all retrieved domain entity records.
        """

    @abstractmethod
    def update(self, entity: TEntity) -> TEntity:
        """
        Synchronizes mutable property mutations on an existing tracking entity back to storage.

        Args:
            entity: The modified domain entity instance reflecting target changes.

        Returns:
            The synchronized domain entity confirmation state.
        """

    @abstractmethod
    def delete(self, entity_id: int) -> bool:
        """
        Removes a target entity record permanently from structural storage boundaries.

        Args:
            entity_id: The primary identifier key of the targeted record to purge.

        Returns:
            True if the transaction resulted in a modified row index mutation, otherwise False.
        """