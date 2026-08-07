"""
Database Connection Management Module.

Provides a thread-isolated persistence broker wrapping low-level relational storage connections. 
Leverages dynamic thread-local storage proxies to ensure absolute structural safety during 
high-frequency parallel operations while isolating downstream data mappings from direct 
third-party engine library coupling.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional, Final, Set

from config.settings import get_settings
from core.exceptions import DatabaseError

# Global Thread Re-entrancy Lock for safe initial singleton instantiation
_singleton_lock: Final[threading.Lock] = threading.Lock()


class DatabaseConnection:
    """
    Thread-safe connection coordinator proxy managing transactional persistence boundaries.
    
    Configures underlying runtime optimizations, registers structural column mappings, 
    and provisions thread-isolated session pools using localized resource environments.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        """
        Initializes the persistence broker mapping and registers isolated local context nodes.
        """
        settings = get_settings()
        self._db_path: Final[str] = str(db_path or settings.database_path)
        self._local: Final[threading.local] = threading.local()
        self._connections: Final[Set[sqlite3.Connection]] = set()
        self._connections_lock: Final[threading.Lock] = threading.Lock()
        self._closed: bool = False

    def _get_connection(self) -> sqlite3.Connection:
        """
        Resolves or builds an active connection context bounded to the current executing thread space.
        
        Raises:
            DatabaseError: If connection configurations fail or path assets are unreachable.
            DatabaseError: If the connection pool has been terminated via ``close()``.
        """
        if self._closed:
            raise DatabaseError(
                "Persistence boundary has been closed. Rejecting operation on a "
                "terminated DatabaseConnection — restart the service to regain access."
            )
        if getattr(self._local, "connection", None) is None:
            try:
                # Enforce safe cross-thread evaluation and setup exact type resolution parsing
                conn = sqlite3.connect(
                    self._db_path,
                    check_same_thread=False,
                    detect_types=sqlite3.PARSE_DECLTYPES,
                )
                conn.row_factory = sqlite3.Row
                
                # Apply structural system engine configuration tuning parameter optimizations
                conn.execute("PRAGMA foreign_keys = ON;")
                conn.execute("PRAGMA journal_mode = WAL;")
                
                with self._connections_lock:
                    self._connections.add(conn)
                self._local.connection = conn
            except sqlite3.Error as exc:
                raise DatabaseError(f"Failed to establish persistent storage link at '{self._db_path}': {exc}") from exc
                
        return self._local.connection

    @contextmanager
    def cursor(self) -> Iterator[sqlite3.Cursor]:
        """
        Context-managed transaction factory worker yielding a database query execution handle.
        
        Commits all database adjustments upon code boundary success, and executes atomicity 
        rollbacks upon query runtime faults.
        
        Raises:
            sqlite3.IntegrityError: Bypassed up directly to allow semantic repository logic handling.
            DatabaseError: Standard wrapped operational persistence layer exception.
        """
        conn: Final[sqlite3.Connection] = self._get_connection()
        cur: Final[sqlite3.Cursor] = conn.cursor()
        try:
            yield cur
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            raise
        except sqlite3.Error as exc:
            conn.rollback()
            raise DatabaseError(f"Database transaction aborted due to operation fault: {exc}") from exc
        finally:
            cur.close()

    def close(self) -> None:
        """
        Terminates every active connection registered across all executing threads.
        """
        with self._connections_lock:
            conns = list(self._connections)
            self._connections.clear()
            self._closed = True
        for conn in conns:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        self._local.connection = None


# Central Global Process Repository Instance Reference
_db_instance: Optional[DatabaseConnection] = None


def get_db_connection() -> DatabaseConnection:
    """
    Thread-safe process factory manager resolving the active DatabaseConnection singleton instance.
    """
    global _db_instance
    if _db_instance is None:
        with _singleton_lock:
            if _db_instance is None:
                _db_instance = DatabaseConnection()
    return _db_instance