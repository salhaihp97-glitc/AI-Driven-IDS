"""
Unit and Integration Test Suite for Database Repositories and Bootstrap Initializers.

Validates CRUD transaction boundaries, duplicate constraints, structural logging 
indexing parameters, search operators, and administrative account seeding idempotency.
"""

from __future__ import annotations

from typing import Final

import pytest

from config.constants import LogLevel, LogSource, UserRole
from core.entities.log_entry import LogEntry
from core.entities.user import User
from core.exceptions import DuplicateRecordError, RecordNotFoundError
from database.bootstrap import run as bootstrap_database
from database.connection import DatabaseConnection
from repositories.log_repository import LogRepository
from repositories.user_repository import UserRepository


# =========================================================================
# Identity Control Management (User Repository) Tests
# =========================================================================

def test_user_add_and_get_by_id(db: DatabaseConnection) -> None:
    """
    Ensures user record storage pipelines return valid data structures with matching parameters.
    """
    repo: Final[UserRepository] = UserRepository(db)
    user = repo.add(User(username="alice", password_hash="hashed", role=UserRole.OPERATOR))

    fetched = repo.get_by_id(user.id)
    assert fetched is not None, "Persistence Fault: Inserted user profile could not be fetched by ID key token."
    assert fetched.username == "alice"
    assert fetched.role == UserRole.OPERATOR


def test_user_get_by_username(db: DatabaseConnection) -> None:
    """
    Validates unique string tracking queries return valid target records or return empty fallbacks.
    """
    repo: Final[UserRepository] = UserRepository(db)
    repo.add(User(username="bob", password_hash="hashed"))

    fetched = repo.get_by_username("bob")
    assert fetched is not None, "Query Fault: Failed to locate user profile by exact username match."
    assert fetched.username == "bob"
    assert repo.get_by_username("nonexistent") is None


def test_duplicate_username_raises(db: DatabaseConnection) -> None:
    """
    Guarantees unique constraint barriers successfully block conflicting user identifiers.
    """
    repo: Final[UserRepository] = UserRepository(db)
    repo.add(User(username="carol", password_hash="hashed"))
    
    with pytest.raises(DuplicateRecordError):
        repo.add(User(username="carol", password_hash="other_hash"))


def test_user_update(db: DatabaseConnection) -> None:
    """
    Verifies state modification routines alter active attributes securely across tables.
    """
    repo: Final[UserRepository] = UserRepository(db)
    user = repo.add(User(username="dave", password_hash="hashed"))
    
    user.username = "dave2"
    repo.update(user)

    updated_record = repo.get_by_id(user.id)
    assert updated_record is not None
    assert updated_record.username == "dave2"


def test_update_nonexistent_user_raises(db: DatabaseConnection) -> None:
    """
    Enforces structural checking blocks to reject mutation executions against missing entities.
    """
    repo: Final[UserRepository] = UserRepository(db)
    ghost = User(id=9999, username="ghost", password_hash="x")
    
    with pytest.raises(RecordNotFoundError):
        repo.update(ghost)


def test_user_delete(db: DatabaseConnection) -> None:
    """
    Confirms hard record purges successfully strip values out of structural tables.
    """
    repo: Final[UserRepository] = UserRepository(db)
    user = repo.add(User(username="erin", password_hash="hashed"))
    
    assert repo.delete(user.id) is True
    assert repo.get_by_id(user.id) is None


# =========================================================================
# Event Auditing (Log Repository) Tests
# =========================================================================

def test_log_add_and_search(db: DatabaseConnection) -> None:
    """
    Validates system message query components against exact levels and contextual substrings.
    """
    repo: Final[LogRepository] = LogRepository(db)
    repo.add(LogEntry(source=LogSource.SYSTEM, level=LogLevel.INFO, message="Service started"))
    repo.add(LogEntry(source=LogSource.ERROR, level=LogLevel.ERROR, message="Something failed"))

    all_logs = repo.get_all()
    assert len(all_logs) == 2

    errors_only = repo.search(level=LogLevel.ERROR)
    assert len(errors_only) == 1
    assert errors_only[0].message == "Something failed"

    text_search = repo.search(text="started")
    assert len(text_search) == 1


def test_log_count_total(db: DatabaseConnection) -> None:
    """Validates total count returns the correct number of log entries."""
    repo: Final[LogRepository] = LogRepository(db)
    repo.add(LogEntry(source=LogSource.SYSTEM, level=LogLevel.INFO, message="A"))
    repo.add(LogEntry(source=LogSource.ERROR, level=LogLevel.ERROR, message="B"))
    repo.add(LogEntry(source=LogSource.CAPTURE, level=LogLevel.WARNING, message="C"))
    assert repo.count() == 3


def test_log_count_by_level(db: DatabaseConnection) -> None:
    """Validates count-by-level grouping returns correct per-level totals."""
    repo: Final[LogRepository] = LogRepository(db)
    repo.add(LogEntry(source=LogSource.SYSTEM, level=LogLevel.INFO, message="i1"))
    repo.add(LogEntry(source=LogSource.SYSTEM, level=LogLevel.INFO, message="i2"))
    repo.add(LogEntry(source=LogSource.ERROR, level=LogLevel.ERROR, message="e1"))
    counts = repo.count_by_level()
    assert counts.get("INFO", 0) == 2
    assert counts.get("ERROR", 0) == 1


def test_log_count_by_source(db: DatabaseConnection) -> None:
    """Validates count-by-source grouping returns correct per-source totals."""
    repo: Final[LogRepository] = LogRepository(db)
    repo.add(LogEntry(source=LogSource.CAPTURE, level=LogLevel.INFO, message="c1"))
    repo.add(LogEntry(source=LogSource.CAPTURE, level=LogLevel.INFO, message="c2"))
    repo.add(LogEntry(source=LogSource.USER, level=LogLevel.INFO, message="u1"))
    counts = repo.count_by_source()
    assert counts.get("CAPTURE", 0) == 2
    assert counts.get("USER", 0) == 1


def test_log_count_filtered(db: DatabaseConnection) -> None:
    """Validates count with source and level filters."""
    repo: Final[LogRepository] = LogRepository(db)
    repo.add(LogEntry(source=LogSource.SYSTEM, level=LogLevel.INFO, message="A"))
    repo.add(LogEntry(source=LogSource.SYSTEM, level=LogLevel.ERROR, message="B"))
    repo.add(LogEntry(source=LogSource.USER, level=LogLevel.INFO, message="C"))
    assert repo.count(source=LogSource.SYSTEM) == 2
    assert repo.count(level=LogLevel.ERROR) == 1
    assert repo.count(source=LogSource.USER, level=LogLevel.ERROR) == 0


# =========================================================================
# Whitelist / Blacklist Repository Tests
# =========================================================================

def test_whitelist_count(db: DatabaseConnection) -> None:
    """Validates whitelist count returns the correct number of entries."""
    from repositories.whitelist_repository import WhitelistRepository
    from core.entities.ip_list_entry import WhitelistIP
    repo = WhitelistRepository(db)
    assert repo.count() == 0
    repo.add(WhitelistIP(ip_address="10.0.0.1", reason="r1"))
    repo.add(WhitelistIP(ip_address="10.0.0.2", reason="r2"))
    assert repo.count() == 2


def test_blacklist_count(db: DatabaseConnection) -> None:
    """Validates blacklist count returns the correct number of entries."""
    from repositories.blacklist_repository import BlacklistRepository
    from core.entities.ip_list_entry import BlacklistIP
    repo = BlacklistRepository(db)
    assert repo.count() == 0
    repo.add(BlacklistIP(ip_address="1.1.1.1", reason="r1"))
    assert repo.count() == 1


def test_whitelist_search_by_reason(db: DatabaseConnection) -> None:
    """Validates whitelist search matches on both ip_address and reason fields."""
    from repositories.whitelist_repository import WhitelistRepository
    from core.entities.ip_list_entry import WhitelistIP
    repo = WhitelistRepository(db)
    repo.add(WhitelistIP(ip_address="10.0.0.1", reason="DNS server"))
    repo.add(WhitelistIP(ip_address="10.0.0.2", reason="Web proxy"))
    results = repo.search("DNS")
    assert len(results) == 1
    assert results[0].ip_address == "10.0.0.1"


def test_blacklist_search_by_reason(db: DatabaseConnection) -> None:
    """Validates blacklist search matches on both ip_address and reason fields."""
    from repositories.blacklist_repository import BlacklistRepository
    from core.entities.ip_list_entry import BlacklistIP
    repo = BlacklistRepository(db)
    repo.add(BlacklistIP(ip_address="5.5.5.5", reason="Known scanner"))
    repo.add(BlacklistIP(ip_address="6.6.6.6", reason="C2 server"))
    results = repo.search("scanner")
    assert len(results) == 1
    assert results[0].ip_address == "5.5.5.5"


def test_ip_list_service_count_methods(db: DatabaseConnection) -> None:
    """Validates IpListService count_whitelist and count_blacklist."""
    from services.ip_list_service import IpListService
    from repositories.whitelist_repository import WhitelistRepository
    from repositories.blacklist_repository import BlacklistRepository
    from repositories.log_repository import LogRepository

    service = IpListService(
        whitelist_repo=WhitelistRepository(db),
        blacklist_repo=BlacklistRepository(db),
        log_repository=LogRepository(db),
    )
    assert service.count_whitelist() == 0
    assert service.count_blacklist() == 0

    service.add_to_whitelist("10.0.0.1", "trusted")
    service.add_to_blacklist("1.1.1.1", "malicious")
    assert service.count_whitelist() == 1
    assert service.count_blacklist() == 1


# =========================================================================
# Database Bootstrap Tests
# =========================================================================

def test_bootstrap_seeds_default_admin(db: DatabaseConnection) -> None:
    """
    Asserts initialization workflows safely provision secure default administrative users.
    """
    bootstrap_database(db)
    repo: Final[UserRepository] = UserRepository(db)

    admin = repo.get_by_username("admin")
    assert admin is not None, "Bootstrap Fault: Database initialization failed to seed root administrative entity."
    assert admin.role == UserRole.ADMIN
    assert admin.password_hash != "admin", "Security Risk: Administrative credentials written as plaintext elements."


def test_bootstrap_does_not_duplicate_admin_on_second_run(db: DatabaseConnection) -> None:
    """
    Validates bootstrap loop mutations remain entirely idempotent on consecutive invocations.
    """
    bootstrap_database(db)
    bootstrap_database(db)
    
    repo: Final[UserRepository] = UserRepository(db)
    assert repo.count() == 1, "Idempotency Mismatch: Sequential setup calls duplicated root catalog identities."