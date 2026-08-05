"""
Database Schema DDL Configuration Module.

Maintains structural relational schema specifications for the AI-IDS persistence boundary.
Exposes atomic, idempotent table and performance index instantiation commands to safely 
initialize target structural assets during local application or test environment configurations.
"""

from __future__ import annotations

from typing import Final, List, Optional

from database.connection import DatabaseConnection, get_db_connection

# Primary Structural Relational Layout Declarations
_DDL_STATEMENTS: Final[List[str]] = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin',
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        last_login_at TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS models (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        file_path TEXT NOT NULL,
        model_type TEXT NOT NULL,
        version TEXT NOT NULL,
        features_count INTEGER,
        is_active INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        metadata TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        model_id INTEGER NOT NULL,
        source_ip TEXT,
        destination_ip TEXT,
        prediction INTEGER NOT NULL,
        confidence REAL NOT NULL,
        source_type TEXT NOT NULL,
        raw_features TEXT,
        severity TEXT NOT NULL DEFAULT '',
        attack_type TEXT NOT NULL DEFAULT '',
        attack_reason TEXT NOT NULL DEFAULT '',
        is_whitelisted INTEGER NOT NULL DEFAULT 0,
        is_blacklisted INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (model_id) REFERENCES models(id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_ip TEXT NOT NULL,
        threat_type TEXT NOT NULL,
        detection_id INTEGER NOT NULL,
        occurrences INTEGER NOT NULL DEFAULT 1,
        first_seen TEXT NOT NULL DEFAULT (datetime('now')),
        last_seen TEXT NOT NULL DEFAULT (datetime('now')),
        is_acknowledged INTEGER NOT NULL DEFAULT 0,
        telegram_sent INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (detection_id) REFERENCES detections(id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT NOT NULL,
        level TEXT NOT NULL,
        message TEXT NOT NULL,
        metadata TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS whitelist_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL UNIQUE,
        reason TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS blacklist_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL UNIQUE,
        reason TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS system_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cpu_percent REAL NOT NULL,
        ram_percent REAL NOT NULL,
        disk_percent REAL NOT NULL,
        network_sent_bytes INTEGER NOT NULL,
        network_recv_bytes INTEGER NOT NULL,
        active_threads INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS telegram_subscribers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id TEXT NOT NULL UNIQUE,
        label TEXT NOT NULL DEFAULT '',
        is_active INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'approved',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    """,
]

# Query Execution Performance Index Modifications
_INDEXES: Final[List[str]] = [
    "CREATE INDEX IF NOT EXISTS idx_detections_created_at ON detections(created_at);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);",
    "CREATE INDEX IF NOT EXISTS idx_logs_created_at ON logs(created_at);",
    "CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source);",
    "CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level);",
    "CREATE INDEX IF NOT EXISTS idx_logs_source_level ON logs(source, level);",
    "CREATE INDEX IF NOT EXISTS idx_whitelist_ip ON whitelist_ips(ip_address);",
    "CREATE INDEX IF NOT EXISTS idx_blacklist_ip ON blacklist_ips(ip_address);",
    "CREATE INDEX IF NOT EXISTS idx_telegram_subscribers_active ON telegram_subscribers(is_active);",
    "CREATE INDEX IF NOT EXISTS idx_telegram_subscribers_status ON telegram_subscribers(status);",
]


def initialize(db: Optional[DatabaseConnection] = None) -> None:
    """
    Executes structural relational data definition blocks within a protected connection context.

    Ensures baseline target system database layouts and performance index footprints are mapped
    idempotently without disturbing preexisting records.

    Args:
        db: Optional existing DatabaseConnection resource node proxy. Resolves standard
            process connection handle pool references if omitted.
    """
    connection: Final[DatabaseConnection] = db or get_db_connection()
    with connection.cursor() as cur:
        for table_statement in _DDL_STATEMENTS:
            cur.execute(table_statement)

        # Schema migrations for existing databases. MUST run before index
        # creation: indexes like idx_telegram_subscribers_status reference
        # migrated columns, so creating them first fails on legacy databases
        # whose tables predate the added columns.
        _migrate_add_severity(cur)
        _migrate_add_attack_type(cur)
        _migrate_add_attack_reason(cur)
        _migrate_add_is_whitelisted(cur)
        _migrate_add_is_blacklisted(cur)
        _migrate_add_subscriber_status(cur)

        for index_statement in _INDEXES:
            cur.execute(index_statement)


def _migrate_add_severity(cur) -> None:
    """Add severity column to detections table if missing (existing DB migration)."""
    try:
        cur.execute("PRAGMA table_info(detections)")
        columns = {row[1] for row in cur.fetchall()}
        if "severity" not in columns:
            cur.execute("ALTER TABLE detections ADD COLUMN severity TEXT NOT NULL DEFAULT ''")
    except Exception:
        pass  # Table may not exist yet; DDL will create it with the column.


def _migrate_add_attack_type(cur) -> None:
    """Add attack_type column to detections table if missing (existing DB migration)."""
    try:
        cur.execute("PRAGMA table_info(detections)")
        columns = {row[1] for row in cur.fetchall()}
        if "attack_type" not in columns:
            cur.execute("ALTER TABLE detections ADD COLUMN attack_type TEXT NOT NULL DEFAULT ''")
    except Exception:
        pass  # Table may not exist yet; DDL will create it with the column.


def _migrate_add_attack_reason(cur) -> None:
    try:
        cur.execute("PRAGMA table_info(detections)")
        columns = {row[1] for row in cur.fetchall()}
        if "attack_reason" not in columns:
            cur.execute("ALTER TABLE detections ADD COLUMN attack_reason TEXT NOT NULL DEFAULT ''")
    except Exception:
        pass


def _migrate_add_is_whitelisted(cur) -> None:
    try:
        cur.execute("PRAGMA table_info(detections)")
        columns = {row[1] for row in cur.fetchall()}
        if "is_whitelisted" not in columns:
            cur.execute("ALTER TABLE detections ADD COLUMN is_whitelisted INTEGER NOT NULL DEFAULT 0")
    except Exception:
        pass


def _migrate_add_is_blacklisted(cur) -> None:
    try:
        cur.execute("PRAGMA table_info(detections)")
        columns = {row[1] for row in cur.fetchall()}
        if "is_blacklisted" not in columns:
            cur.execute("ALTER TABLE detections ADD COLUMN is_blacklisted INTEGER NOT NULL DEFAULT 0")
    except Exception:
        pass


def _migrate_add_subscriber_status(cur) -> None:
    """Add status column to telegram_subscribers table if missing (existing DB migration)."""
    try:
        cur.execute("PRAGMA table_info(telegram_subscribers)")
        columns = {row[1] for row in cur.fetchall()}
        if "status" not in columns:
            cur.execute("ALTER TABLE telegram_subscribers ADD COLUMN status TEXT NOT NULL DEFAULT 'approved'")
    except Exception:
        pass