"""
Explore current system state for UAT testing.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is on sys.path
_proj_root = Path(__file__).resolve().parent.parent
if str(_proj_root) not in sys.path:
    sys.path.insert(0, str(_proj_root))

from database.connection import DatabaseConnection
from database import schema

db_path = Path("data/ai_ids.db")
log_path = Path("logs/ai_ids.log")
models_dir = Path("models")

print("=== FILE SYSTEM STATE ===")
print(f"DB exists: {db_path.exists()}, size: {db_path.stat().st_size if db_path.exists() else 0} bytes")
print(f"Log exists: {log_path.exists()}, size: {log_path.stat().st_size if log_path.exists() else 0} bytes")
print(f"Models dir exists: {models_dir.exists()}")
if models_dir.exists():
    print(f"Models: {[f.name for f in models_dir.iterdir()]}")

print()
print("=== DATABASE TABLES ===")

conn = DatabaseConnection(db_path=db_path)
schema.initialize(conn)

with conn.cursor() as cur:
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row["name"] for row in cur.fetchall()]
    print(f"Tables: {tables}")

    for t in tables:
        cur.execute(f"SELECT COUNT(*) as c FROM {t}")
        count = cur.fetchone()["c"]
        print(f"  {t}: {count} rows")

        if count > 0 and t in ("detections", "alerts", "users", "models", "system_metrics"):
            cur.execute(f"SELECT * FROM {t} LIMIT 3")
            for row in cur.fetchall():
                print(f"    {dict(row)}")

conn.close()

print()
print("=== LOG FILE (last 30 lines) ===")
if log_path.exists():
    with open(log_path, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
        for line in lines[-30:]:
            print(line.rstrip())
else:
    print("(no log file)")
