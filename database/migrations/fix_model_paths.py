"""
Migration: Normalise model file paths in the database to store only filenames.

Previously, model paths were stored as absolute Windows paths from another machine
(e.g. C:\\Users\\salh\\Desktop\\...). This migration strips those down to just the
filename so that path resolution is always handled dynamically via
C{config.settings.Settings.resolve_model_path()}.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
from typing import Final

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Ensure workspace root is on sys.path for local imports
WORKSPACE_ROOT: Final[Path] = Path(__file__).resolve().parent.parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from config.settings import Settings, get_settings
from database.connection import get_db_connection
from database.schema import initialize


def run() -> int:
    """
    Executes the model path migration.

    Iterates over every record in the C{models} table, extracts the filename
    from the stored path, and updates the record.  Also verifies the file
    actually exists under the project's C{models/} directory.

    Returns:
        Number of records updated.
    """
    initialize()
    settings: Final[Settings] = get_settings()
    db = get_db_connection()
    updated: int = 0

    with db.cursor() as cur:
        rows = cur.execute("SELECT id, file_path, name FROM models").fetchall()

        for row in rows:
            model_id, file_path, name = row
            filename: str = Path(file_path).name

            resolved = settings.resolve_model_path(filename)
            if not resolved.exists():
                print(
                    f"[WARN] Model '{name}' (id={model_id}): file '{resolved}' not found. "
                    f"Storing filename '{filename}' anyway."
                )
            else:
                print(
                    f"[OK] Model '{name}' (id={model_id}): "
                    f"'{file_path}' -> '{filename}' (resolves to '{resolved}')"
                )

            cur.execute(
                "UPDATE models SET file_path = ? WHERE id = ?",
                (filename, model_id),
            )
            updated += 1

    print(f"\nMigration complete. {updated} model record(s) updated.")
    return updated


if __name__ == "__main__":
    run()
