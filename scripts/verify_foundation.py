"""
System Architecture Foundation Verification Script.

Serves as an independent CLI sanity-checking gateway designed to isolate and thoroughly validate 
the core underlying infrastructure layers (configuration variables, database contexts, and relational 
repositories) without spawning the overhead of a Streamlit frontend loop.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Final

# Resolve systemic workspace boundary paths dynamically prior to loading local submodules
WORKSPACE_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from config.settings import Settings, get_settings
from database.bootstrap import run as bootstrap_database
from infrastructure.logging.logger_factory import get_logger
from repositories.log_repository import LogRepository
from repositories.user_repository import UserRepository

logger = get_logger("app")


def main() -> None:
    """
    Executes structural integration evaluation routines to verify foundation-level system readiness.
    """
    settings: Final[Settings] = get_settings()
    logger.info("Initializing system architecture diagnostics (env=%s, debug=%s)", settings.app_env, settings.debug)

    # Initialize physical storage structures and database table definitions
    bootstrap_database()

    # Instantiate targeted core repositories to verify baseline database bindings
    user_repo: Final[UserRepository] = UserRepository()
    log_repo: Final[LogRepository] = LogRepository()

    # Capture absolute baseline statistics to verify access boundaries
    user_count: Final[int] = user_repo.count()
    historical_logs: Final[int] = len(log_repo.get_all())

    print("=" * 60)
    print("AI-IDS - Foundation Layer Integration Diagnostic Summary")
    print("=" * 60)
    print(f"Target Database Endpoint : {settings.database_path}")
    print(f"Registered System Users  : {user_count}")
    print(f"Persistent Event Logs    : {historical_logs}")
    print("Verification Successful: Base architectural frameworks are ready.")
    print("=" * 60)


if __name__ == "__main__":
    main()