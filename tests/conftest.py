"""
Global Pytest Shared Test Configuration and Fixture Module.

Provides isolated, ephemeral infrastructure components for unit and integration testing. 
Generates an independent, short-lived SQLite database file instance on the local filesystem 
for each distinct execution thread to prevent cross-test data contamination.
"""

from __future__ import annotations

import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Final

import pytest

from database import schema
from database.connection import DatabaseConnection


@pytest.fixture(scope="function")
def db() -> Generator[DatabaseConnection, None, None]:
    """
    Spins up an ephemeral filesystem sandbox directory containing an isolated SQLite database.

    Automatically maps target tables via the system schema bootstrap routines, yields the active 
    connection context to the requesting test runtime, and cleans up resource handles upon 
    test completion.

    Yields:
        A pristine, pre-initialized DatabaseConnection engine instance.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path: Final[Path] = Path(tmp_dir) / "test_ai_ids.db"
        connection = DatabaseConnection(db_path=db_path)
        
        # Build clean structural relational table assets prior to yielding control
        schema.initialize(connection)
        
        yield connection
        
        # Explicitly terminate connection channels before filesystem contexts erase the parent folder
        connection.close()


@pytest.fixture(autouse=True)
def _stub_telegram_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Prevents the test suite from issuing real outbound HTTP calls to the
    Telegram Bot API.

    The ``Container`` notifier falls back to the real ``.env`` bot credentials
    when no runtime override is persisted, which would otherwise cause every
    attack-detection test to push live alerts to the configured chat and leave
    fire-and-forget daemon threads racing with ephemeral temp-file cleanup on
    Windows.  Returning a synthetic HTTP 200 keeps delivery logic fully
    exercised while eliminating network I/O and the resulting flakiness.

    Unit tests that assert low-level transport behaviour still control the
    attribute directly via ``unittest.mock.patch`` on the same module path,
    which overrides this stub for the duration of those tests.
    """
    import types

    def _stub_post(*args: object, **kwargs: object) -> types.SimpleNamespace:
        return types.SimpleNamespace(
            status_code=200,
            text="stubbed",
            json=lambda: {"ok": True, "result": {}},
        )

    monkeypatch.setattr(
        "infrastructure.notifications.telegram_notifier.requests.post",
        _stub_post,
    )


@pytest.fixture(autouse=True)
def _patch_model_path_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Overrides Settings.resolve_model_path so that ModelLoader tests can use
    temporary file paths directly instead of requiring files inside the
    configured *models_dir*.
    """
    monkeypatch.setattr(
        "config.settings.Settings.resolve_model_path",
        staticmethod(lambda p: Path(p)),
    )


@pytest.fixture(autouse=True)
def _patch_model_loader_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Also patches the *Settings* reference already imported inside
    *ml.model_loader* so the override is visible at the call site.
    """
    monkeypatch.setattr(
        "ml.model_loader.Settings.resolve_model_path",
        staticmethod(lambda p: Path(p)),
    )
