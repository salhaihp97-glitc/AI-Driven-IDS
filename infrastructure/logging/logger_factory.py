"""
Logger Factory Infrastructure Module.

Establishes a centralized observability bootstrap layer for the AI-IDS system framework. 
Provisions structured log formatting, thread-safe handler initialization, auto-rotating 
file boundaries, and console streams to enforce uniform system diagnostics across all modules.

Windows-specific note:
    Streamlit launches multiple script-runner processes that can all hold an open handle
    on ``ai_ids.log``. When the size limit is hit, the stdlib ``RotatingFileHandler`` tries
    to rename the file to ``ai_ids.log.1`` while another process still has it open, which
    fails with ``PermissionError: [WinError 32]``. That exception is normally re-raised by
    the logging machinery as a noisy "--- Logging error ---" traceback and can leave the
    handler in a broken state. ``WindowsSafeRotatingFileHandler`` below retries the rename
    and, if the lock persists, defers rotation (appends to the current file) instead of
    crashing, so no messages are lost and no tracebacks flood the console.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Final

from config.settings import get_settings

# Thread Re-entrancy Lock for safe logging subsystem initialization
_config_lock: Final[threading.Lock] = threading.Lock()
_is_configured: bool = False

# Standard Production Layout Schemes
_LOG_FORMAT: Final[str] = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT: Final[str] = "%Y-%m-%d %H:%M:%S"

# Windows lock retry budget: locks (antivirus scans, sibling Streamlit processes) are
# usually held for only a few tens of milliseconds, so a short bounded retry avoids
# dropping a rotation that would otherwise succeed a moment later.
_ROLLOVER_RETRIES: Final[int] = 3
_ROLLOVER_RETRY_DELAY_S: Final[float] = 0.1


class WindowsSafeRotatingFileHandler(RotatingFileHandler):
    """
    A Windows-aware rotating file handler that tolerates transient file-lock failures.

    On Windows, another process can briefly hold an exclusive handle on the log file, so
    the rename performed during rollover raises ``PermissionError`` (WinError 32). The
    standard handler lets that exception bubble up, which Python's logging prints as a
    cryptic "--- Logging error ---" traceback and can abort further logging. This handler
    retries the rotation a few times and, if the file is still locked, keeps appending to
    the current file and defers rotation to the next cycle instead of failing.
    """

    def _perform_rotation(self) -> None:
        """Shuffles backup files and renames the active log into position (stdlib logic)."""
        for i in range(self.backupCount - 1, 0, -1):
            source = self.rotation_filename("%s.%d" % (self.baseFilename, i))
            destination = self.rotation_filename("%s.%d" % (self.baseFilename, i + 1))
            if os.path.exists(source):
                if os.path.exists(destination):
                    os.remove(destination)
                self.rotate(source, destination)

        newest_backup = self.rotation_filename(self.baseFilename + ".1")
        if os.path.exists(newest_backup):
            os.remove(newest_backup)
        self.rotate(self.baseFilename, newest_backup)

    def _warn_deferred_rotation(self) -> None:
        # Print directly to stderr (never through the logging tree) to avoid recursion.
        # ASCII-only text keeps the warning safe on any console code page.
        print(
            f"WARNING: Log rotation for '{self.baseFilename}' deferred - file locked "
            "by another process (WinError 32). Appending to the current file instead.",
            file=sys.stderr,
        )

    def doRollover(self) -> None:  # noqa: N802 (matches stdlib handler API)
        """
        Performs size-based log rotation, tolerating transient Windows file locks.

        If the active log file cannot be renamed because another process holds it open,
        the rotation is retried briefly and then deferred: the handler reopens the current
        file in append mode so subsequent messages keep flowing and nothing is lost.
        """
        if self.stream:
            self.stream.close()
            self.stream = None

        if self.backupCount > 0:
            try:
                for attempt in range(_ROLLOVER_RETRIES):
                    try:
                        self._perform_rotation()
                        break
                    except PermissionError:
                        if attempt < _ROLLOVER_RETRIES - 1:
                            time.sleep(_ROLLOVER_RETRY_DELAY_S)
                            continue
                        raise
            except PermissionError:
                # Windows lock still held: defer rotation, keep appending to the current file.
                self._warn_deferred_rotation()
                if not self.delay:
                    self.stream = self._open()
                return
            except OSError as exc:
                # Any other filesystem error during rotation: warn and continue appending
                # rather than surfacing a "--- Logging error ---" traceback.
                print(
                    f"WARNING: Log rotation for '{self.baseFilename}' skipped due to "
                    f"OSError({exc.errno}). Appending to the current file instead.",
                    file=sys.stderr,
                )
                if not self.delay:
                    self.stream = self._open()
                return

        if not self.delay:
            self.stream = self._open()


def _configure_root_logger() -> None:
    """
    Constructs and binds the top-level structured logging handlers under cross-thread protection.
    """
    global _is_configured
    
    if _is_configured:
        return

    with _config_lock:
        # Double-checked locking pattern to maintain thread safety
        if _is_configured:
            return

        settings = get_settings()
        root_logger = logging.getLogger("ai_ids")
        root_logger.setLevel(settings.log_level)
        
        # Prevent log bleeding into un-configured fallback system root handlers
        root_logger.propagate = False

        formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

        # Build Standard Out Console Stream Registry if enabled
        if settings.log_to_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            root_logger.addHandler(console_handler)

        # Ensure the destination logging repository exists on the filesystem
        logs_directory = Path(settings.logs_dir)
        logs_directory.mkdir(parents=True, exist_ok=True)

        # Build Persistent Rotating File System Registry.
        # delay=True avoids eagerly opening the file at import time, which reduces the
        # number of concurrent handles held by multiple Streamlit script-runner processes.
        log_file_path = logs_directory / "ai_ids.log"
        file_handler = WindowsSafeRotatingFileHandler(
            log_file_path,
            maxBytes=settings.log_file_max_bytes,
            backupCount=settings.log_file_backup_count,
            encoding="utf-8",
            delay=True,
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

        _is_configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Resolves a namespaced logging node tied directly to the core application hierarchy.

    Args:
        name: The target tracking descriptor namespace context (typically passing __name__).

    Returns:
        A fully configured, isolated Python Logger instance.
    """
    _configure_root_logger()
    
    # Clean redundant leading/trailing separators if module names are passed abnormally
    sanitized_name = name.strip(".")
    return logging.getLogger(f"ai_ids.{sanitized_name}")
