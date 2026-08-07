"""
Application Settings Module.

Centralized state container handling configuration injection parsing out of environment 
variables and environment configuration files (.env). Enforces strict single-point-of-access 
rules over environmental variables to decouple system state components from host system layers.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # Fallback seamlessly if python-dotenv is not deployed in host workspace parameters
    pass

# Root Directory Context Mappings
BASE_DIR: Final[Path] = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Canonical environment variable defaults — the single source of truth.
# Both the runtime ``Settings`` and the CLI setup wizard (``cli.py``) derive
# their defaults from this mapping, guaranteeing that a freshly generated
# ``.env`` file and an unconfigured process behave identically.
# ---------------------------------------------------------------------------
DEFAULT_ENV_VARS: Final[dict[str, str]] = {
    "AI_IDS_ENV": "development",
    "AI_IDS_DEBUG": "true",
    "AI_IDS_SECRET_KEY": "",
    "AI_IDS_DB_PATH": "data/ai_ids.db",
    "AI_IDS_MODELS_DIR": "models",
    "AI_IDS_LOGS_DIR": "logs",
    "AI_IDS_CAPTURED_FLOWS_DIR": "data",
    "AI_IDS_LOG_LEVEL": "INFO",
    "AI_IDS_LOG_TO_CONSOLE": "true",
    "AI_IDS_LOG_MAX_BYTES": "5000000",
    "AI_IDS_LOG_BACKUP_COUNT": "5",
    "AI_IDS_BCRYPT_ROUNDS": "12",
    "AI_IDS_TELEGRAM_BOT_TOKEN": "",
    "AI_IDS_TELEGRAM_CHAT_ID": "",
    "AI_IDS_ALERT_WINDOW_MINUTES": "10",
    "AI_IDS_FLOW_IDLE_TIMEOUT": "15",
    "AI_IDS_LIVE_CAPTURE_MODE": "cicflowmeter",
    "AI_IDS_CICFLOWMETER_INTERVAL_SECONDS": "10",
    "AI_IDS_CICFLOWMETER_EXPIRED_UPDATE_SECONDS": "10",
    "AI_IDS_LIVE_FLUSH_POLL_SECONDS": "2.0",
    "AI_IDS_LIVE_SHUTDOWN_TIMEOUT_SECONDS": "5.0",
    "AI_IDS_LIVE_MAX_RECENT_FLOWS": "500",
    "AI_IDS_LIVE_UI_POLL_LOOPS": "60",
    "AI_IDS_LIVE_UI_POLL_INTERVAL": "1.0",
    "AI_IDS_LIVE_FLOWS_LIMIT": "200",
    "AI_IDS_FLOW_ACTIVITY_TIMEOUT_SECONDS": "5.0",
    "AI_IDS_MONITORING_INTERVAL": "5",
    "AI_IDS_FLOW_EXTRACTOR": "cicflowmeter",
    "AI_IDS_CSV_ANALYSIS_MAX_ROWS": "0",
    "AI_IDS_CSV_ANALYSIS_CHUNK_SIZE": "10000",
    "AI_IDS_ML_DECISION_THRESHOLD": "0.5",
    "AI_IDS_ML_MIN_FEATURE_COVERAGE": "0.5",
    # --- Macro-Flow Assembly (pure data pipeline -> feeds the model only) ---
    # Disabled by default: the deployed per-flow CICIDS2017 models (RF V3 / XGB V2)
    # are trained on individual flow rows, so aggregation changes the feature space.
    # Turn on only for models trained on macro-aggregate features.
    "AI_IDS_MACRO_FLOW_ENABLED": "false",
    "AI_IDS_MACRO_FLOW_WINDOW_SECONDS": "10.0",
    "AI_IDS_MACRO_FLOW_KEY_FIELDS": "src_ip,dst_ip,dst_port,protocol",
    "AI_IDS_MACRO_FLOW_MIN_MEMBERS": "2",
}

# Placeholder secret used when no key has been configured yet. It is deliberately
# NOT stored in ``DEFAULT_ENV_VARS`` so the setup wizard treats an empty value as
# "generate a new key" while the runtime still refuses to boot with a truly empty key.
INSECURE_SECRET_KEY: Final[str] = "dev-insecure-secret-change-me"


def _get_bool(name: str, default: bool) -> bool:
    """
    Safely resolves environment variables into standardized boolean data structures.
    """
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    """
    Enforces strict structural string conversions down to pure integer boundaries.
    """
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _get_float(name: str, default: float) -> float:
    """
    Enforces strict structural string conversions down to pure floating-point boundaries.
    """
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _env(name: str) -> str:
    """Resolves a raw environment value against the canonical defaults table."""
    return os.getenv(name, DEFAULT_ENV_VARS.get(name, ""))


def _env_bool(name: str) -> bool:
    """Canonical default for a boolean-typed environment variable."""
    return _env(name).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str) -> int:
    """Canonical default for an integer-typed environment variable."""
    try:
        return int(_env(name))
    except ValueError:
        return 0


def _env_float(name: str) -> float:
    """Canonical default for a floating-point-typed environment variable."""
    try:
        return float(_env(name))
    except ValueError:
        return 0.0


def _env_path(name: str) -> Path:
    """
    Resolves a path-typed environment variable, anchoring relative references to
    the project root so behaviour does not depend on the caller's working directory.
    """
    value = _env(name)
    path = Path(value)
    return path if path.is_absolute() else BASE_DIR / path


@dataclass(frozen=True)
class Settings:
    """
    Immutable process-wide global application configuration data container schema.
    """
    # --- Physical System Path Enforcements ---
    base_dir: Path = BASE_DIR
    database_path: Path = field(default_factory=lambda: _env_path("AI_IDS_DB_PATH"))
    models_dir: Path = field(default_factory=lambda: _env_path("AI_IDS_MODELS_DIR"))
    logs_dir: Path = field(default_factory=lambda: _env_path("AI_IDS_LOGS_DIR"))
    captured_flows_dir: Path = field(default_factory=lambda: _env_path("AI_IDS_CAPTURED_FLOWS_DIR"))

    # --- Structural Environment Constants ---
    app_env: str = field(default_factory=lambda: _env("AI_IDS_ENV"))
    debug: bool = field(default_factory=lambda: _get_bool("AI_IDS_DEBUG", _env_bool("AI_IDS_DEBUG")))
    secret_key: str = field(default_factory=lambda: os.getenv("AI_IDS_SECRET_KEY", INSECURE_SECRET_KEY))

    # --- Centralized Subsystem Log Rules ---
    log_level: str = field(default_factory=lambda: _env("AI_IDS_LOG_LEVEL"))
    log_to_console: bool = field(default_factory=lambda: _get_bool("AI_IDS_LOG_TO_CONSOLE", _env_bool("AI_IDS_LOG_TO_CONSOLE")))
    log_file_max_bytes: int = field(default_factory=lambda: _get_int("AI_IDS_LOG_MAX_BYTES", _env_int("AI_IDS_LOG_MAX_BYTES")))
    log_file_backup_count: int = field(default_factory=lambda: _get_int("AI_IDS_LOG_BACKUP_COUNT", _env_int("AI_IDS_LOG_BACKUP_COUNT")))

    # --- Cryptographic / Hashing Strategies ---
    bcrypt_rounds: int = field(default_factory=lambda: _get_int("AI_IDS_BCRYPT_ROUNDS", _env_int("AI_IDS_BCRYPT_ROUNDS")))

    # --- Telemetry/Alert Integration Bridges ---
    telegram_bot_token: str = field(default_factory=lambda: _env("AI_IDS_TELEGRAM_BOT_TOKEN"))
    telegram_chat_id: str = field(default_factory=lambda: _env("AI_IDS_TELEGRAM_CHAT_ID"))

    # --- Alert Engine Boundaries ---
    alert_aggregation_window_minutes: int = field(
        default_factory=lambda: _get_int("AI_IDS_ALERT_WINDOW_MINUTES", _env_int("AI_IDS_ALERT_WINDOW_MINUTES"))
    )

    # --- Live Capture Pipeline Control Directives ---
    flow_idle_timeout_seconds: int = field(default_factory=lambda: _get_int("AI_IDS_FLOW_IDLE_TIMEOUT", _env_int("AI_IDS_FLOW_IDLE_TIMEOUT")))
    live_capture_mode: str = field(default_factory=lambda: _env("AI_IDS_LIVE_CAPTURE_MODE").strip().lower())
    flow_extractor_mode: str = field(default_factory=lambda: _env("AI_IDS_FLOW_EXTRACTOR").strip().lower() or "cicflowmeter")
    cicflowmeter_interval_seconds: int = field(default_factory=lambda: _get_int("AI_IDS_CICFLOWMETER_INTERVAL_SECONDS", _env_int("AI_IDS_CICFLOWMETER_INTERVAL_SECONDS")))
    cicflowmeter_expired_update_seconds: int = field(default_factory=lambda: _get_int("AI_IDS_CICFLOWMETER_EXPIRED_UPDATE_SECONDS", _env_int("AI_IDS_CICFLOWMETER_EXPIRED_UPDATE_SECONDS")))
    monitoring_poll_interval_seconds: int = field(
        default_factory=lambda: _get_int("AI_IDS_MONITORING_INTERVAL", _env_int("AI_IDS_MONITORING_INTERVAL"))
    )

    # --- Live Capture / Live Flows Tunables (environment-driven, no hardcoded constants) ---
    live_flush_poll_seconds: float = field(default_factory=lambda: _get_float("AI_IDS_LIVE_FLUSH_POLL_SECONDS", _env_float("AI_IDS_LIVE_FLUSH_POLL_SECONDS")))
    live_shutdown_timeout_seconds: float = field(default_factory=lambda: _get_float("AI_IDS_LIVE_SHUTDOWN_TIMEOUT_SECONDS", _env_float("AI_IDS_LIVE_SHUTDOWN_TIMEOUT_SECONDS")))
    live_max_recent_flows: int = field(default_factory=lambda: _get_int("AI_IDS_LIVE_MAX_RECENT_FLOWS", _env_int("AI_IDS_LIVE_MAX_RECENT_FLOWS")))
    flow_activity_timeout_seconds: float = field(default_factory=lambda: _get_float("AI_IDS_FLOW_ACTIVITY_TIMEOUT_SECONDS", _env_float("AI_IDS_FLOW_ACTIVITY_TIMEOUT_SECONDS")))
    live_ui_poll_loops: int = field(default_factory=lambda: _get_int("AI_IDS_LIVE_UI_POLL_LOOPS", _env_int("AI_IDS_LIVE_UI_POLL_LOOPS")))
    live_ui_poll_interval: float = field(default_factory=lambda: _get_float("AI_IDS_LIVE_UI_POLL_INTERVAL", _env_float("AI_IDS_LIVE_UI_POLL_INTERVAL")))
    live_flows_limit: int = field(default_factory=lambda: _get_int("AI_IDS_LIVE_FLOWS_LIMIT", _env_int("AI_IDS_LIVE_FLOWS_LIMIT")))

    # --- Batch CSV Analysis Resource Boundaries ---
    # 0 means the entire file is analyzed (no row cap). A positive value caps how many
    # rows are audited. The chunk size keeps streaming reads memory-safe on large files.
    csv_analysis_max_rows: int = field(default_factory=lambda: _get_int("AI_IDS_CSV_ANALYSIS_MAX_ROWS", _env_int("AI_IDS_CSV_ANALYSIS_MAX_ROWS")))
    csv_analysis_chunk_size: int = field(default_factory=lambda: _get_int("AI_IDS_CSV_ANALYSIS_CHUNK_SIZE", _env_int("AI_IDS_CSV_ANALYSIS_CHUNK_SIZE")))

    # --- ML Inference Boundaries ---
    # Decision threshold (probability above which a sample is flagged as attack) and the
    # minimum feature coverage required before a flow is eligible for inference. Both are
    # environment-driven so detection strictness is tunable without code changes.
    ml_decision_threshold: float = field(default_factory=lambda: _get_float("AI_IDS_ML_DECISION_THRESHOLD", _env_float("AI_IDS_ML_DECISION_THRESHOLD")))
    ml_min_feature_coverage: float = field(default_factory=lambda: _get_float("AI_IDS_ML_MIN_FEATURE_COVERAGE", _env_float("AI_IDS_ML_MIN_FEATURE_COVERAGE")))

    # --- Macro-Flow Assembly (pure data pipeline, feeds the model only) ---
    # Combines many small flows sharing a five-ish-tuple key over a time window into a
    # single macro-flow carrying the true aggregate statistics, so the model can observe
    # floods (e.g. rotating-source-port SYN floods) that are invisible at per-flow level.
    macro_flow_enabled: bool = field(default_factory=lambda: _get_bool("AI_IDS_MACRO_FLOW_ENABLED", _env_bool("AI_IDS_MACRO_FLOW_ENABLED")))
    macro_flow_window_seconds: float = field(default_factory=lambda: _get_float("AI_IDS_MACRO_FLOW_WINDOW_SECONDS", _env_float("AI_IDS_MACRO_FLOW_WINDOW_SECONDS")))
    macro_flow_key_fields: str = field(default_factory=lambda: _env("AI_IDS_MACRO_FLOW_KEY_FIELDS"))
    macro_flow_min_members: int = field(default_factory=lambda: _get_int("AI_IDS_MACRO_FLOW_MIN_MEMBERS", _env_int("AI_IDS_MACRO_FLOW_MIN_MEMBERS")))

    @staticmethod
    def resolve_model_path(path_or_filename: str) -> Path:
        """
        Resolves a model path, handling both absolute and relative references.

        If the path is already absolute and points to an existing file, extracts the
        filename and resolves it against C{models_dir}. If the path does not exist
        as given, attempts to resolve just the filename part against C{models_dir}.
        This ensures backward compatibility with hardcoded absolute paths from other
        machines while normalising storage to filenames only.

        Returns:
            A Path resolved under the configured C{models_dir}.
        """
        settings = get_settings()
        given = Path(path_or_filename)

        if given.is_absolute() and given.exists():
            return settings.models_dir / given.name

        candidate = settings.models_dir / given.name
        if candidate.exists():
            return candidate

        candidate2 = settings.models_dir / path_or_filename
        if candidate2.exists():
            return candidate2

        return settings.models_dir / given.name

    def ensure_directories(self) -> None:
        """
        Validates and recursively builds required operational storage volumes on the host system.
        """
        try:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            self.models_dir.mkdir(parents=True, exist_ok=True)
            self.logs_dir.mkdir(parents=True, exist_ok=True)
            self.captured_flows_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            sys.stderr.write(f"[CRITICAL CONFIG ERROR] Permission failure verifying system path nodes: {exc}\n")
            raise


# Internal Process Singleton Reference Registry Block
_settings_instance: Optional[Settings] = None


def get_settings() -> Settings:
    """
    Resolves or instantiates the structural process-wide context settings singleton.
    """
    global _settings_instance
    if _settings_instance is None:
        # Construct and establish memory registers for system parameters
        instance = Settings()
        instance.ensure_directories()
        _settings_instance = instance
        
        # Micro bootstrapping stdout telemetry diagnostic check 
        if instance.debug:
            sys.stdout.write(
                f"[BOOTSTRAP] System environment configured for '{instance.app_env}' mode. "
                f"Active Logging Target Level: {instance.log_level}\n"
            )
            
    return _settings_instance