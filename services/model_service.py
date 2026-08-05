"""
Machine Learning Model Registry Orchestration Service Module.

Governs structural schema registration, asset caching strategies, deployment lifecycles, 
and database catalog records for predictive models. Minimizes system disk bottlenecks by 
maintaining thread-safe, ready-to-use memory map wrappers for runtime predictions.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Final

import joblib

from config.constants import LogLevel, LogSource
from config.settings import Settings
from core.entities.log_entry import LogEntry
from core.entities.model_record import ModelRecord
from core.exceptions import RecordNotFoundError
from infrastructure.logging.logger_factory import get_logger
from ml.interfaces import IModelAdapter
from ml.model_loader import ModelLoader
from repositories.log_repository import LogRepository
from repositories.model_repository import ModelRepository

logger = get_logger("services.model_service")


class ModelService:
    """
    Central business logic coordinator governing the machine learning asset engine catalog.
    """

    def __init__(
        self,
        model_repository: ModelRepository,
        loader: ModelLoader | None = None,
        log_repository: LogRepository | None = None,
    ) -> None:
        """
        Initializes the model service framework with system dependencies and isolation layers.
        """
        self._repo: Final[ModelRepository] = model_repository
        self._loader: Final[ModelLoader] = loader or ModelLoader()
        self._logs: Final[LogRepository | None] = log_repository
        self._adapter_cache: Final[dict[int, IModelAdapter]] = {}
        self._label_encoder_cache: Any | None = None
        self._label_encoder_lock: Final[threading.Lock] = threading.Lock()

    def _log(self, message: str, level: LogLevel = LogLevel.INFO) -> None:
        """
        Appends operational diagnostic footprint entries directly to the historical logging schema.
        """
        if self._logs is not None:
            self._logs.add(LogEntry(source=LogSource.SYSTEM, level=level, message=message))

    def register_model(self, name: str, file_path: str, model_type: str, version: str = "1.0") -> ModelRecord:
        """
        Validates structure compatibility and signs a target model into the catalog registry.

        Args:
            name: Human-readable display label identifier for the model.
            file_path: Absolute or relative host system directory location of the target binary file.
            model_type: Classifier architecture name category mapping back to runtime loaders.
            version: Strict semantic optimization tracker metadata value.

        Returns:
            A persisted ModelRecord tracking framework reference metadata variables.
        """
        adapter = self._loader.load(file_path, model_type)
        record = ModelRecord(
            name=name,
            file_path=Path(file_path).name,
            model_type=model_type,
            version=version,
            features_count=len(adapter.required_features),
            is_active=False,
        )
        record = self._repo.add(record)
        self._adapter_cache[record.id] = adapter
        
        logger.info("Registered model '%s' (id=%s, %d features).", name, record.id, record.features_count)
        self._log(f"Model Engine Event: Model '{name}' registered successfully (id={record.id}, features={record.features_count}, architecture={model_type}).")
        return record

    def list_models(self) -> list[ModelRecord]:
        """
        Retrieves all structural record representations compiled within the database registry.
        """
        return self._repo.get_all()

    def get_active_models(self) -> list[ModelRecord]:
        """
        Filters out and gathers only models currently flagged ready for operational pipeline duty.
        """
        return self._repo.get_active()

    def activate(self, model_id: int, exclusive: bool = False) -> ModelRecord:
        """
        Enables an explicit targeting mechanism to pass live analytical contexts through the target model.
        """
        record = self._repo.get_by_id(model_id)
        if record is None:
            raise RecordNotFoundError(f"Model Lifecycle Fault: Model matching context token ID {model_id} could not be resolved.")
            
        if exclusive:
            self._repo.deactivate_all()
            
        record.is_active = True
        self._repo.update(record)
        
        logger.info("Activated model id=%s ('%s').", model_id, record.name)
        log_suffix = " All alternative processing entities deactivated synchronously." if exclusive else ""
        self._log(f"Model Lifecycle Event: Pipeline routing model '{record.name}' (id={model_id}) marked active.{log_suffix}")
        return record

    def deactivate(self, model_id: int) -> ModelRecord:
        """
        Gracefully strips execution layer authority away from the targeted evaluation entry model.
        """
        record = self._repo.get_by_id(model_id)
        if record is None:
            raise RecordNotFoundError(f"Model Lifecycle Fault: Model matching context token ID {model_id} could not be resolved.")
            
        record.is_active = False
        self._repo.update(record)
        self._log(f"Model Lifecycle Event: Pipeline routing model '{record.name}' (id={model_id}) detached from active loops.")
        return record

    def get_adapter(self, model_id: int) -> IModelAdapter:
        """
        Resolves operational inference adapters cleanly from cache memory layout matrices.
        """
        if model_id in self._adapter_cache:
            return self._adapter_cache[model_id]

        record = self._repo.get_by_id(model_id)
        if record is None:
            raise RecordNotFoundError(f"Inference Mapping Fault: Model database tracking row entry ID {model_id} does not exist.")

        resolved_path = str(Settings.resolve_model_path(record.file_path))
        adapter = self._loader.load(resolved_path, record.model_type)
        self._adapter_cache[model_id] = adapter
        return adapter

    def get_label_encoder(self, model_id: int | None = None) -> Any | None:
        """
        Loads and caches the trained LabelEncoder from ``models/label_encoder.joblib``.

        Uses an internal thread-safe lock to ensure the encoder is deserialised from
        disk exactly once.  Returns ``None`` (with a logged warning) when the file is
        missing or corrupt, so callers such as ``ui/pages/detection.py`` can degrade
        gracefully to "Attack (Class N)" fallback labels.

        Args:
            model_id: Optional model identifier for future per-model encoder support.

        Returns:
            The fitted ``sklearn.preprocessing.LabelEncoder`` instance, or ``None``.
        """
        if self._label_encoder_cache is not None:
            return self._label_encoder_cache

        with self._label_encoder_lock:
            if self._label_encoder_cache is not None:
                return self._label_encoder_cache

            path = Settings.resolve_model_path("label_encoder.joblib")
            if not path.exists():
                logger.warning("Label encoder file not found at '%s'. Attack labels will show class numbers.", path)
                self._label_encoder_cache = None
                return None

            try:
                self._label_encoder_cache = joblib.load(path)
                logger.info("Label encoder loaded successfully from '%s' (%d classes).", path, len(self._label_encoder_cache.classes_))
            except Exception as exc:
                logger.warning("Failed to load label encoder from '%s': %s. Attack labels will show class numbers.", path, exc)
                self._label_encoder_cache = None

        return self._label_encoder_cache