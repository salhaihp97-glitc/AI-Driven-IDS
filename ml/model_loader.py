"""
Machine Learning Model Loader Module.

Acts as the exclusive isolation layer for deserializing external model artifacts from persistent 
storage. Abstracts framework-specific binary parsing algorithms (such as joblib, pickle, or 
native XGBoost booster engines) and maps them uniformly into decoupled IModelAdapter instances.
"""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any, Final, Set

from config.settings import Settings, get_settings
from core.exceptions import ConfigurationError
from infrastructure.logging.logger_factory import get_logger
from ml.feature_schema import resolve_feature_schema
from ml.interfaces import IModelAdapter

# Initialize Machine Learning Telemetry Logger
logger = get_logger("ml.model_loader")

# Supported Structural System Format Signatures
_SUPPORTED_EXTENSIONS: Final[Set[str]] = {".joblib", ".pkl", ".json", ".ubj"}


class ModelLoader:
    """
    Unified Serialization Access Broker.
    
    Validates structural file properties and manages runtime engine dispatch routines to transform 
    serialized disk footprints into highly operational prediction abstractions.
    """

    def load(self, model_path: str, model_type_hint: str = "unknown") -> IModelAdapter:
        """
        Ingests a serialized pipeline binary file from disk and maps it into a system adapter contract.

        Args:
            model_path: System locator path string referencing the physical model file asset.
            model_type_hint: Optional descriptor tracking structural algorithm definitions.

        Returns:
            An operational, decoupled IModelAdapter instance ready for query inferences.

        Raises:
            ConfigurationError: If the asset is missing, unreadable, or formatted abnormally.
        """
        resolved: Final[Path] = Settings.resolve_model_path(model_path)
        if not resolved.exists():
            raise ConfigurationError(f"Target model asset could not be located at path: '{model_path}' (resolved: '{resolved}')")
        path: Final[Path] = resolved

        suffix: Final[str] = path.suffix.lower()
        if suffix not in _SUPPORTED_EXTENSIONS:
            raise ConfigurationError(
                f"Unsupported model file signature configuration '{suffix}'. "
                f"Permitted structural extensions include: {sorted(_SUPPORTED_EXTENSIONS)}"
            )

        if suffix in {".json", ".ubj"}:
            return self._load_xgboost_booster(path, model_type_hint)
        return self._load_joblib_or_pickle(path, model_type_hint)

    def _load_joblib_or_pickle(self, path: Path, model_type_hint: str) -> IModelAdapter:
        """
        Handles scikit-learn compatible pipeline abstractions using standard object graph hydration streams.
        """
        # LAZY IMPORT: Breaking circular import chain between model_loader and model_adapter
        from ml.model_adapter import SklearnCompatibleModelAdapter

        loaded_object: Final[Any] = self._read_joblib_or_pickle(path)

        # Extract internal estimators if wrapped within tracking training dictionaries
        estimator: Any = loaded_object
        if isinstance(loaded_object, dict):
            estimator = loaded_object.get("pipeline") or loaded_object.get("model") or loaded_object

        schema = resolve_feature_schema(path, estimator, model_type_hint)
        scaler = self._load_sidecar_scaler(path)

        # The scaler is the ground-truth record of the training-time feature footprint:
        # if it exposes fitted feature names, its order and membership supersede any
        # static sidecar metadata so vectors are aligned with what the estimator learned.
        if scaler is not None:
            scaler_names = getattr(scaler, "feature_names_in_", None)
            if scaler_names is not None:
                scaler_names_list: list[str] = list(scaler_names)
                if scaler_names_list != schema.feature_names:
                    logger.warning(
                        "Scaler feature footprint overrides sidecar schema: %d features in scaler "
                        "order vs %d in '%s'. Using scaler order for prediction alignment.",
                        len(scaler_names_list), len(schema.feature_names), path.name,
                    )
                    schema.feature_names = scaler_names_list

        logger.info(
            "Successfully hydrated object graph for model '%s' (%d features) via joblib/pickle.", 
            path.name, 
            schema.count
        )
        decision_threshold: Final[float] = get_settings().ml_decision_threshold
        return SklearnCompatibleModelAdapter(estimator, schema, scaler=scaler, decision_threshold=decision_threshold)

    def _load_sidecar_scaler(self, model_path: Path) -> Any | None:
        """
        Attempts to hydrate a preprocessing scaler artifact co-located with the model binary.

        The training pipeline exports ``scaler.joblib`` beside its estimators. Returning it
        enables the adapter to reproduce training-time scaling during inference. A missing or
        unreadable scaler is a non-fatal condition and simply results in raw (unscaled) input.
        """
        scaler_path: Final[Path] = model_path.parent / "scaler.joblib"
        if not scaler_path.exists():
            return None
        try:
            return self._read_joblib_or_pickle(scaler_path)
        except ConfigurationError as exc:
            logger.warning("Scaler sidecar artifact found but could not be loaded: %s", exc)
            return None

    @staticmethod
    def _read_joblib_or_pickle(path: Path) -> Any:
        """
        Performs cascading stream deserialization utilizing joblib or fallback binary pickle filters.
        """
        try:
            import joblib
            return joblib.load(path)
        except Exception as joblib_error:  # noqa: BLE001 - Deliberately catching broad errors for secondary format attempt
            try:
                with open(path, "rb") as fh:
                    return pickle.load(fh)
            except Exception as pickle_error:
                raise ConfigurationError(
                    f"Persistence Boundary Fault: Failed to deserialize asset object '{path.name}' "
                    f"via standard joblib primitives ({joblib_error}) or secondary fallback pickle decoding ({pickle_error})."
                ) from pickle_error

    def _load_xgboost_booster(self, path: Path, model_type_hint: str) -> IModelAdapter:
        """
        Deserializes native high-performance gradient boosting frameworks from native document formats.
        """
        try:
            import xgboost as xgb
        except ImportError as exc:
            raise ConfigurationError(
                "Missing Structural Execution Dependency: A native XGBoost model configuration was "
                "provided, but the core 'xgboost' library runtime is uninstalled. Run `pip install xgboost`."
            ) from exc

        # Dynamic local import to preserve execution boundary decoupling architectures
        from ml.xgboost_booster_adapter import XGBoostBoosterAdapter

        try:
            booster = xgb.Booster()
            booster.load_model(str(path))
            
            schema = resolve_feature_schema(path, booster, model_type_hint or "xgboost")
            logger.info(
                "Successfully loaded native XGBoost Booster core configuration '%s' (%d features).", 
                path.name, 
                schema.count
            )
            decision_threshold: Final[float] = get_settings().ml_decision_threshold
            return XGBoostBoosterAdapter(booster, schema, decision_threshold=decision_threshold)
        except Exception as booster_error:
            raise ConfigurationError(
                f"Failed to ingest native gradient booster state matrix from '{path.name}': {booster_error}"
            ) from booster_error