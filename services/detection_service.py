"""
Unified Statistical Inference Engine and Detection Framework Module.

Acts as the decoupled data orchestration boundary layer mapping raw feature sets to 
active machine learning runtime models. Manages individual or high-throughput batch vectors, 
verifies feature matrix coverage, records pipeline statuses, and routes threat indications 
to the real-time alerting system.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Final

import numpy as np

from config.constants import LogLevel, LogSource
from config.settings import Settings, get_settings
from core.entities.detection import Detection
from core.entities.log_entry import LogEntry
from core.exceptions import ValidationError
from infrastructure.logging.logger_factory import get_logger
from ml.feature_mapper import FeatureMapper
from repositories.detection_repository import DetectionRepository
from repositories.log_repository import LogRepository
from services.alert_engine import AlertEngine
from services.ip_list_service import IpListService
from services.model_service import ModelService

logger = get_logger("services.detection_service")
BENIGN_CLASS_INDEX: Final[int] = 0


@dataclass(frozen=True)
class DetectionResult:
    """
    Immutable state capsule containing output details from an individual traffic line analysis.
    """
    detection: Detection | None
    missing_features: list[str]
    alert_created: bool
    prediction: int
    confidence: float
    attack_type: str = ""
    attack_reason: str = ""
    is_whitelisted: bool = False
    is_blacklisted: bool = False


class DetectionService:
    """
    Central operational hub driving machine learning inference pipelines across system ingest channels.
    """

    def __init__(
        self,
        model_service: ModelService,
        detection_repository: DetectionRepository,
        log_repository: LogRepository,
        alert_engine: AlertEngine,
        ip_list_service: IpListService | None = None,
        feature_mapper: FeatureMapper | None = None,
        settings: Settings | None = None,
    ) -> None:
        """
        Initializes the service with core application boundaries using strict dependency injection patterns.
        """
        self._models: Final[ModelService] = model_service
        self._detections: Final[DetectionRepository] = detection_repository
        self._logs: Final[LogRepository] = log_repository
        self._alerts: Final[AlertEngine] = alert_engine
        self._ip_lists: Final[IpListService | None] = ip_list_service
        self._mapper: Final[FeatureMapper] = feature_mapper or FeatureMapper()
        self._settings: Final[Settings] = settings or get_settings()

    def run(
        self,
        model_id: int,
        raw_features: dict[str, float],
        source_type: str,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        min_feature_coverage: float | None = None,
        skip_integration: bool = False,
    ) -> DetectionResult:
        """
        Executes granular statistical classification models on an isolated traffic data array.

        Args:
            model_id: Primary tracking key identifying the targeted deployment asset.
            raw_features: Extracted variable dimensions mapping metrics found on the wire.
            source_type: Ingestion tag identifying origin channels (e.g., 'live', 'pcap', 'csv').
            source_ip: Optional host source network identifier string.
            destination_ip: Optional destination network endpoint identifier string.
            min_feature_coverage: Minimum percentage of required features that must be matched.
                When None, falls back to the ``AI_IDS_ML_MIN_FEATURE_COVERAGE`` setting. Passing a
                value overrides the configured default for this call.

        Returns:
            A populated DetectionResult outlining tracking identifiers and predictions.

        Raises:
            ValidationError: If structural attribute coverage falls below required thresholds.
        """
        try:
            # 0. Check IP whitelist/blacklist status (skipped for file analysis)
            is_whitelisted = False
            is_blacklisted = False
            if not skip_integration:
                is_whitelisted = bool(self._ip_lists and source_ip and self._ip_lists.is_whitelisted(source_ip))
                is_blacklisted = bool(self._ip_lists and source_ip and self._ip_lists.is_blacklisted(source_ip))

            # Resolve the coverage guardrail from settings when the caller did not supply it.
            effective_min_coverage: Final[float] = (
                min_feature_coverage if min_feature_coverage is not None else self._settings.ml_min_feature_coverage
            )

            # 1. Resolve model context details and expected structural attributes
            adapter = self._models.get_adapter(model_id)
            required_features = adapter.required_features

            # 2. Validate dimensional completeness against minimum requirements
            self._mapper.validate_minimum_coverage(raw_features, required_features, effective_min_coverage)
            feature_vector, missing_features = self._mapper.map_with_report(raw_features, required_features)

            if missing_features:
                logger.debug("Missing features (filled with 0.0): %d | First 5: %s", len(missing_features), missing_features[:5])

            # 3. Request classification vectors from the specialized analytical driver
            prediction = int(adapter.predict(feature_vector))
            confidence = float(adapter.predict_confidence(feature_vector))

            logger.debug("Model output: class=%d, confidence=%.2f%%", prediction, confidence * 100)

            if prediction != BENIGN_CLASS_INDEX:
                logger.warning("Malicious footprint detected! Class: %d | Confidence: %.2f%%", prediction, confidence * 100)

            # 3b. Pure ML classifier authority: the active model is the sole arbiter
            # of verdicts. No heuristic/rule overrides are applied — any threat signal
            # must originate from the model's decision boundary.
            signature_hit = None
            signature_override = False

            # 4. Resolve attack type via per-model class vocabulary
            # (meta sidecar ``classes`` wins; global label encoder is the fallback).
            attack_type = ""
            model_classes = self._models.get_model_classes(model_id)
            if model_classes and 0 <= prediction < len(model_classes):
                attack_type = model_classes[prediction]

            # 4b. Build feature-level explanation for model decisions
            model_name = self._resolve_model_name(model_id)
            feature_analysis = self._build_feature_analysis(raw_features, required_features, adapter, prediction, feature_vector)

            # 5. Override for IP lists (only when integration is active)
            attack_reason = ""
            severity = Detection.classify_severity(confidence, prediction != BENIGN_CLASS_INDEX)
            if is_blacklisted:
                prediction = 1
                confidence = 1.0
                attack_type = "Blocked IP Attempting Access"
                attack_reason = f"Blacklisted IP {source_ip} attempting to access the network — immediate block applied"
                severity = "CRITICAL"
            elif is_whitelisted:
                if prediction != BENIGN_CLASS_INDEX:
                    attack_type = "Admin Test Traffic"
                    attack_reason = f"Whitelisted admin test traffic from {source_ip} — model would classify as anomalous but trusted"
                else:
                    severity = ""
                    attack_reason = f"Whitelisted admin test traffic from {source_ip} — classified as benign"
            else:
                if prediction != BENIGN_CLASS_INDEX:
                    attack_reason = (
                        f"ML model ({model_name}) classified as {attack_type} "
                        f"with {confidence:.1%} confidence — "
                        f"{feature_analysis}"
                    )
                else:
                    attack_reason = "Traffic classified as benign by ML model — no attack pattern detected above threshold"

            detection_entity = Detection(
                model_id=model_id,
                source_ip=source_ip,
                destination_ip=destination_ip,
                prediction=prediction,
                confidence=confidence,
                source_type=source_type,
                raw_features=json.dumps(raw_features, default=str),
                severity=severity,
                attack_type=attack_type,
                attack_reason=attack_reason,
                is_whitelisted=is_whitelisted,
                is_blacklisted=is_blacklisted,
            )
            persisted_detection = self._detections.add(detection_entity)

            # 5. Resolve severity classifications dynamically based on results
            log_severity = LogLevel.WARNING if prediction != BENIGN_CLASS_INDEX else LogLevel.INFO
            log_message = (
                f"Execution Tail Complete: VectorSource='{source_type}' -> "
                f"Class={prediction} ({attack_type}) (Confidence={confidence:.2%}) | Src={source_ip} -> Dst={destination_ip}"
            )
            
            self._logs.add(
                LogEntry(
                    source=self._log_source_for(source_type),
                    level=log_severity,
                    message=log_message,
                )
            )

            # 6. Evaluate alert conditions (skipped for file analysis)
            alert_entity = None
            if not skip_integration:
                alert_entity = self._alerts.process_detection(persisted_detection, model_name=model_name)

            return DetectionResult(
                detection=persisted_detection, 
                missing_features=missing_features, 
                alert_created=alert_entity is not None,
                prediction=prediction,
                confidence=confidence,
                attack_type=attack_type,
                attack_reason=attack_reason,
                is_whitelisted=is_whitelisted,
                is_blacklisted=is_blacklisted,
            )

        except ValidationError as validation_err:
            logger.error("Structural Validation Constraint failed for model %s: %s", model_id, validation_err)
            raise

        except Exception as system_exception:
            error_message = f"Fatal pipeline breakdown processing model {model_id}. Context: {system_exception}"
            try:
                self._logs.add(LogEntry(source=LogSource.ERROR, level=LogLevel.ERROR, message=error_message))
            except Exception:
                logger.critical("Persistence boundaries failed during standard crash logging procedures.")
            
            logger.exception("Prediction pipeline execution terminated unexpectedly due to a system level error.")
            raise system_exception

    def _build_feature_analysis(
        self,
        raw_features: dict[str, float],
        required_features: list[str],
        adapter: object,
        prediction: int,
        feature_vector: np.ndarray,
    ) -> str:
        """Build a human-readable explanation of which features drove the model decision."""
        if prediction == BENIGN_CLASS_INDEX:
            return "no anomalous patterns detected"

        feature_values = {name: raw_features.get(name, 0.0) for name in required_features}
        sorted_features = sorted(feature_values.items(), key=lambda x: abs(x[1]), reverse=True)
        top_features = sorted_features[:5]

        parts = [f"key contributing features: {', '.join(f'{name}={value:.4f}' for name, value in top_features)}"]
        return "; ".join(parts)

    def _resolve_model_name(self, model_id: int) -> str:
        """Resolves a human-readable model name with a simple repeat-call cache."""
        cache = self.__dict__.setdefault("_model_name_cache", {})
        if model_id in cache:
            return cache[model_id]
        model_records = self._models.list_models()
        name = next(
            (model.name for model in model_records if model.id == model_id),
            f"unresolved_model_{model_id}",
        )
        cache[model_id] = name
        return name

    @staticmethod
    def _log_source_for(source_type: str) -> LogSource:
        """
        Resolves the system audit classification bucket type mapped to incoming capture channels.
        """
        return LogSource.CAPTURE if source_type in ("live", "pcap") else LogSource.PREDICTION