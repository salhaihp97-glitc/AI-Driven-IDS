"""
Dynamic Feature Schema Resolution Module.

Enforces flexible structural schema mapping constraints for incoming machine learning models.
Refuses hardcoded dimension expectations, resolving feature names dynamically across standard
estimator properties, internal wrapper dictionary definitions, or filesystem sidecar metadata layers.

Resolution Priority:
  1. Sidecar JSON file (highest priority) — guarantees consistent feature ordering across models.
  2. Dict wrapper — custom persistent wrapper objects.
  3. Model-internal attributes — fallback when no sidecar or wrapper exists.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Final

from core.exceptions import ConfigurationError
from infrastructure.logging.logger_factory import get_logger

logger = get_logger("ml.feature_schema")


@dataclass
class FeatureSchema:
    """
    Domain metadata wrapper outlining the structural requirements of a machine learning asset.
    """
    feature_names: list[str]
    model_type: str = "unknown"
    version: str = "1.0"

    @property
    def count(self) -> int:
        """
        Calculates the exact dimensionality count of the feature footprint layout.
        """
        return len(self.feature_names)


def _sidecar_path(model_path: Path) -> Path:
    """
    Derives the standard matching path locator string for the target model's sidecar file.
    """
    return model_path.with_suffix(model_path.suffix + ".meta.json")


def write_sidecar(model_path: Path, feature_names: list[str], model_type: str, version: str = "1.0") -> Path:
    """
    Generates or overwrites the sidecar JSON metadata manifest for an offline model structure.

    Args:
        model_path: The core operational target binary file path reference.
        feature_names: Ordered tracking list of required string column keys.
        model_type: Structural identification type (e.g., "xgboost").
        version: Arbitrary deployment tracking state indicator version tag.

    Returns:
        The verified Path location pointing to the written metadata file asset.
    """
    sidecar: Final[Path] = _sidecar_path(model_path)
    payload: Final[dict[str, Any]] = {
        "feature_names": feature_names,
        "model_type": model_type,
        "version": version
    }
    sidecar.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return sidecar


def _try_from_estimator_attribute(loaded_object: Any) -> Optional[list[str]]:
    """
    Attempts to resolve input dimensions via native fitted library reflection flags.
    """
    # Standard scikit-learn pipeline attribute (v1.0+)
    names = getattr(loaded_object, "feature_names_in_", None)
    if names is not None:
        return list(names)
    
    # Standard native XGBoost Booster serialization layout properties
    names = getattr(loaded_object, "feature_names", None)
    if names:
        return list(names)
        
    return None


def _try_from_dict_wrapper(loaded_object: Any) -> Optional[list[str]]:
    """
    Attempts to parse schema vectors from custom internal dictionary tracking objects.
    """
    if isinstance(loaded_object, dict) and "feature_names" in loaded_object:
        return list(loaded_object["feature_names"])
    return None


def _try_from_sidecar(model_path: Path) -> Optional[dict[str, Any]]:
    """
    Attempts to read physical sidecar data maps located immediately next to the binary asset.
    """
    sidecar: Final[Path] = _sidecar_path(model_path)
    if sidecar.exists():
        try:
            return json.loads(sidecar.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
    return None


def resolve_feature_schema(model_path: Path, loaded_object: Any, model_type: str = "unknown") -> FeatureSchema:
    """
    Resolves the required structural feature schema contract for a loaded pipeline container.

    Cascades systematically through distinct detection attempts in an ordered sequence.

    Resolution Priority (sidecar-first to guarantee consistent feature ordering):
      1. External Sidecar Metadata — ensures both RF and XGBoost use identical feature order.
      2. Custom Dict Wrapper — persistent wrapper objects.
      3. Model-Internal Attributes — fallback when no sidecar exists.

    Args:
        model_path: The deployment path location of the binary artifact.
        loaded_object: The hydrated runtime memory instance target.
        model_type: Optional operational model type classification tag fallback.

    Returns:
        A fully validated and structurally complete FeatureSchema instance.

    Raises:
        ConfigurationError: If all dynamic lookup avenues fail to map the execution matrix.
    """
    # Resolution Level 1 (Priority): External Sidecar Metadata Parsing
    # The sidecar guarantees consistent feature ordering across all model types,
    # preventing silent misalignment when RF and XGBoost resolve different orderings
    # from their internal attributes.
    sidecar_data = _try_from_sidecar(model_path)
    if sidecar_data and "feature_names" in sidecar_data:
        schema = FeatureSchema(
            feature_names=list(sidecar_data["feature_names"]),
            model_type=sidecar_data.get("model_type", model_type),
            version=sidecar_data.get("version", "1.0"),
        )
        # Validate that model-internal features (if available) match the sidecar
        internal_names = _try_from_estimator_attribute(loaded_object)
        if internal_names and len(internal_names) == len(schema.feature_names):
            if internal_names != schema.feature_names:
                logger.warning(
                    "Feature order mismatch detected: sidecar='%s' vs model-internal='%s'. "
                    "Using sidecar order for consistent prediction behavior.",
                    schema.feature_names[:5], internal_names[:5],
                )
        return schema

    # Resolution Level 2: Custom Persistent Target Wrappers
    names = _try_from_dict_wrapper(loaded_object)
    if names:
        inferred_type = loaded_object.get("model_type", model_type) if isinstance(loaded_object, dict) else model_type
        return FeatureSchema(feature_names=names, model_type=inferred_type)

    # Resolution Level 3 (Fallback): Native Object Attribute Inspection
    names = _try_from_estimator_attribute(loaded_object)
    if names:
        return FeatureSchema(feature_names=names, model_type=model_type)

    # Defensively abort the processing pipeline if dimensions remain unmapped
    raise ConfigurationError(
        f"Unable to safely resolve necessary model dimensions for asset '{model_path.name}'. "
        f"The binary lacks standard fitted attribute fields, does not match internal wrapper maps, "
        f"and no accompanying layout manifest file was located at '{_sidecar_path(model_path).name}'. "
        f"Please supply a structural sidecar JSON configuration next to the target file."
    )