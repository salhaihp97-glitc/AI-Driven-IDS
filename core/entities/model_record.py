"""
Model Record Domain Entity Module.

Defines the core structural domain representation for machine learning model assets.
Tracks physical storage footprints, behavioral architecture configurations, version schemas,
and active operational statuses inside the prediction pipelines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Optional


@dataclass
class ModelRecord:
    """
    Domain entity model capturing metadata for a registered machine learning asset.

    Serves as the tracking record utilized by downstream prediction and inference engines
    to load, evaluate, and trace active analytical model versions.
    """
    name: str
    file_path: str
    model_type: str
    version: str
    id: Optional[int] = None
    features_count: Optional[int] = None
    is_active: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: Optional[str] = None
