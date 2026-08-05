"""
Batch Network Traffic Data Analytics Processing Service Module.

Manages data extraction and model inference workflows against tabular CSV log streams.
Implements column normalizations, fallback IP address identity mapping, memory-safe
chunked ingestion, a configurable analysis cap (unlimited by default), and multi-class
anomaly counters.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Final

import numpy as np
import pandas as pd

from config.settings import Settings, get_settings
from core.exceptions import ValidationError
from infrastructure.logging.logger_factory import get_logger
from services.detection_service import DetectionResult, DetectionService
from services.model_service import ModelService

logger = get_logger("services.csv_analysis_service")

# Candidate matrix templates used to normalize variations of source and destination IP field titles
_IP_COLUMN_CANDIDATES: Final[set[str]] = {
    "source ip", "src ip", "source_ip", "src_ip", "sourceip", "srcip", "src_host", "source host"
}
_DEST_IP_COLUMN_CANDIDATES: Final[set[str]] = {
    "destination ip", "dst ip", "destination_ip", "dst_ip", "destinationip", "dstip", "dst_host", "destination host"
}


@dataclass
class CsvAnalysisSummary:
    """
    Structured execution summary mapping completed data metrics across an analyzed file stream.
    """
    total_rows: int
    attack_count: int
    normal_count: int
    results: list[DetectionResult]


class CsvAnalysisService:
    """
    Application core processor driving batch tabular security audits and ML feature vector extraction.
    """

    def __init__(
        self,
        detection_service: DetectionService,
        model_service: ModelService,
        settings: Settings | None = None,
    ) -> None:
        """
        Initializes the service with the mandatory core classification engine and model registry.

        Args:
            detection_service: The core classification engine dispatching vector inferences.
            model_service: The model registry used to resolve display names.
            settings: Optional settings override (defaults to the process singleton).
        """
        self._detection_service: Final[DetectionService] = detection_service
        self._model_service: Final[ModelService] = model_service
        self._settings: Final[Settings] = settings or get_settings()

    def analyze(self, model_id: int, csv_path: str, max_rows: int | None = None) -> CsvAnalysisSummary:
        """
        Parses a target text dataset to detect anomalies and evaluate network threat counts.

        The file is streamed in memory-safe chunks and, by default, analyzed in full. The
        ``max_rows`` argument and the ``AI_IDS_CSV_ANALYSIS_MAX_ROWS`` setting both act as
        optional truncation ceilings; a value of 0 or None means no cap.

        Args:
            model_id: Primary database identifier indexing the targeted inference model asset.
            csv_path: The file location path pointing to the raw dataset to audit.
            max_rows: Optional truncation ceiling to limit the total layout evaluation context.

        Returns:
            A populated CsvAnalysisSummary compiling classification vectors and metrics.

        Raises:
            ValidationError: If the file is unreadable, corrupted, or completely empty.
        """
        try:
            header = pd.read_csv(csv_path, nrows=0)
        except Exception as exc:
            raise ValidationError(f"Data File Access Fault: Unable to ingest target CSV log structure: {exc}") from exc

        # Sanitize metadata boundaries by stripping trailing whitespace from column mappings
        columns: Final[list[str]] = [str(col).strip() for col in header.columns]
        if not columns:
            raise ValidationError("Data Evaluation Interrupted: The targeted CSV file structure contains no valid rows.")

        columns_lower: Final[dict[str, str]] = {col.lower(): col for col in columns}

        # Primary lookup extraction for host keys using defined matrix template candidates
        ip_col = next((columns_lower[c] for c in _IP_COLUMN_CANDIDATES if c in columns_lower), None)
        dst_col = next((columns_lower[c] for c in _DEST_IP_COLUMN_CANDIDATES if c in columns_lower), None)

        # Secondary substring fallback check for non-standard column naming conventions
        if not ip_col:
            for col_lower, original_col in columns_lower.items():
                if "src" in col_lower and "ip" in col_lower:
                    ip_col = original_col
                    break
                if "source" in col_lower and "ip" in col_lower:
                    ip_col = original_col
                    break

        if not dst_col:
            for col_lower, original_col in columns_lower.items():
                if "dst" in col_lower and "ip" in col_lower:
                    dst_col = original_col
                    break
                if "destination" in col_lower and "ip" in col_lower:
                    dst_col = original_col
                    break

        results: Final[list[DetectionResult]] = []
        attack_count: int = 0
        total_rows: int = 0
        start_time: Final[float] = time.time()

        # Resolve model display name once before the loop to avoid redundant lookups
        model_name: str = f"model_{model_id}"
        for m in self._model_service.list_models():
            if m.id == model_id:
                model_name = m.name
                break

        # Effective truncation ceiling: explicit argument wins, then the configured setting.
        effective_cap: int | None = None
        if max_rows and max_rows > 0:
            effective_cap = max_rows
        if effective_cap is None:
            configured: Final[int] = self._settings.csv_analysis_max_rows
            if configured and configured > 0:
                effective_cap = configured

        chunk_size: int = self._settings.csv_analysis_chunk_size
        if chunk_size <= 0:
            chunk_size = 10000

        logger.debug("Auditing CSV: columns %s | row cap %s | chunk size %d", columns, effective_cap, chunk_size)

        # Fresh signature state so this file is audited independently of earlier batches
        self._detection_service.reset_signatures()

        truncated: bool = False
        try:
            for chunk in pd.read_csv(csv_path, chunksize=chunk_size):
                chunk.columns = [str(col).strip() for col in chunk.columns]
                for _, row in chunk.iterrows():
                    if effective_cap is not None and total_rows >= effective_cap:
                        truncated = True
                        break

                    total_rows += 1
                    if total_rows % 100 == 0:
                        logger.debug("Auditing batch index row %d... (Duration: %.2fs)", total_rows, time.time() - start_time)

                    try:
                        raw_features: Final[dict[str, float]] = {
                            col: float(row[col])
                            for col in chunk.columns
                            if pd.notnull(row[col])
                            and col not in (ip_col, dst_col)
                            and col.lower() not in {"label", "label ", "timestamp", "flow id",
                                                     "prediction", "confidence", "severity"}
                            and isinstance(row[col], (int, float, np.integer, np.floating))
                        }

                        source_ip = str(row[ip_col]).strip() if (ip_col and pd.notnull(row[ip_col])) else "Unknown"
                        destination_ip = str(row[dst_col]).strip() if (dst_col and pd.notnull(row[dst_col])) else "Unknown"

                        # Dispatch normalized vector targets directly to the active traffic pipeline
                        result = self._detection_service.run(
                            model_id=model_id,
                            raw_features=raw_features,
                            source_type="csv",
                            source_ip=source_ip,
                            destination_ip=destination_ip,
                            skip_integration=True,
                        )
                        results.append(result)

                        # Any non-zero prediction signature indicates a confirmed threat anomaly
                        if result.detection is not None and result.detection.prediction != 0:
                            attack_count += 1

                    except Exception as e:
                        logger.error("Skipping structural row vector configuration due to inference engine error: %s", e)

                if truncated:
                    break
        except Exception as exc:
            raise ValidationError(f"Data Evaluation Interrupted: Failed while auditing CSV stream: {exc}") from exc

        if total_rows == 0:
            raise ValidationError("Data Evaluation Interrupted: The targeted CSV file structure contains no valid rows.")

        logger.info(
            "Tabular ingestion complete. Audited: %d rows (model: %s). Malicious anomalies: %d",
            total_rows, model_name, attack_count,
        )

        return CsvAnalysisSummary(
            total_rows=total_rows,
            attack_count=attack_count,
            normal_count=len(results) - attack_count,
            results=results,
        )