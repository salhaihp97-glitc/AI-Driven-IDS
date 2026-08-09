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
from typing import Final, Optional

import numpy as np
import pandas as pd

from capture.flow_models import FlowFeatures
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


@dataclass
class _RowUnit:
    """Internal per-row extraction capsule used to feed macro assembly + inference."""
    flow: FlowFeatures
    source_ip: str
    destination_ip: str


def _benign_result() -> DetectionResult:
    """Returns a neutral DetectionResult placeholder for rows whose macro-flows could not be scored."""
    return DetectionResult(
        detection=None,
        missing_features=[],
        alert_created=False,
        prediction=0,
        confidence=0.0,
        attack_type="BENIGN",
        attack_reason="Inference unavailable — row treated as benign",
    )


class CsvAnalysisService:
    """
    Application core processor driving batch tabular security audits and ML feature vector extraction.
    """

    def __init__(
        self,
        detection_service: DetectionService,
        model_service: ModelService,
        settings: Settings | None = None,
        macro_assembler: object | None = None,
    ) -> None:
        """
        Initializes the service with the mandatory core classification engine and model registry.

        Args:
            detection_service: The core classification engine dispatching vector inferences.
            model_service: The model registry used to resolve display names.
            settings: Optional settings override (defaults to the process singleton).
            macro_assembler: Optional ``MacroFlowAssembler`` (pure data engineering only).
        """
        self._detection_service: Final[DetectionService] = detection_service
        self._model_service: Final[ModelService] = model_service
        self._settings: Final[Settings] = settings or get_settings()
        if macro_assembler is None:
            from capture.macro_flow_assembler import MacroFlowAssembler
            macro_assembler = MacroFlowAssembler()
        self._assembler: Final[object] = macro_assembler

    def analyze(
        self,
        model_id: int,
        csv_path: str,
        max_rows: int | None = None,
        source_type: str = "csv",
        skip_integration: bool = True,
    ) -> CsvAnalysisSummary:
        """
        Parses a target text dataset to detect anomalies and evaluate network threat counts.

        The file is streamed in memory-safe chunks and, by default, analyzed in full. The
        ``max_rows`` argument and the ``AI_IDS_CSV_ANALYSIS_MAX_ROWS`` setting both act as
        optional truncation ceilings; a value of 0 or None means no cap.

        When macro-flow assembly is enabled, raw rows are first aggregated into macro-flows
        (pure data engineering that groups tiny flows sharing a key) so floods that are
        invisible per-flow reach the model. Each macro-flow is then classified by the ML
        model alone — no rule/statistical layer overrides the verdict. ``total_rows`` always
        reports the number of raw rows audited, while ``results`` holds one DetectionResult
        per classification unit (macro-flow when assembly is active, otherwise per-row).

        Args:
            model_id: Primary database identifier indexing the targeted inference model asset.
            csv_path: The file location path pointing to the raw dataset to audit.
            max_rows: Optional truncation ceiling to limit the total layout evaluation context.
            source_type: Origin channel tag forwarded to the detection pipeline (defaults to
                ``"csv"`` for file analysis; live capture passes ``"live"``).
            skip_integration: When False, alerts and IP whitelist/blacklist enforcement are
                active for these flows (used by live capture). File analysis keeps the default
                ``True`` so verdicts stay pure ML outputs.

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

        # Resolve optional identity columns (ports / protocol) for macro assembly keys.
        def _find_column(candidates: set[str]) -> Optional[str]:
            for c in candidates:
                if c in columns_lower:
                    return columns_lower[c]
            return None

        src_port_col = _find_column({"src port", "source port", "src_port", "source_port"})
        dst_port_col = _find_column({"dst port", "destination port", "dst_port", "destination_port"})
        protocol_col = _find_column({"protocol"})

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

        units: list[_RowUnit] = []
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

                        def _row_int(col_name: Optional[str]) -> int:
                            if col_name is None:
                                return 0
                            value = row.get(col_name)
                            try:
                                return int(float(value)) if pd.notnull(value) else 0
                            except (TypeError, ValueError):
                                return 0

                        flow = FlowFeatures(
                            src_ip=source_ip,
                            dst_ip=destination_ip,
                            src_port=_row_int(src_port_col),
                            dst_port=_row_int(dst_port_col),
                            protocol=_row_int(protocol_col),
                            features=raw_features,
                        )
                        units.append(_RowUnit(flow=flow, source_ip=source_ip, destination_ip=destination_ip))

                    except Exception as e:
                        logger.error("Skipping structural row vector configuration due to ingestion error: %s", e)

                if truncated:
                    break
        except Exception as exc:
            raise ValidationError(f"Data Evaluation Interrupted: Failed while auditing CSV stream: {exc}") from exc

        if total_rows == 0:
            raise ValidationError("Data Evaluation Interrupted: The targeted CSV file structure contains no valid rows.")

        # Aggregate raw rows into macro-flow classification units when assembly is enabled.
        # Macro units are classified by the macro-aggregate model (``macro_rf_v1``), never by
        # the per-flow classifier -- the entire reason floods are invisible per-flow is that
        # per-flow models can only see individual short connections. Each resulting verdict is
        # then attributed back to the exact raw rows that formed the macro-flow, so downstream
        # row-aligned consumers (live cleaned CSV) tag every member row with the aggregate attack.
        enabled_assembler = bool(getattr(self._assembler, "enabled", False))
        if enabled_assembler:
            # The macro model is the sole authority for assembled units; resolve its database id.
            macro_model_id = self._model_service.resolve_macro_model_id(self._settings.macro_flow_model_id)
            if macro_model_id is None:
                logger.warning(
                    "Macro-flow assembly enabled but no macro model is registered; "
                    "falling back to per-flow model %d for assembled units.",
                    model_id,
                )
                macro_model_id = model_id

            mapped = list(self._assembler.assemble_mapped([u.flow for u in units]))
            logger.info(
                "Macro-flow assembly active: %d raw rows -> %d macro-flow units (macro model id=%s).",
                total_rows, len(mapped), macro_model_id,
            )

            # Each unique macro verdict is computed once, then re-used for every raw member row.
            row_results: list[DetectionResult] = [None] * total_rows  # type: ignore[list-item]
            attack_count = 0
            for flow, member_indices in mapped:
                member_indices_list = list(member_indices)
                if member_indices_list:
                    source_ip = units[member_indices_list[0]].source_ip
                    destination_ip = units[member_indices_list[0]].destination_ip
                else:
                    source_ip, destination_ip = flow.src_ip, flow.dst_ip
                try:
                    # Dispatch the assembled unit (pure data engineering) to the macro model.
                    # The model is the sole authority: no rule/statistical layer overrides this.
                    result = self._detection_service.run(
                        model_id=macro_model_id,
                        raw_features=flow.features,
                        source_type=source_type,
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        skip_integration=skip_integration,
                    )
                except Exception as e:
                    logger.error("Skipping macro-flow unit configuration due to inference engine error: %s", e)
                    continue

                for member_row_index in member_indices_list:
                    row_results[member_row_index] = result
                if result.detection is not None and result.detection.prediction != 0:
                    attack_count += 1

            # Rows that failed macro inference get a benign placeholder so lengths stay aligned.
            results = [r if r is not None else _benign_result() for r in row_results]

            return CsvAnalysisSummary(
                total_rows=total_rows,
                attack_count=attack_count,
                normal_count=total_rows - attack_count,
                results=results,
            )

        # Dispatch normalized vector targets directly to the active traffic pipeline.
        # The model is the sole authority: no rule/statistical layer overrides its verdict.
        for unit in units:
            try:
                result = self._detection_service.run(
                    model_id=model_id,
                    raw_features=unit.flow.features,
                    source_type=source_type,
                    source_ip=unit.source_ip,
                    destination_ip=unit.destination_ip,
                    skip_integration=skip_integration,
                )
                results.append(result)

                # Any non-zero prediction signature indicates a confirmed threat anomaly
                if result.detection is not None and result.detection.prediction != 0:
                    attack_count += 1

            except Exception as e:
                logger.error("Skipping structural row vector configuration due to inference engine error: %s", e)

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
