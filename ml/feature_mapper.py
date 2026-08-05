"""
Semantic Feature Alignment Engine Module.

Provides high-performance runtime alignment between real-time network flow telemetry feature sets 
(e.g., CICFlowMeter outputs) and target academic machine learning inference matrices. Handles 
casing differences, character anomalies, structural naming aliases, and missing fields safely.
"""

from __future__ import annotations

import re
from typing import Final, Union

import numpy as np
import pandas as pd

from core.exceptions import ValidationError


class FeatureMapper:
    """
    High-Performance Semantic Alignment Engine.
    
    Normalizes variable string configurations and maps telemetry fields dynamically to structured 
    feature vectors required by analytical models, preventing pipeline evaluation crashes.
    """

    def __init__(self, missing_value_fill: float = 0.0) -> None:
        """
        Initializes the semantic alignment mapper with defensive missing field fallbacks.
        """
        self._fill: Final[float] = missing_value_fill
        
        # Comprehensive Global Telemetry Alias Registry Map
        self._aliases: Final[dict[str, str]] = {
            # 1. Base Transport Layer Protocol Context Identifiers
            "destinationport": "dstport",
            "dstport": "destinationport",
            "protocol": "protocol",
            
            # 2. Network Stream Throughput Rate Indicators
            "flowbytess": "flowbytss",
            "flowbytss": "flowbytess",
            "flowpacketss": "flowpktss",
            "flowpktss": "flowpacketss",
            "fwdpacketss": "fwdpktss",
            "fwdpktss": "fwdpacketss",
            "bwdpacketss": "bwdpktss",
            "bwdpktss": "bwdpacketss",
            
            # 3. Packet Sizing Structural Averages
            "averagepacketsize": "pktsizeavg",
            "pktsizeavg": "averagepacketsize",
            
            # 4. Segment Length Mathematical Distributions
            "avgfwdsegmentsize": "fwdsegsizeavg",
            "fwdsegsizeavg": "avgfwdsegmentsize",
            "avgbwdsegmentsize": "bwdsegsizeavg",
            "bwdsegsizeavg": "avgbwdsegmentsize",
            
            # 5. Volumetric Telemetry Aggregates 
            "totfwdpkts": "totalfwdpackets",
            "totalfwdpackets": "totfwdpkts",
            "totbwdpkts": "totalbackwardpackets",
            "totalbackwardpackets": "totbwdpkts",
            "totlenfwdpkts": "totallengthoffwdpackets",
            "totallengthoffwdpackets": "totlenfwdpkts",
            "totlenbwdpkts": "totallengthofbwdpackets",
            "totallengthofbwdpackets": "totlenbwdpkts",
            
            # 6. Granular Packet Size Characteristics
            "fwdpacketlengthmax": "fwdpktlenmax",
            "fwdpacketlengthmin": "fwdpktlenmin",
            "fwdpacketlengthmean": "fwdpktlenmean",
            "fwdpacketlengthstd": "fwdpktlenstd",
            "bwdpacketlengthmax": "bwdpktlenmax",
            "bwdpacketlengthmin": "bwdpktlenmin",
            "bwdpacketlengthmean": "bwdpktlenmean",
            "bwdpacketlengthstd": "bwdpktlenstd",
            "packetlengthmax": "pktlenmax",
            "packetlengthmin": "pktlenmin",
            "packetlengthmean": "pktlenmean",
            "packetlengthstd": "pktlenstd",
            "packetlengthvariance": "pktlenvar",
            "packetlengthvar": "pktlenvar",
            "minpacketlength": "pktlenmin",
            "maxpacketlength": "pktlenmax",
            
            # 7. Inter-Arrival Time (IAT) Metric Signatures
            "flowiatmaximum": "flowiatmax",
            "flowiatminimum": "flowiatmin",
            "fwdiatmaximum": "fwdiatmax",
            "fwdiatminimum": "fwdiatmin",
            "fwdiattotal": "fwdiattot",
            "fwdiattot": "fwdiattotal",
            "bwdiatmaximum": "bwdiatmax",
            "bwdiatminimum": "bwdiatmin",
            "bwdiattotal": "bwdiattot",
            "bwdiattot": "bwdiattotal",
            
            # 8. Frame Headers, TCP Windowing, and Flag State Variables
            "fwdheaderlength": "fwdheaderlen",
            "bwdheaderlength": "bwdheaderlen",
            "fwdheaderlen": "fwdheaderlength",
            "bwdheaderlen": "bwdheaderlength",
            "minsegsizeforward": "fwdsegsizemin",
            "fwdsegsizemin": "minsegsizeforward",
            "actdatapktfwd": "fwdactdatapkts",
            "fwdactdatapkts": "actdatapktfwd",
            "initwinbytesforward": "initfwdwinbyts",
            "initwinbytesbackward": "initbwdwinbyts",
            "initfwdwinbyts": "initwinbytesforward",
            "initbwdwinbyts": "initwinbytesbackward",
            "finflagcount": "finflagcnt",
            "synflagcount": "synflagcnt",
            "rstflagcount": "rstflagcnt",
            "pshflagcount": "pshflagcnt",
            "ackflagcount": "ackflagcnt",
            "urgflagcount": "urgflagcnt",
            "eceflagcount": "eceflagcnt",
            "cweflagcount": "cwrflagcount",
            "finflagcnt": "finflagcount",
            "synflagcnt": "synflagcount",
            "rstflagcnt": "rstflagcount",
            "pshflagcnt": "pshflagcount",
            "ackflagcnt": "ackflagcount",
            "urgflagcnt": "urgflagcount",
            "eceflagcnt": "eceflagcount",
            "cwrflagcount": "cweflagcount",
            "subflowfwdpackets": "subflowfwdpkts",
            "subflowfwdbytes": "subflowfwdbyts",
            "subflowbwdpackets": "subflowbwdpkts",
            "subflowbwdbytes": "subflowbwdbyts",
            "subflowfwdpkts": "subflowfwdpackets",
            "subflowfwdbyts": "subflowfwdbytes"
        }

    def _normalize(self, name: str) -> str:
        """
        Cleans and sanitizes arbitrary feature identifiers using a deterministic transformation.
        
        Removes all whitespace characters, dashes, trailing periods, and underscores,
        returning a standard lowercase structural keyword.
        """
        if not name:
            return ""
        clean_name: Final[str] = re.sub(r'[\s_.\-/]', '', name).strip().lower()
        return self._aliases.get(clean_name, clean_name)

    def map(self, available_features: dict[str, float], required_features: list[str]) -> np.ndarray:
        """
        Generates an ordered NumPy inference vector matching the required feature signatures.
        """
        vector, _ = self.map_with_report(available_features, required_features)
        return vector

    def map_with_report(self, available_features: dict[str, float], required_features: list[str]) -> tuple[np.ndarray, list[str]]:
        """
        Compiles the aligned numerical inference array and generates a structural missing-fields audit report.
        """
        normalized_available: Final[dict[str, float]] = {}
        for k, v in available_features.items():
            norm_k = self._normalize(k)
            normalized_available[norm_k] = v
            
            raw_clean = re.sub(r'[\s_.\-/]', '', k).strip().lower()
            normalized_available[raw_clean] = v

        vector: Final[np.ndarray] = np.empty(len(required_features), dtype=float)
        missing_features: list[str] = []

        for i, feature_name in enumerate(required_features):
            key = self._normalize(feature_name)
            raw_clean_req = re.sub(r'[\s_.\-/]', '', feature_name).strip().lower()
            base_raw_clean = re.sub(r'\d+$', '', raw_clean_req)
            
            matched_value = None
            
            # Cascading fallback lookup routine
            if key in normalized_available:
                matched_value = normalized_available[key]
            elif raw_clean_req in normalized_available:
                matched_value = normalized_available[raw_clean_req]
            elif base_raw_clean in normalized_available:
                matched_value = normalized_available[base_raw_clean]
            else:
                for target_key, alias_val in self._aliases.items():
                    if target_key == key and alias_val in normalized_available:
                        matched_value = normalized_available[alias_val]
                        break
                    if alias_val == key and target_key in normalized_available:
                        matched_value = normalized_available[target_key]
                        break

            if matched_value is not None:
                try:
                    val = float(matched_value)
                    vector[i] = self._fill if not np.isfinite(val) else val
                except (ValueError, TypeError):
                    vector[i] = self._fill
            else:
                vector[i] = self._fill
                missing_features.append(feature_name)

        return vector, missing_features

    def map_dataframe_with_report(
        self, 
        df: pd.DataFrame, 
        required_features: list[str],
        as_numpy: bool = False
    ) -> tuple[Union[pd.DataFrame, np.ndarray], list[str]]:
        """
        Dynamically aligns batch DataFrames to target model schemas.
        
        Handles structural column mapping, missing feature imputation, extra feature truncation,
        and enforces strict 2D dimensionality output arrays (n_samples, n_features) when returning NumPy arrays.
        """
        if df.empty:
            empty_res = np.empty((0, len(required_features)), dtype=float) if as_numpy else pd.DataFrame(columns=required_features)
            return empty_res, required_features

        # Build column normalization lookup map for current DataFrame
        column_map: dict[str, str] = {}
        for col in df.columns:
            norm_col = self._normalize(col)
            column_map[norm_col] = col
            
            raw_clean = re.sub(r'[\s_.\-/]', '', col).strip().lower()
            column_map[raw_clean] = col

        aligned_df = pd.DataFrame(index=df.index)
        missing_features: list[str] = []

        for feature_name in required_features:
            key = self._normalize(feature_name)
            raw_clean_req = re.sub(r'[\s_.\-/]', '', feature_name).strip().lower()
            base_raw_clean = re.sub(r'\d+$', '', raw_clean_req)

            matched_col = None

            if key in column_map:
                matched_col = column_map[key]
            elif raw_clean_req in column_map:
                matched_col = column_map[raw_clean_req]
            elif base_raw_clean in column_map:
                matched_col = column_map[base_raw_clean]
            else:
                for target_key, alias_val in self._aliases.items():
                    if target_key == key and alias_val in column_map:
                        matched_col = column_map[alias_val]
                        break
                    if alias_val == key and target_key in column_map:
                        matched_col = column_map[target_key]
                        break

            if matched_col is not None:
                aligned_df[feature_name] = (
                    pd.to_numeric(df[matched_col], errors="coerce")
                    .replace([np.inf, -np.inf], np.nan)
                    .fillna(self._fill)
                )
            else:
                aligned_df[feature_name] = self._fill
                missing_features.append(feature_name)

        if as_numpy:
            np_array = aligned_df.to_numpy(dtype=float)
            
            # --- Strict 2D Dimensionality Guarding ---
            # Flattens 3D arrays like (1, N, Features) directly into 2D (N, Features)
            if np_array.ndim == 3 and np_array.shape[0] == 1:
                np_array = np_array.squeeze(axis=0)
            elif np_array.ndim > 2:
                np_array = np_array.reshape(-1, len(required_features))
                
            return np_array, missing_features

        return aligned_df, missing_features

    def validate_minimum_coverage(
        self, available_features: dict[str, float], required_features: list[str], min_coverage: float = 0.5
    ) -> None:
        """
        Structural Integrity Guardrail.
        
        Evaluates metrics coverage to block inference pipelines from executing decisions on 
        empty, corrupt, or significantly malformed telemetry streams.
        
        Raises:
            ValidationError: If total mapped metrics coverage drops below the required threshold.
        """
        if not required_features:
            return

        _, missing = self.map_with_report(available_features, required_features)
        coverage: Final[float] = 1.0 - (len(missing) / len(required_features))
        
        if coverage < min_coverage:
            raise ValidationError(
                f"Defensive Barrier Triggered: Only {coverage:.0%} of required features are present "
                f"(missing count: {len(missing)}). Minimum required coverage is {min_coverage:.0%}."
            )