from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Final

import numpy as np

from capture.flow import Flow
from infrastructure.logging.logger_factory import get_logger

logger = get_logger("capture.flow_feature_calculator")


@dataclass(frozen=True)
class FlowFeatures:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    features: Dict[str, float]


class FlowFeatureCalculator:

    def compute(self, flow: Flow) -> FlowFeatures:
        packets = flow.packets
        if not packets:
            logger.error("Feature extraction computation failed: target flow context has zero recorded observations.")
            raise ValueError("Cannot compute statistical features across an uninitialized or empty flow structure.")

        timestamps: Final[np.ndarray] = np.array([p.timestamp for p in packets], dtype=float)
        sizes: Final[np.ndarray] = np.array([p.size_bytes for p in packets], dtype=float)
        is_fwd: Final[np.ndarray] = np.array([p.is_forward for p in packets], dtype=bool)

        duration: Final[float] = float(timestamps.max() - timestamps.min())
        duration_safe: Final[float] = duration if duration > 0.0 else 1e-6

        fwd_sizes: Final[np.ndarray] = sizes[is_fwd]
        bwd_sizes: Final[np.ndarray] = sizes[~is_fwd]

        total_fwd_packets: Final[int] = int(is_fwd.sum())
        total_bwd_packets: Final[int] = int((~is_fwd).sum())
        total_len_fwd: Final[float] = float(fwd_sizes.sum()) if fwd_sizes.size else 0.0
        total_len_bwd: Final[float] = float(bwd_sizes.sum()) if bwd_sizes.size else 0.0

        flow_iat: Final[np.ndarray] = np.diff(np.sort(timestamps)) if len(timestamps) > 1 else np.array([0.0])

        fwd_timestamps = timestamps[is_fwd]
        bwd_timestamps = timestamps[~is_fwd]

        fwd_iat: Final[np.ndarray] = np.diff(np.sort(fwd_timestamps)) if len(fwd_timestamps) > 1 else np.array([0.0])
        bwd_iat: Final[np.ndarray] = np.diff(np.sort(bwd_timestamps)) if len(bwd_timestamps) > 1 else np.array([0.0])

        syn_count: Final[int] = sum(1 for p in packets if p.syn)
        ack_count: Final[int] = sum(1 for p in packets if p.ack)
        rst_count: Final[int] = sum(1 for p in packets if p.rst)
        fin_count: Final[int] = sum(1 for p in packets if p.fin)
        psh_count: Final[int] = sum(1 for p in packets if p.psh)
        urg_count: Final[int] = sum(1 for p in packets if p.urg)
        ece_count: Final[int] = sum(1 for p in packets if p.ece)
        cwr_count: Final[int] = sum(1 for p in packets if p.cwr)

        # Forward-only flag counts (CICFlowMeter convention: Fwd PSH Flags)
        fwd_psh_count: Final[int] = sum(1 for p in packets if p.is_forward and p.psh)

        init_win_fwd: Final[int] = next((p.window_size for p in packets if p.is_forward), 0)
        init_win_bwd: Final[int] = next((p.window_size for p in packets if not p.is_forward), 0)

        # Header length arrays
        fwd_header_lengths: Final[np.ndarray] = np.array(
            [p.header_length for p in packets if p.is_forward], dtype=float
        )
        bwd_header_lengths: Final[np.ndarray] = np.array(
            [p.header_length for p in packets if not p.is_forward], dtype=float
        )
        fwd_header_len_total: Final[float] = float(fwd_header_lengths.sum()) if fwd_header_lengths.size else 0.0
        bwd_header_len_total: Final[float] = float(bwd_header_lengths.sum()) if bwd_header_lengths.size else 0.0

        act_data_pkt_fwd: Final[int] = sum(1 for p in packets if p.is_forward and p.size_bytes > 0)
        min_seg_size_forward: Final[float] = float(fwd_header_lengths.min()) if fwd_header_lengths.size else 0.0

        active_mean, active_std, active_max, active_min, idle_mean, idle_std, idle_max, idle_min = self._active_idle_stats(timestamps)

        features: Final[Dict[str, float]] = {
            "Destination Port": float(flow.dst_port),
            "Protocol": float(flow.protocol),
            "Flow Duration": duration * 1_000_000.0,
            "Total Fwd Packets": float(total_fwd_packets),
            "Total Backward Packets": float(total_bwd_packets),
            "Total Length of Fwd Packets": total_len_fwd,
            "Total Length of Bwd Packets": total_len_bwd,
            "Fwd Packet Length Max": float(fwd_sizes.max()) if fwd_sizes.size else 0.0,
            "Fwd Packet Length Min": float(fwd_sizes.min()) if fwd_sizes.size else 0.0,
            "Fwd Packet Length Mean": float(fwd_sizes.mean()) if fwd_sizes.size else 0.0,
            "Fwd Packet Length Std": float(fwd_sizes.std(ddof=0)) if fwd_sizes.size > 1 else 0.0,
            "Bwd Packet Length Max": float(bwd_sizes.max()) if bwd_sizes.size else 0.0,
            "Bwd Packet Length Min": float(bwd_sizes.min()) if bwd_sizes.size else 0.0,
            "Bwd Packet Length Mean": float(bwd_sizes.mean()) if bwd_sizes.size else 0.0,
            "Bwd Packet Length Std": float(bwd_sizes.std(ddof=0)) if bwd_sizes.size > 1 else 0.0,
            "Flow Bytes/s": float(sizes.sum() / duration_safe),
            "Flow Packets/s": float(len(packets) / duration_safe),
            "Flow IAT Mean": float(flow_iat.mean() * 1_000_000.0),
            "Flow IAT Std": float(flow_iat.std(ddof=0) * 1_000_000.0) if len(flow_iat) > 1 else 0.0,
            "Flow IAT Max": float(flow_iat.max() * 1_000_000.0) if len(flow_iat) > 0 else 0.0,
            "Flow IAT Min": float(flow_iat.min() * 1_000_000.0) if len(flow_iat) > 0 else 0.0,
            "Fwd IAT Total": float(fwd_iat.sum() * 1_000_000.0) if len(fwd_iat) > 0 else 0.0,
            "Fwd IAT Mean": float(fwd_iat.mean() * 1_000_000.0) if fwd_iat.size else 0.0,
            "Fwd IAT Std": float(fwd_iat.std(ddof=0) * 1_000_000.0) if len(fwd_iat) > 1 else 0.0,
            "Fwd IAT Max": float(fwd_iat.max() * 1_000_000.0) if len(fwd_iat) > 0 else 0.0,
            "Fwd IAT Min": float(fwd_iat.min() * 1_000_000.0) if len(fwd_iat) > 0 else 0.0,
            "Bwd IAT Total": float(bwd_iat.sum() * 1_000_000.0) if len(bwd_iat) > 0 else 0.0,
            "Bwd IAT Mean": float(bwd_iat.mean() * 1_000_000.0) if bwd_iat.size else 0.0,
            "Bwd IAT Std": float(bwd_iat.std(ddof=0) * 1_000_000.0) if len(bwd_iat) > 1 else 0.0,
            "Bwd IAT Max": float(bwd_iat.max() * 1_000_000.0) if len(bwd_iat) > 0 else 0.0,
            "Bwd IAT Min": float(bwd_iat.min() * 1_000_000.0) if len(bwd_iat) > 0 else 0.0,
            "Fwd PSH Flags": float(fwd_psh_count),
            "Fwd Header Length": fwd_header_len_total,
            "Bwd Header Length": bwd_header_len_total,
            "Fwd Packets/s": float(total_fwd_packets / duration_safe),
            "Bwd Packets/s": float(total_bwd_packets / duration_safe),
            "Min Packet Length": float(sizes.min()) if sizes.size else 0.0,
            "Max Packet Length": float(sizes.max()) if sizes.size else 0.0,
            "Packet Length Mean": float(sizes.mean()) if sizes.size else 0.0,
            "Packet Length Std": float(sizes.std(ddof=0)) if sizes.size > 1 else 0.0,
            "Packet Length Variance": float(sizes.var(ddof=0)) if sizes.size > 1 else 0.0,
            "FIN Flag Count": float(fin_count),
            "SYN Flag Count": float(syn_count),
            "RST Flag Count": float(rst_count),
            "PSH Flag Count": float(psh_count),
            "ACK Flag Count": float(ack_count),
            "URG Flag Count": float(urg_count),
            "CWR Flag Count": float(cwr_count),
            "ECE Flag Count": float(ece_count),
            "Down/Up Ratio": float(total_bwd_packets // total_fwd_packets) if total_fwd_packets > 0 else 0.0,
            "Average Packet Size": float(sizes.mean()) if sizes.size else 0.0,
            "Avg Fwd Segment Size": float(fwd_sizes.mean()) if fwd_sizes.size else 0.0,
            "Avg Bwd Segment Size": float(bwd_sizes.mean()) if bwd_sizes.size else 0.0,
            "Subflow Fwd Packets": float(total_fwd_packets),
            "Subflow Fwd Bytes": total_len_fwd,
            "Subflow Bwd Packets": float(total_bwd_packets),
            "Subflow Bwd Bytes": total_len_bwd,
            "Init_Win_bytes_forward": float(init_win_fwd),
            "Init_Win_bytes_backward": float(init_win_bwd),
            "act_data_pkt_fwd": float(act_data_pkt_fwd),
            "min_seg_size_forward": min_seg_size_forward,
            "Active Mean": active_mean,
            "Active Std": active_std,
            "Active Max": active_max,
            "Active Min": active_min,
            "Idle Mean": idle_mean,
            "Idle Std": idle_std,
            "Idle Max": idle_max,
            "Idle Min": idle_min,
            "Fwd Header Length.1": fwd_header_len_total,
        }

        return FlowFeatures(
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            features=features,
        )

    @staticmethod
    def _active_idle_stats(timestamps: np.ndarray) -> tuple[float, float, float, float, float, float, float, float]:
        """
        Computes CICFlowMeter Active/Idle burst statistics from packet timestamps.

        Mirrors the CICFlowMeter convention used to generate the CICIDS2017 training
        corpus: a gap larger than ACTIVITY_TIMEOUT (5 seconds, derived empirically
        from the dataset's Idle/Flow-IAT boundary) closes the current active burst
        and opens an idle period equal to that gap. Durations are in microseconds.
        Returns (active_mean, active_std, active_max, active_min,
                 idle_mean, idle_std, idle_max, idle_min) or all zeros when there is
        no burst structure.
        """
        zeros: Final[tuple[float, float, float, float, float, float, float, float]] = (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        if timestamps is None or len(timestamps) < 2:
            return zeros

        ordered: Final[np.ndarray] = np.sort(timestamps.astype(np.float64))
        active_us: Final[List[float]] = []
        idle_us: Final[List[float]] = []

        start_active: float = ordered[0]
        end_active: float = ordered[0]
        for ts in ordered[1:]:
            gap_us: float = (ts - end_active) * 1_000_000.0
            if gap_us > 5_000_000.0:
                if end_active - start_active > 0.0:
                    active_us.append((end_active - start_active) * 1_000_000.0)
                idle_us.append(gap_us)
                start_active = ts
                end_active = ts
            else:
                end_active = ts
        # NOTE: CICFlowMeter's FlowGenerator does NOT record the trailing active
        # burst at flow end (endActiveIdleTime is commented out in the timeout path
        # and never called on FIN/RST termination), so single-burst flows yield
        # Active=0/Idle=0 exactly as observed throughout CICIDS2017.

        def stats(vals: List[float]) -> tuple[float, float, float, float]:
            if not vals:
                return (0.0, 0.0, 0.0, 0.0)
            arr: Final[np.ndarray] = np.asarray(vals, dtype=np.float64)
            mean: Final[float] = float(arr.mean())
            std: Final[float] = float(arr.std(ddof=0))
            maximum: Final[float] = float(arr.max())
            minimum: Final[float] = float(arr.min())
            return (mean, std, maximum, minimum)

        a_mean, a_std, a_max, a_min = stats(active_us)
        i_mean, i_std, i_max, i_min = stats(idle_us)
        return (a_mean, a_std, a_max, a_min, i_mean, i_std, i_max, i_min)

    def compute_many(self, flows: List[Flow]) -> List[FlowFeatures]:
        logger.debug("Executing batch feature extraction pipeline across %d active flow allocations.", len(flows))
        results: List[FlowFeatures] = []

        for flow in flows:
            if not flow.is_empty:
                results.append(self.compute(flow))

        logger.info("Batch feature calculation routine completed. Parsed %d vectors successfully.", len(results))
        return results
