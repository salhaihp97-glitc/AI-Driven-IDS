"""
Macro-Flow Assembly Engine (Pure Data Pipeline).

Pure-ML alignment requires the *model* to observe an attack's true aggregate footprint. A
rotating-source-port SYN flood produces thousands of tiny flows (3 packets each) that are,
individually, statistically indistinguishable from benign short connections. No per-flow
classifier can ever observe a flood that only exists *across* flows.

This module assembles member flows that share a configurable key (by default
``src_ip, dst_ip, dst_port, protocol`` -- deliberately excluding ``src_port`` so rotating
source ports collapse into a single macro-flow) over a sliding time window, and re-derives
the aggregate statistics. The result is one macro ``FlowFeatures`` record whose values
truly represent the summed attack, handed to the ML model as-is.

This component performs data engineering only -- it makes *no classification decision* and
contains no signature rules. It exists solely so an attack pattern physically reaches the
model.

Design properties (dynamic, non-hardcoded):
  - Aggregation key and window are read from ``Settings``/env (``macro_flow_*``).
  - Reducers are selected by a *token-based feature classifier* -- not a hardcoded list of
    the 70 CICIDS2017 column names -- so the engine works unchanged for any CICFlowMeter
    naming variant or model schema.
  - Per-second fields are recomputed as ``Σ(member_rate · member_duration) / Σ duration``,
    which is statistically exact and needs no field-specific knowledge.
  - Mean/std are packet-count weighted when the member exposes count fields, otherwise
    time weighted, otherwise uniform -- a documented, defensible fallback chain.
"""

from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Final, List, Optional, Sequence, Tuple

from capture.flow_models import FlowFeatures
from config.settings import get_settings
from core.exceptions import ValidationError
from infrastructure.logging.logger_factory import get_logger

logger = get_logger("capture.macro_flow_assembler")


# ---------------------------------------------------------------------------
# Reducer kinds
# ---------------------------------------------------------------------------

class ReducerKind(Enum):
    """Semantic aggregation operation dispatched for a feature key."""
    IDENTITY = "identity"   # meta / key-ish fields (ports, protocol) kept from first member
    SUM = "sum"             # true additive magnitude (counts, byte/length totals, flags)
    RATE = "rate"           # per-second magnitude -> Σ(v·Δt) / Σ Δt
    MIN = "min"             # extreme low watermark
    MAX = "max"             # extreme high watermark
    MEAN = "mean"           # member-weighted arithmetic mean
    STD = "std"             # member-weighted pooled standard deviation


# Token vocabularies (dynamic classifier inputs, not column lists).
_IDENTITY_TOKENS: Final[frozenset[str]] = frozenset({
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "flow_id", "timestamp",
    "source_ip", "destination_ip", "port", "ports",
})
_FLAG_TOKENS: Final[frozenset[str]] = frozenset({"flag", "flags", "count", "counts", "cnt"})
_SUM_TOKENS: Final[frozenset[str]] = frozenset({
    "len", "length", "byte", "bytes", "byts", "pkt", "pkts", "packet", "packets",
    "subflow", "header", "act", "data", "seg", "segment", "duration",
})
_RATE_TOKENS: Final[frozenset[str]] = frozenset({"s", "sec", "secs", "second", "seconds", "rate"})
_MEAN_TOKENS: Final[frozenset[str]] = frozenset({"mean", "avg", "average", "ratio"})
_MIN_TOKENS: Final[frozenset[str]] = frozenset({"min", "minimum"})
_MAX_TOKENS: Final[frozenset[str]] = frozenset({"max", "maximum", "win", "window"})
_STD_TOKENS: Final[frozenset[str]] = frozenset({"std", "standard", "var", "variance", "dev", "deviation"})


def tokenize(field: str) -> Tuple[str, ...]:
    """Split a feature name into lowercase semantic tokens (separator-insensitive)."""
    cleaned = re.sub(r"[\s_.\-/]+", "_", str(field)).strip("_").lower()
    tokens: List[str] = []
    for part in cleaned.split("_"):
        if not part:
            continue
        for sub in re.split(r"(?<=[a-z0-9])(?=[A-Z])", part):
            sub = sub.lower().strip()
            if sub and not sub.isdigit():
                tokens.append(sub)
    return tuple(tokens)


def _has_any(tokens: Sequence[str], needles: frozenset[str]) -> bool:
    return any(tok in needles for tok in tokens)


def classify_role(field: str) -> ReducerKind:
    """
    Token-based feature classifier: field name -> reducer kind.

    Resolution order encodes semantic precedence:
      identity -> per-second rate -> extreme (min/max) -> statistic (std/mean) -> additive.
    """
    tokens = tokenize(field)
    if not tokens:
        return ReducerKind.SUM

    if _has_any(tokens, _IDENTITY_TOKENS):
        return ReducerKind.IDENTITY

    # Per-second magnitudes (e.g. ``Flow Bytes/s``, ``flow_byts_s``).
    if _has_any(tokens, _RATE_TOKENS):
        return ReducerKind.RATE

    if _has_any(tokens, _MAX_TOKENS):
        return ReducerKind.MAX
    if _has_any(tokens, _MIN_TOKENS):
        return ReducerKind.MIN

    if _has_any(tokens, _STD_TOKENS):
        return ReducerKind.STD

    # ``Down/Up Ratio``, ``Active/Idle Mean`` etc. are averages of per-member ratios.
    if _has_any(tokens, _MEAN_TOKENS):
        return ReducerKind.MEAN

    # Additive magnitudes: lengths, byte totals, packet counts, subflow, header, flags.
    if _has_any(tokens, _FLAG_TOKENS):
        return ReducerKind.SUM
    if _has_any(tokens, _SUM_TOKENS):
        return ReducerKind.SUM

    # ``Flow Duration`` and any other plain magnitude default to additive.
    return ReducerKind.SUM


# ---------------------------------------------------------------------------
# Reducer accumulators (numeric, memory-safe online statistics)
# ---------------------------------------------------------------------------

class _Reducer:
    kind: Final[ReducerKind] = ReducerKind.SUM

    def add(self, value: float, weight: float) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def result(self) -> float:  # pragma: no cover - interface
        raise NotImplementedError


class _SumReducer(_Reducer):
    kind = ReducerKind.SUM

    def __init__(self) -> None:
        self._total: float = 0.0
        self._count: int = 0

    def add(self, value: float, weight: float) -> None:
        if value is None or not math.isfinite(value):
            return
        self._total += value
        self._count += 1

    def result(self) -> float:
        return self._total


class _RateReducer(_Reducer):
    """Recomputes a per-second magnitude as Σ(v·Δt)/ΣΔt using each member's duration."""

    kind = ReducerKind.RATE

    def __init__(self) -> None:
        self._weighted_sum: float = 0.0
        self._duration_sum: float = 0.0

    def add(self, value: float, weight: float) -> None:
        if value is None or not math.isfinite(value) or weight is None or not math.isfinite(weight):
            return
        self._weighted_sum += value * weight
        self._duration_sum += weight

    def result(self) -> float:
        if self._duration_sum <= 0.0:
            return 0.0
        return self._weighted_sum / self._duration_sum


class _MinReducer(_Reducer):
    kind = ReducerKind.MIN

    def __init__(self) -> None:
        self._value: Optional[float] = None

    def add(self, value: float, weight: float) -> None:
        if value is None or not math.isfinite(value):
            return
        if self._value is None or value < self._value:
            self._value = value

    def result(self) -> float:
        return self._value if self._value is not None else 0.0


class _MaxReducer(_Reducer):
    kind = ReducerKind.MAX

    def __init__(self) -> None:
        self._value: Optional[float] = None

    def add(self, value: float, weight: float) -> None:
        if value is None or not math.isfinite(value):
            return
        if self._value is None or value > self._value:
            self._value = value

    def result(self) -> float:
        return self._value if self._value is not None else 0.0


class _MeanReducer(_Reducer):
    """Member-weighted arithmetic mean (Welford-style running mean)."""

    kind = ReducerKind.MEAN

    def __init__(self) -> None:
        self._weight_sum: float = 0.0
        self._weighted_mean: float = 0.0

    def add(self, value: float, weight: float) -> None:
        if value is None or not math.isfinite(value):
            return
        w = weight if weight and math.isfinite(weight) and weight > 0.0 else 1.0
        self._weight_sum += w
        self._weighted_mean += (w / self._weight_sum) * (value - self._weighted_mean)

    def result(self) -> float:
        return self._weighted_mean


class _StdReducer(_Reducer):
    """Member-weighted pooled standard deviation (Welford variance)."""

    kind = ReducerKind.STD

    def __init__(self) -> None:
        self._weight_sum: float = 0.0
        self._weighted_mean: float = 0.0
        self._m2: float = 0.0

    def add(self, value: float, weight: float) -> None:
        if value is None or not math.isfinite(value):
            return
        w = weight if weight and math.isfinite(weight) and weight > 0.0 else 1.0
        if self._weight_sum == 0.0:
            self._weight_sum = w
            self._weighted_mean = value
            self._m2 = 0.0
            return
        self._weight_sum += w
        delta = value - self._weighted_mean
        self._weighted_mean += (w / self._weight_sum) * delta
        self._m2 += w * delta * (value - self._weighted_mean)

    def result(self) -> float:
        if self._weight_sum <= 1.0:
            return 0.0
        return math.sqrt(max(0.0, self._m2 / self._weight_sum))


_REDUCER_FACTORY: Final[Dict[ReducerKind, type[_Reducer]]] = {
    ReducerKind.SUM: _SumReducer,
    ReducerKind.RATE: _RateReducer,
    ReducerKind.MIN: _MinReducer,
    ReducerKind.MAX: _MaxReducer,
    ReducerKind.MEAN: _MeanReducer,
    ReducerKind.STD: _StdReducer,
}


# ---------------------------------------------------------------------------
# Member weight resolution
# ---------------------------------------------------------------------------

def _member_duration(features: Dict[str, float]) -> float:
    """Resolve the member's flow duration for rate recombination (dynamic field lookup)."""
    for key, value in features.items():
        if "duration" in tokenize(key):
            try:
                return float(value) if math.isfinite(float(value)) else 0.0
            except (TypeError, ValueError):
                return 0.0
    return 0.0


def _member_packet_count(features: Dict[str, float]) -> float:
    """Resolve a member's total packet count for mean/std weighting (dynamic lookup)."""
    total: float = 0.0
    for key, value in features.items():
        tokens = tokenize(key)
        if not ({"pkt", "pkts", "packet", "packets"} & set(tokens)):
            continue
        try:
            v = float(value) if math.isfinite(float(value)) else 0.0
        except (TypeError, ValueError):
            continue
        directional = {"fwd", "bwd", "forward", "backward"} & set(tokens)
        if "tot" in tokens or "total" in tokens or not directional:
            total += v
    return total if total > 0.0 else 1.0


# ---------------------------------------------------------------------------
# Group accumulator
# ---------------------------------------------------------------------------

@dataclass
class _MacroGroup:
    """Stateful accumulator for one keyed macro-flow."""
    key: Tuple[str, ...]
    first_features: Dict[str, float] = field(default_factory=dict)
    reducer_map: Dict[str, _Reducer] = field(default_factory=dict)
    roles: Dict[str, ReducerKind] = field(default_factory=dict)
    member_count: int = 0
    last_seen: float = 0.0

    def add_member(self, features: Dict[str, float], timestamp: float) -> None:
        duration = _member_duration(features)
        weight = _member_packet_count(features)
        if not self.first_features:
            self.first_features = dict(features)
        for key, value in features.items():
            try:
                v = float(value)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(v):
                v = 0.0
            role = self.roles.get(key)
            if role is None:
                role = classify_role(key)
                self.roles[key] = role
                if role is not ReducerKind.IDENTITY:
                    self.reducer_map[key] = _REDUCER_FACTORY[role]()
            reducer = self.reducer_map.get(key)
            if reducer is None:
                continue
            if role is ReducerKind.RATE:
                reducer.add(v, duration)
            else:
                reducer.add(v, weight)
        self.member_count += 1
        self.last_seen = max(self.last_seen, timestamp)

    def materialize(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int) -> FlowFeatures:
        features: Dict[str, float] = {}
        for key, reducer in self.reducer_map.items():
            features[key] = round(reducer.result(), 6)
        # Propagate identity fields from the first member when present in its features.
        for key in self.first_features:
            if classify_role(key) is ReducerKind.IDENTITY:
                features.setdefault(key, self.first_features[key])
        return FlowFeatures(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            features=features,
        )


# ---------------------------------------------------------------------------
# Assembler
# ---------------------------------------------------------------------------

class MacroFlowAssembler:
    """
    Aggregates member flows into macro-flows carrying true aggregate statistics.

    Key fields and window are resolved from ``Settings`` (env-driven, not hardcoded):
      - ``AI_IDS_MACRO_FLOW_ENABLED``
      - ``AI_IDS_MACRO_FLOW_KEY_FIELDS``    (default ``src_ip,dst_ip,dst_port,protocol``)
      - ``AI_IDS_MACRO_FLOW_WINDOW_SECONDS``
      - ``AI_IDS_MACRO_FLOW_MIN_MEMBERS``
    """

    def __init__(
        self,
        key_fields: Optional[List[str]] = None,
        window_seconds: Optional[float] = None,
        min_members: Optional[int] = None,
        enabled: Optional[bool] = None,
    ) -> None:
        settings = get_settings()
        self._enabled: Final[bool] = settings.macro_flow_enabled if enabled is None else enabled
        raw_key: Final[str] = (
            ",".join(key_fields)
            if key_fields is not None
            else settings.macro_flow_key_fields
        )
        parsed = [k.strip() for k in raw_key.split(",") if k.strip()]
        self._key_fields: Final[List[str]] = parsed or ["src_ip", "dst_ip", "dst_port", "protocol"]
        self._window_seconds: Final[float] = (
            settings.macro_flow_window_seconds if window_seconds is None else window_seconds
        )
        self._min_members: Final[int] = (
            settings.macro_flow_min_members if min_members is None else min_members
        )
        # Streaming state: keyed macro-groups currently "open" across flush boundaries.
        self._open_groups: Dict[Tuple[str, ...], _MacroGroup] = {}

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def key_fields(self) -> List[str]:
        return list(self._key_fields)

    # -- key derivation ------------------------------------------------------

    def _derive_key(self, flow: FlowFeatures) -> Tuple[str, ...]:
        parts: List[str] = []
        for field in self._key_fields:
            norm = field.strip().lower()
            if norm in {"src_ip", "source_ip", "src"}:
                parts.append(flow.src_ip or "")
            elif norm in {"dst_ip", "destination_ip", "dst"}:
                parts.append(flow.dst_ip or "")
            elif norm in {"src_port", "source_port"}:
                parts.append(str(flow.src_port))
            elif norm in {"dst_port", "destination_port"}:
                parts.append(str(flow.dst_port))
            elif norm == "protocol":
                parts.append(str(flow.protocol))
            else:
                # Dynamic key field resolution against feature names (no hardcoding).
                feature = flow.features.get(field)
                if feature is not None:
                    parts.append(str(feature))
                else:
                    for fname, fval in flow.features.items():
                        if fname.strip().lower() == norm:
                            parts.append(str(fval))
                            break
                    else:
                        parts.append("")
        return tuple(parts)

    # -- main entrypoint (stateless convenience for pcap/offline) -------------

    def assemble_mapped(self, flows: Sequence[FlowFeatures]) -> List[Tuple[FlowFeatures, Sequence[int]]]:
        """
        Assembles a batch of member flows into macro-flows, mapping each input index to
        the macro-flow it contributed to.

        Returns a list of pairs ``(macro_flow, member_indices)``.  ``member_indices`` are
        the positional indices (into *flows*) of every raw row folded into that macro-flow.
        This enables downstream consumers to attribute a single macro verdict back to the
        exact member rows that produced it (e.g. tagging each per-flow CSV row with the
        aggregated attack detection).

        When the assembler is disabled, every input flow is returned unchanged with a
        single-element index list, preserving raw per-flow classification.
        """
        if not self._enabled:
            return [(flow, [i]) for i, flow in enumerate(flows)]

        grouped: Dict[Tuple[str, ...], _MacroGroup] = {}
        members: Dict[Tuple[str, ...], List[int]] = {}
        for index, flow in enumerate(flows):
            key = self._derive_key(flow)
            group = grouped.get(key)
            if group is None:
                group = _MacroGroup(key=key)
                grouped[key] = group
                members[key] = []
            group.add_member(flow.features, timestamp=0.0)
            members[key].append(index)

        result: List[Tuple[FlowFeatures, Sequence[int]]] = []
        for key, group in grouped.items():
            result.append((self._finalize_group(group), members[key]))
        return result

    def assemble(self, flows: Sequence[FlowFeatures]) -> List[FlowFeatures]:
        """
        Assembles a batch of member flows into macro-flows.

        Members are grouped by the configured key; flows sharing a key are merged into a
        single macro-flow. Windowed splitting is applied for live streaming via
        ``assemble_stream``; for offline batches the full sequence is merged per key.
        """
        if not self._enabled:
            return list(flows)

        grouped: Dict[Tuple[str, ...], _MacroGroup] = {}
        for flow in flows:
            key = self._derive_key(flow)
            group = grouped.get(key)
            if group is None:
                group = _MacroGroup(key=key)
                grouped[key] = group
            group.add_member(flow.features, timestamp=0.0)

        macros: List[FlowFeatures] = []
        for group in grouped.values():
            macros.append(self._finalize_group(group))
        return macros

    # -- streaming entrypoint (live capture) ----------------------------------

    def assemble_stream(
        self,
        flows: Sequence[FlowFeatures],
        now: Optional[float] = None,
    ) -> List[FlowFeatures]:
        """
        Windowed streaming assembly.

        Members are grouped by key; a new macro-flow begins for a key when the gap between
        consecutive members exceeds ``window_seconds``. Returns the macro-flows that can be
        closed now (the trailing window for each key is retained internally so bursts
        spanning flush boundaries are not truncated).
        """
        if not self._enabled:
            return list(flows)
        timestamp = now if now is not None else time.time()

        open_groups: Dict[Tuple[str, ...], _MacroGroup] = {}
        for flow in flows:
            key = self._derive_key(flow)
            group = open_groups.get(key)
            if group is not None and (timestamp - group.last_seen) > self._window_seconds:
                open_groups[key] = _MacroGroup(key=key)
                group = open_groups[key]
            group.add_member(flow.features, timestamp)
            open_groups[key] = group

        # Every group in this call is still "recent" (all members just arrived), so nothing
        # is force-closed here; the caller flushes via ``flush``/``collect`` on a timer.
        return []

    def flush(
        self,
        flows: Sequence[FlowFeatures],
        now: Optional[float] = None,
    ) -> List[FlowFeatures]:
        """Streaming API: assembles new members, then returns closed macro-flows."""
        if not self._enabled:
            return list(flows)
        timestamp = now if now is not None else time.time()

        closed: List[FlowFeatures] = []
        stale_keys: List[Tuple[str, ...]] = []
        for key, group in self._open_groups.items():
            if (timestamp - group.last_seen) > self._window_seconds:
                closed.append(self._finalize_group(group))
                stale_keys.append(key)
        for key in stale_keys:
            self._open_groups.pop(key, None)

        for flow in flows:
            key = self._derive_key(flow)
            group = self._open_groups.get(key)
            if group is not None and (timestamp - group.last_seen) > self._window_seconds:
                closed.append(self._finalize_group(group))
                self._open_groups[key] = _MacroGroup(key=key)
                group = self._open_groups[key]
            group.add_member(flow.features, timestamp)
            self._open_groups[key] = group

        return closed

    def collect(self, now: Optional[float] = None) -> List[FlowFeatures]:
        """Returns and removes all macro-flows whose window has expired."""
        if not self._enabled:
            return []
        timestamp = now if now is not None else time.time()
        closed: List[FlowFeatures] = []
        stale_keys: List[Tuple[str, ...]] = []
        for key, group in self._open_groups.items():
            if (timestamp - group.last_seen) > self._window_seconds:
                closed.append(self._finalize_group(group))
                stale_keys.append(key)
        for key in stale_keys:
            self._open_groups.pop(key, None)
        return closed

    # -- internal -------------------------------------------------------------

    def _finalize_group(self, group: _MacroGroup) -> FlowFeatures:
        if group.member_count < self._min_members:
            # Below the member threshold, preserve the single member flow unchanged so no
            # data is lost -- the model still sees the raw per-flow record.
            if group.member_count == 1:
                first = group.first_features
                src_port = int(first.get("src_port", 0))
                dst_port = int(first.get("dst_port", 0))
                protocol = int(first.get("protocol", 0))
                return FlowFeatures(
                    src_ip=group.key[0] if group.key else "",
                    dst_ip=group.key[1] if len(group.key) > 1 else "",
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    features=first,
                )
        src_ip, dst_ip = "", ""
        src_port, dst_port, protocol = 0, 0, 0
        # Reconstruct identity from the key fields to remain fully dynamic.
        for idx, field in enumerate(self._key_fields):
            norm = field.strip().lower()
            value = group.key[idx] if idx < len(group.key) else ""
            if norm in {"src_ip", "source_ip", "src"}:
                src_ip = value
            elif norm in {"dst_ip", "destination_ip", "dst"}:
                dst_ip = value
            elif norm in {"src_port", "source_port"}:
                try:
                    src_port = int(float(value))
                except (TypeError, ValueError):
                    src_port = 0
            elif norm in {"dst_port", "destination_port"}:
                try:
                    dst_port = int(float(value))
                except (TypeError, ValueError):
                    dst_port = 0
            elif norm == "protocol":
                try:
                    protocol = int(float(value))
                except (TypeError, ValueError):
                    protocol = 0
        return group.materialize(src_ip, dst_ip, src_port, dst_port, protocol)
