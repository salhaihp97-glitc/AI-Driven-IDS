"""
Flow Data Model Module.

Defines the core structural entities representing network packets and bidirectional session
accumulators. Adheres to the Single Responsibility Principle by serving as pure data-holding
structures, leaving all statistical computations to downstream calculator engines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Final

from infrastructure.logging.logger_factory import get_logger

# Initialize Component-Specific Performance Logger Instance
logger = get_logger("capture.flow")


def flow_protocol_name(protocol: int) -> str:
    """
    Maps a standard IANA transport protocol number to a human-readable label.

    Used by both the live flows presentation layer and any downstream consumer so
    protocol labelling stays in a single, shared location.
    """
    if protocol == 6:  # TCP
        return "TCP"
    if protocol == 17:  # UDP
        return "UDP"
    return "Other"


@dataclass(frozen=True)
class PacketObservation:
    """
    Immutable value object capturing structural metadata properties from an individual 
    intercepted network packet frame.
    """
    timestamp: float
    size_bytes: int
    is_forward: bool  # Resolves True if packet follows the initial connection initiator's path
    syn: bool = False
    ack: bool = False
    rst: bool = False
    fin: bool = False
    psh: bool = False
    urg: bool = False
    ece: bool = False
    cwr: bool = False
    window_size: int = 0
    header_length: int = 0


@dataclass
class Flow:
    """
    Stateful entity class acting as a thread-safe telemetry accumulator bucket for a 
    bidirectional 5-tuple communication session context.
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # Standard IANA Transport Protocol Number Designation (6=TCP, 17=UDP)
    packets: List[PacketObservation] = field(default_factory=list)

    def add_packet(self, packet: PacketObservation) -> None:
        """
        Appends an immutable packet metadata block onto the internal session tracking array.
        """
        self.packets.append(packet)
        
        # Periodic high-throughput trace reporting to prevent console cluttering while maintaining observability
        packet_count: Final[int] = len(self.packets)
        if packet_count % 50 == 0:
            logger.debug(
                "Telemetry Ingestion Update: Session [%s:%d -> %s:%d] reached %d accumulated packets.",
                self.src_ip, self.src_port, self.dst_ip, self.dst_port, packet_count
            )

    @property
    def last_timestamp(self) -> float:
        """
        Extracts the unix timestamp associated with the most recently observed packet event.
        """
        return self.packets[-1].timestamp if self.packets else 0.0

    @property
    def is_empty(self) -> bool:
        """
        Evaluates the connection tracking array to verify structural readiness.
        """
        return not self.packets