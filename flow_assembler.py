"""
Flow Assembler Module.

Handles stateful, thread-safe aggregation of raw packet observations into bidirectional 
Flow data abstractions. Uses a canonical 5-tuple sorting mechanism to ensure packet sequences 
traveling in either direction (Forward/Backward) resolve into the same logical session flow.
"""

from __future__ import annotations

import threading
from typing import Dict, List, Tuple, Final

from capture.flow import Flow, PacketObservation
from infrastructure.logging.logger_factory import get_logger

# Initialize Component-Specific Logger Instance
logger = get_logger("capture.flow_assembler")

# Canonical Type Definition representing (Lower_IP, Higher_IP, Lower_Port, Higher_Port, Protocol)
FlowKey = Tuple[str, str, int, int, int]


class FlowAssembler:
    """
    Thread-safe network flow reassembly engine.
    
    Tracks active connections, identifies bidirectional traffic streams, and exposes
    eviction mechanisms for purging idle or completed flows from runtime memory structures.
    """
    
    def __init__(self, idle_timeout_seconds: float = 15.0) -> None:
        """
        Initializes the flow collection tracking map and corresponding thread lock primitives.
        """
        self._idle_timeout: Final[float] = idle_timeout_seconds
        self._flows: Final[Dict[FlowKey, Flow]] = {}
        self._lock: Final[threading.Lock] = threading.Lock()
        
        logger.info("FlowAssembler initialized with an idle timeout window of %.2f seconds.", idle_timeout_seconds)

    @staticmethod
    def _canonical_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int) -> FlowKey:
        """
        Deterministically orders endpoints to map traffic invariants down into a unique canonical key.
        """
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        return (dst_ip, src_ip, dst_port, src_port, protocol)

    def add_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        timestamp: float,
        size_bytes: int,
        syn: bool = False,
        ack: bool = False,
        rst: bool = False,
        fin: bool = False,
        psh: bool = False,
        urg: bool = False,
        ece: bool = False,
        cwr: bool = False,
        window_size: int = 0,
        header_length: int = 0,
    ) -> None:
        """
        Ingests a singular packet metadata observation and binds it to its canonical stateful flow.
        """
        key: Final[FlowKey] = self._canonical_key(src_ip, dst_ip, src_port, dst_port, protocol)

        with self._lock:
            flow = self._flows.get(key)
            if flow is None:
                flow = Flow(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, protocol=protocol)
                self._flows[key] = flow
                logger.debug("New stateful flow tracking context spawned for key: %s", str(key))

            # Establish packet direction based on original session initiator parameters
            is_forward: Final[bool] = (flow.src_ip, flow.src_port) == (src_ip, src_port)
            
            # Construct observation model and append it directly into target session context
            observation = PacketObservation(
                timestamp=timestamp,
                size_bytes=size_bytes,
                is_forward=is_forward,
                syn=syn, ack=ack, rst=rst, fin=fin, psh=psh, urg=urg,
                ece=ece, cwr=cwr,
                window_size=window_size,
                header_length=header_length,
            )
            flow.add_packet(observation)

    def pop_idle_flows(self, now: float) -> List[Flow]:
        """
        Scans, evicts, and returns all tracked flows that have exceeded the configured inactivity threshold.
        """
        completed: List[Flow] = []
        
        with self._lock:
            expired_keys: Final[List[FlowKey]] = [
                key for key, flow in self._flows.items()
                if (now - flow.last_timestamp) >= self._idle_timeout
            ]
            
            for key in expired_keys:
                completed.append(self._flows.pop(key))
                
        if completed:
            logger.info("Evicted %d stale/idle network sessions from internal flow tracking memory.", len(completed))
            
        return completed

    def flush_all(self) -> List[Flow]:
        """
        Forcibly purges and returns all tracked flow structures from memory regardless of time status.
        """
        logger.info("Forced flush signal received. Clearing out entire flow tracking database allocation structures.")
        with self._lock:
            flows: Final[List[Flow]] = list(self._flows.values())
            self._flows.clear()
        return flows

    @property
    def active_flow_count(self) -> int:
        """
        Returns the total count of distinct concurrent communication sessions currently being tracked.
        """
        with self._lock:
            return len(self._flows)