"""
Native Flow Extractor Module.

Implements the IFlowExtractor domain contract interface. Parses historical PCAP capture recordings 
using optimized Python network packet processing libraries, delegating session construction and 
feature mapping directly to core decoupled internal system components.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Final, List, Optional

from capture.flow_assembler import FlowAssembler
from capture.flow_feature_calculator import FlowFeatureCalculator, FlowFeatures
from config.settings import get_settings
from core.exceptions import ConfigurationError
from infrastructure.logging.logger_factory import get_logger
from ml.interfaces import IFlowExtractor

# Initialize Subsystem Performance Logger Interface
logger = get_logger("capture.native_flow_extractor")


class NativeFlowExtractor(IFlowExtractor):
    """
    Pure Python offline network telemetry extraction engine.
    
    Processes captured traffic trace dumps without requiring external cross-compiled system 
    binaries or distinct virtual runtime sandbox environments.
    """

    def __init__(self, idle_timeout_seconds: Optional[float] = None) -> None:
        """
        Initializes the feature computing layout and registers session state constraints.
        """
        self._idle_timeout: Final[float] = idle_timeout_seconds or get_settings().flow_idle_timeout_seconds
        self._calculator: Final[FlowFeatureCalculator] = FlowFeatureCalculator()
        logger.debug("NativeFlowExtractor context registered with idle validation window of %.2fs.", self._idle_timeout)

    def extract_from_pcap(self, pcap_path: str) -> List[FlowFeatures]:
        """
        Ingests a target PCAP recording file and maps extracted metrics into a sequence of flow features.
        """
        logger.info("Starting historical packet extraction matrix pipeline against target: '%s'", pcap_path)
        start_time: Final[float] = time.perf_counter()
        
        raw_packets = self._read_packets(pcap_path)
        assembler = FlowAssembler(idle_timeout_seconds=self._idle_timeout)

        # Reconstruct stateful bidirectional conversations
        for packet_metadata in raw_packets:
            assembler.add_packet(**packet_metadata)

        flows: Final[List[Any]] = assembler.flush_all()
        elapsed_time: Final[float] = time.perf_counter() - start_time
        
        logger.info(
            "Extraction Complete: Reassembled %d baseline flows from '%s' in %.3f seconds.", 
            len(flows), pcap_path, elapsed_time
        )
        return self._calculator.compute_many(flows)

    @staticmethod
    def _transport_payload_length(ip_total_len: int, ip_header_len: int, transport_header_len: int, layer_payload: Any) -> int:
        """
        Computes the transport-layer payload byte count for a captured frame.

        Mirrors the CICFlowMeter convention used by the CICIDS2017 feature corpus the
        deployed models were trained on: packet size features count the bytes carried
        by the transport layer (TCP/UDP data), not the full IP datagram. Falls back to
        the parsed layer payload length when the IP total-length field is unavailable.
        """
        if ip_total_len > 0:
            return max(0, ip_total_len - ip_header_len - transport_header_len)
        try:
            return int(len(layer_payload))
        except Exception:  # noqa: BLE001 - defensive fallback for malformed captures
            return 0

    @staticmethod
    def _read_packets(pcap_path: str) -> List[Dict[str, Any]]:
        """
        Low-level file ingest worker mapping unparsed binary packet blocks down to structural dictionary records.
        
        Raises:
            ConfigurationError: If requirements criteria fail or targeted file resources are corrupt.
        """
        try:
            from scapy.all import IP, TCP, UDP, rdpcap
        except ImportError as exc:
            logger.critical("Dependency check mismatch: 'scapy' core libraries are missing from active environment.")
            raise ConfigurationError(
                "The 'scapy' package dependency is required to parse PCAP targets natively. "
                "Verify requirement specifications or run 'pip install scapy'."
            ) from exc

        try:
            logger.debug("Loading binary packet payload records directly into host system memory.")
            packets = rdpcap(pcap_path)
        except Exception as exc:
            logger.error("OS I/O Error: Failed to safely parse input target storage path context: %s", exc)
            raise ConfigurationError(f"Target PCAP tracking source file could not be read ('{pcap_path}'): {exc}") from exc

        parsed_records: List[Dict[str, Any]] = []
        
        for pkt in packets:
            if IP not in pkt:
                continue
                
            ip_layer = pkt[IP]
            protocol: Final[int] = int(ip_layer.proto)
            ip_header_len: Final[int] = int(ip_layer.ihl) * 4
            ip_total_len: Final[int] = int(ip_layer.len)
            timestamp: Final[float] = float(pkt.time)

            src_port: int = 0
            dst_port: int = 0
            syn = ack = rst = fin = psh = urg = ece = cwr = False
            window_size: int = 0
            header_length: int = 0
            size_bytes: int = len(pkt)

            if TCP in pkt:
                tcp_layer = pkt[TCP]
                src_port, dst_port = int(tcp_layer.sport), int(tcp_layer.dport)
                flags = tcp_layer.flags
                syn = bool(flags & 0x02)
                ack = bool(flags & 0x10)
                rst = bool(flags & 0x04)
                fin = bool(flags & 0x01)
                psh = bool(flags & 0x08)
                urg = bool(flags & 0x20)
                ece = bool(flags & 0x40)
                cwr = bool(flags & 0x80)
                window_size = int(tcp_layer.window)
                # The CICIDS2017 feature corpus records transport-layer payload sizes
                # (TCP data bytes) and transport header lengths only, EXCLUDING the IP
                # header. Reproducing that convention keeps runtime features inside the
                # distribution the deployed models were trained on.
                tcp_header_len: Final[int] = int(tcp_layer.dataofs) * 4
                header_length = tcp_header_len
                size_bytes = NativeFlowExtractor._transport_payload_length(ip_total_len, ip_header_len, tcp_header_len, tcp_layer.payload)

            elif UDP in pkt:
                udp_layer = pkt[UDP]
                src_port, dst_port = int(udp_layer.sport), int(udp_layer.dport)
                header_length = 8  # UDP header is always 8 bytes (transport layer only)
                size_bytes = NativeFlowExtractor._transport_payload_length(ip_total_len, ip_header_len, 8, udp_layer.payload)

            else:
                header_length = ip_header_len

            parsed_records.append({
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "timestamp": timestamp,
                "size_bytes": size_bytes,
                "syn": syn,
                "ack": ack,
                "rst": rst,
                "fin": fin,
                "psh": psh,
                "urg": urg,
                "ece": ece,
                "cwr": cwr,
                "window_size": window_size,
                "header_length": header_length,
            })
            
        return parsed_records