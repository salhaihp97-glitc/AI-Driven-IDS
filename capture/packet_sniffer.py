"""
Packet Sniffer Module.

Provides explicit execution thread encapsulation over the Scapy packet capture engine.
Ensures persistent packet capture contexts survive high-frequency volatile user interface 
lifecycle mutations (e.g., Streamlit runtime state purges) while maintaining predictable
synchronous start and stop controls.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Optional, Final

from core.exceptions import ConfigurationError
from infrastructure.logging.logger_factory import get_logger

# Initialize Component-Specific Performance Logger Instance
logger = get_logger("capture.packet_sniffer")


class PacketSniffer:
    """
    Explicitly managed background network thread sniffer wrapper.
    
    Enforces atomic lifecycle states over low-level raw socket sniffing tasks,
    surfacing detailed hardware exception states back up to orchestrator instances.
    """

    def __init__(self, on_packet: Callable[[Any], None], shutdown_timeout_seconds: float = 5.0) -> None:
        """
        Initializes the sniffing context event primitives and target ingestion hooks.

        Args:
            on_packet: Callback invoked synchronously for every captured frame.
            shutdown_timeout_seconds: Maximum wait budget (seconds) for the worker
                thread to unwind after a stop signal before handles are released.
        """
        self._on_packet: Final[Callable[[Any], None]] = on_packet
        self._shutdown_timeout: Final[float] = shutdown_timeout_seconds
        self._thread: Optional[threading.Thread] = None
        self._stop_event: Final[threading.Event] = threading.Event()
        self._interface: Optional[str] = None
        self._error: Optional[str] = None

    @property
    def is_running(self) -> bool:
        """
        Evaluates whether the dedicated worker capture thread is alive and processing.
        """
        return self._thread is not None and self._thread.is_alive()

    @property
    def last_error(self) -> Optional[str]:
        """
        Exposes the historical operational thread exception traceback message if one exists.
        """
        return self._error

    def start(self, interface: str) -> None:
        """
        Spawns the background capture worker tracking thread on the target network interface card.
        
        Raises:
            ConfigurationError: If the sniffer engine is already executing or if 
                                required dependencies are missing.
        """
        if self.is_running:
            logger.warning("Sniffer execution rejected: Worker thread is already active.")
            raise ConfigurationError("Capture is already running. Stop it before starting a new one.")

        try:
            # Execute early fail-fast package evaluation before spawning OS threads
            import scapy.all  # noqa: F401
        except ImportError as exc:
            logger.critical("Dependency resolution failed: 'scapy' package missing from target environment.")
            raise ConfigurationError(
                "The 'scapy' package is required for live capture but is not installed. "
                "Install it with `pip install scapy` (and run with sufficient privileges "
                "to open raw sockets: root on Linux, Administrator/Npcap on Windows)."
            ) from exc

        self._interface = interface
        self._error = None
        self._stop_event.clear()
        
        self._thread = threading.Thread(
            target=self._run, 
            name="AI-IDS-PacketSniffer", 
            daemon=True
        )
        self._thread.start()
        logger.info("Started background packet capture context on interface: '%s'.", interface)

    def stop(self) -> None:
        """
        Signals the stop filter trigger and blocks execution until the worker thread exits cleanly.
        """
        if not self.is_running:
            return
            
        logger.info("Signaling stop sequence down to interface listener thread: '%s'.", self._interface)
        self._stop_event.set()
        
        if self._thread:
            self._thread.join(timeout=self._shutdown_timeout)
            
        # Clear out state handles to support fresh subsequent capture actions
        self._thread = None
        logger.info("Packet capture thread safely decommissioned on interface: '%s'.", self._interface)

    def _run(self) -> None:
        """
        Internal target loop executing high-frequency raw socket evaluations.
        """
        from scapy.all import sniff

        try:
            sniff(
                iface=self._interface,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _pkt: self._stop_event.is_set(),
            )
        except Exception as exc:
            # Safeguard background process: Capture thread exceptions must never silently crash the master process
            self._error = str(exc)
            logger.exception(
                "Core packet sniffer thread crashed. Verify OS network layer execution privileges. Exception: %s", 
                exc
            )