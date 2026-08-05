"""
Network Interface Lister Module.

Provides platform-agnostic hardware discovery routines utilizing standard psutil backends.
Abstracts differences between Windows NPF/Pcap device bindings and Linux standard eth/wlan 
naming conventions, generating clean unified metadata representations for user interface components.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Final

import psutil

from infrastructure.logging.logger_factory import get_logger

# Initialize Component-Specific Performance Logger Instance
logger = get_logger("capture.interface_lister")


@dataclass(frozen=True)
class NetworkInterfaceInfo:
    """
    Immutable data representation encapsulating low-level system properties 
    and human-readable identifiers for a physical or virtual network interface card.
    """
    system_name: str  # Structural hardware interface key (e.g., "eth0", "\\Device\\NPF_{...}")
    display_name: str  # User-friendly descriptive label generated for UI components
    is_up: bool
    addresses: List[str]


class NetworkInterfaceLister:
    """
    Platform-independent hardware enumeration utility service.
    
    Queries operating system network stack layers directly to fetch current operational metrics 
    without relying on unstable platform-specific shell subprocess executions.
    """

    def list_interfaces(self) -> List[NetworkInterfaceInfo]:
        """
        Queries and returns a structured array of all detected operating system network interfaces.
        """
        logger.debug("Querying host operating system network stack for active interface attachments.")
        
        try:
            stats: Final = psutil.net_if_stats()
            addrs: Final = psutil.net_if_addrs()
        except Exception as exc:
            logger.error("OS API failure: Internal error encountered while requesting interface statistics: %s", exc)
            return []

        interfaces: List[NetworkInterfaceInfo] = []
        
        for name, addr_list in addrs.items():
            # Gracefully fallback to False if statistics are unavailable for a specific interface key
            is_up: Final[bool] = stats[name].isup if name in stats else False
            
            # Isolate IP network structures using safe family name evaluations
            ip_addresses: Final[List[str]] = [
                addr.address for addr in addr_list 
                if addr.family and getattr(addr.family, "name", "") in ("AF_INET", "AF_INET6")
            ]
            
            interface_info = NetworkInterfaceInfo(
                system_name=name,
                display_name=self._friendly_name(name, ip_addresses),
                is_up=is_up,
                addresses=ip_addresses,
            )
            interfaces.append(interface_info)

        logger.info(
            "Hardware Inventory Scan Complete: Discovered %d distinct network interface descriptors.", 
            len(interfaces)
        )
        return interfaces

    @staticmethod
    def _friendly_name(system_name: str, addresses: List[str]) -> str:
        """
        Constructs an explicit, human-readable display descriptor for UI formatting.
        """
        primary_ip: Final[str] = addresses[0] if addresses else "No Assigned Address"
        return f"{system_name} ({primary_ip})"