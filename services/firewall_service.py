"""
Windows Firewall Management Service Module.

Orchestrates firewall rule lifecycle in concert with the IP whitelist/blacklist
repositories and the AlertEngine. Provides high-level operations for:
- Auto-blocking attacking IPs on threat detection
- Syncing firewall rules when lists change
- Manual override for admin operations
"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from functools import lru_cache
from typing import Final

from config.constants import LogLevel, LogSource
from config.settings import get_settings
from core.entities.log_entry import LogEntry
from core.exceptions import ValidationError
from infrastructure.firewall.windows_firewall import WindowsFirewallManager
from infrastructure.logging.logger_factory import get_logger
from repositories.blacklist_repository import BlacklistRepository
from repositories.log_repository import LogRepository
from repositories.whitelist_repository import WhitelistRepository
from utils.validators import validate_ip_address

logger = get_logger("services.firewall_service")


@lru_cache(maxsize=1)
def _discover_local_ipv4() -> frozenset[str]:
    """
    Enumerates every IPv4 literal bound to a local interface.

    Cached for the process lifetime because interface bindings are effectively
    static while the IDS runs. Used by :func:`is_protected_ip` so infrastructure
    addresses (the capture host itself, its gateway and subnets) are never
    auto-blocked.
    """
    discovered: set[str] = set()
    try:
        import psutil
        for _, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    discovered.add(addr.address)
    except Exception:  # noqa: BLE001 - best-effort discovery must never crash the pipeline
        logger.warning("Local IPv4 discovery failed; auto-block protection uses configured list only.")
    return frozenset(discovered)


def _is_ipv4(literal: str) -> bool:
    """Returns ``True`` when *literal* is a valid IPv4 address string."""
    try:
        return ipaddress.ip_address(literal).version == 4
    except ValueError:
        return False


@lru_cache(maxsize=1)
def _discover_default_gateways() -> frozenset[str]:
    """
    Resolves default gateway IP literals via platform route inspection.

    Best-effort: on failure an empty set is returned and protection falls back to
    the configured ``AI_IDS_PROTECTED_IPS`` plus local subnet/broadcast literals.
    """
    gateways: set[str] = set()
    try:
        if __import__("sys").platform.startswith("win"):
            out = subprocess.run(
                ["route", "print", "0.0.0.0", "mask", "0.0.0.0"],
                capture_output=True, text=True, timeout=5, check=False,
            ).stdout
            for line in out.splitlines():
                if "0.0.0.0" in line:
                    match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", line)
                    if match and line.strip().startswith("0.0.0.0"):
                        gateways.add(match.group(1))
        else:
            out = subprocess.run(
                ["ip", "route"], capture_output=True, text=True, timeout=5, check=False,
            ).stdout
            for line in out.splitlines():
                if line.startswith("default"):
                    match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", line)
                    if match:
                        gateways.add(match.group(1))
    except Exception:  # noqa: BLE001 - best-effort discovery must never crash the pipeline
        logger.debug("Default gateway discovery failed; using configured protected IPs only.")
    return frozenset(gateways)


@lru_cache(maxsize=1)
def _discover_subnet_boundaries() -> frozenset[str]:
    """
    Resolves the network + broadcast literal of every local IPv4 subnet.

    Cached like the other discovery helpers — subnet geometry is effectively
    static for the process lifetime.
    """
    boundaries: set[str] = set()
    try:
        import psutil
        for _, iface_addrs in psutil.net_if_addrs().items():
            for addr in iface_addrs:
                if addr.family == socket.AF_INET and addr.netmask:
                    try:
                        net = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                        boundaries.add(str(net.network_address))
                        boundaries.add(str(net.broadcast_address))
                    except ValueError:
                        continue
    except Exception:  # noqa: BLE001 - best-effort discovery must never crash the pipeline
        pass
    return frozenset(boundaries)


@lru_cache(maxsize=1)
def _protected_addresses() -> frozenset[ipaddress.IPv4Address]:
    """
    Merges every protected IPv4 literal (configured + discovered) into one
    cached set so per-flow protection checks are O(1) after first resolution.
    """
    protected: set[str] = set(get_settings().protected_ips)
    protected.update(_discover_local_ipv4())
    protected.update(_discover_default_gateways())
    protected.update(_discover_subnet_boundaries())
    return frozenset(ipaddress.ip_address(p) for p in protected if _is_ipv4(p))


class FirewallService:
    """
    Business-level firewall rule manager.

    Coordinates between:
    - WindowsFirewallManager (low-level netsh operations)
    - WhitelistRepository / BlacklistRepository (persistence)
    - LogRepository (audit trail)
    """

    def __init__(
        self,
        whitelist_repo: WhitelistRepository,
        blacklist_repo: BlacklistRepository,
        log_repository: LogRepository | None = None,
        firewall_manager: WindowsFirewallManager | None = None,
    ) -> None:
        self._whitelist: Final[WhitelistRepository] = whitelist_repo
        self._blacklist: Final[BlacklistRepository] = blacklist_repo
        self._logs: Final[LogRepository | None] = log_repository
        self._fw: Final[WindowsFirewallManager] = firewall_manager or WindowsFirewallManager()

    # ── Properties ──────────────────────────────────────────────────────

    @property
    def is_admin(self) -> bool:
        """Whether the current process has admin privileges (required for firewall changes)."""
        return self._fw.is_admin

    @property
    def platform(self) -> str:
        """Human-readable platform description."""
        if not self._fw._is_windows:
            return "Non-Windows (rules simulated)"
        if not self.is_admin:
            return "Windows (needs Admin for firewall changes)"
        return "Windows — Full Firewall Control"

    # ── Auto-Block on Detection ─────────────────────────────────────────

    def is_protected_ip(self, ip_address: str) -> bool:
        """
        Determines whether a target IP must never be auto-blocked.

        Protection covers, in priority order:
          1. IPs explicitly configured via ``AI_IDS_PROTECTED_IPS``.
          2. Local interface IPv4 literals (the capture host itself).
          3. Default gateways discovered from the OS routing table.
          4. The network and broadcast address of every local IPv4 subnet.

        A whitelisted IP is always returned as protected by the caller before
        this method is consulted; the two lists are intentionally disjoint.
        """
        if not ip_address:
            return False
        try:
            ip = ipaddress.ip_address(ip_address)
        except ValueError:
            return False
        return ip in _protected_addresses()

    def auto_block_on_threat(self, ip_address: str, reason: str = "") -> bool:
        """
        Called by AlertEngine when a threat is confirmed.

        - If auto-blocking is globally disabled → no-op.
        - If IP is whitelisted or a protected infrastructure address → skip.
        - If IP is already blacklisted → add firewall block rule
        - Otherwise → add to blacklist + firewall block rule

        Returns True only if firewall rule was actually created.
        """
        if not ip_address or ip_address == "unknown":
            return False

        if not get_settings().auto_block_enabled:
            logger.info("Auto-block DISABLED by configuration — skipping block for %s.", ip_address)
            return False

        # Only valid IP literals may reach the persistence layer or netsh.
        try:
            ip_address = validate_ip_address(ip_address)
        except ValidationError:
            logger.warning("Auto-block rejected malformed IP address: %r", ip_address)
            return False

        # Respect whitelist — admin trust overrides auto-block
        if self._whitelist.exists(ip_address):
            logger.info(
                "Auto-block SKIPPED for %s — IP is whitelisted (admin trust).", ip_address
            )
            return False

        # Respect protected infrastructure — never blacklist the gateway/host/subnets
        if self.is_protected_ip(ip_address):
            logger.info(
                "Auto-block SKIPPED for %s — protected infrastructure address.", ip_address
            )
            return False

        # Add to blacklist if not already there
        if not self._blacklist.exists(ip_address):
            from core.entities.ip_list_entry import BlacklistIP
            self._blacklist.add(BlacklistIP(
                ip_address=ip_address,
                reason=reason or "Auto-blocked by AI-IDS threat detection",
            ))
            self._audit(f"Auto-blacklisted IP {ip_address}: {reason or 'threat detected'}")

        # Create firewall block rule
        blocked = self._fw.block_ip(ip_address, reason or "AI-IDS auto-block")
        if blocked:
            self._audit(f"Firewall BLOCK rule created for {ip_address}")
            logger.warning("AUTO-BLOCK: IP %s blocked at firewall level.", ip_address)
        else:
            logger.error(
                "AUTO-BLOCK FAILED for %s — firewall rule could not be created. "
                "Check that the application is running as Administrator.", ip_address
            )

        return blocked

    # ── Manual Admin Operations ─────────────────────────────────────────

    def manual_block(self, ip_address: str, reason: str = "") -> dict[str, bool]:
        """
        Admin manually blocks an IP — adds firewall rule + blacklist.

        Returns dict with granular status:
        - blacklist_added: whether IP was added to blacklist DB
        - firewall_blocked: whether firewall rule was created
        """
        result = {"blacklist_added": False, "firewall_blocked": False}

        if not ip_address:
            return result

        ip_address = validate_ip_address(ip_address)

        # Remove any allow rule
        self._fw.remove_allow_rule(ip_address)

        # Add to blacklist
        if not self._blacklist.exists(ip_address):
            from core.entities.ip_list_entry import BlacklistIP
            self._blacklist.add(BlacklistIP(
                ip_address=ip_address,
                reason=reason or "Manual block by admin",
            ))
            result["blacklist_added"] = True
        else:
            result["blacklist_added"] = True  # already in blacklist

        # Create firewall block rule
        result["firewall_blocked"] = self._fw.block_ip(ip_address, reason or "Manual admin block")

        self._audit(
            f"Manual BLOCK: {ip_address} — "
            f"blacklist={'ok' if result['blacklist_added'] else 'exists'}, "
            f"firewall={'ok' if result['firewall_blocked'] else 'FAILED'}"
        )
        return result

    def manual_allow(self, ip_address: str, reason: str = "") -> dict[str, bool]:
        """
        Admin manually allows an IP — adds firewall allow rule + whitelist.

        Returns dict with granular status:
        - blacklist_removed: whether IP was removed from blacklist
        - whitelist_added: whether IP was added to whitelist
        - firewall_allowed: whether firewall rule was created
        """
        result = {"blacklist_removed": False, "whitelist_added": False, "firewall_allowed": False}

        if not ip_address:
            return result

        ip_address = validate_ip_address(ip_address)

        # Remove any block rule
        self._fw.remove_block_rule(ip_address)

        # Remove from blacklist if present
        entries = self._blacklist.get_all()
        for entry in entries:
            if entry.ip_address == ip_address:
                self._blacklist.delete(entry.id)
                result["blacklist_removed"] = True
                break

        # Add to whitelist
        if not self._whitelist.exists(ip_address):
            from core.entities.ip_list_entry import WhitelistIP
            self._whitelist.add(WhitelistIP(
                ip_address=ip_address,
                reason=reason or "Manual allow by admin",
            ))
            result["whitelist_added"] = True
        else:
            result["whitelist_added"] = True  # already in whitelist

        result["firewall_allowed"] = self._fw.allow_ip(ip_address, reason or "Manual admin allow")

        self._audit(
            f"Manual ALLOW: {ip_address} — "
            f"blacklist_rm={'ok' if result['blacklist_removed'] else 'none'}, "
            f"whitelist={'ok' if result['whitelist_added'] else 'exists'}, "
            f"firewall={'ok' if result['firewall_allowed'] else 'FAILED'}"
        )
        return result

    def remove_ip_rule(self, ip_address: str) -> bool:
        """Remove all AI-IDS firewall rules for an IP."""
        removed = self._fw.remove_rule(ip_address)
        if removed:
            self._audit(f"Removed firewall rule for {ip_address}")
        return removed

    # ── Bulk Sync ───────────────────────────────────────────────────────

    def sync_firewall_with_lists(self) -> dict[str, int]:
        """
        Full reconciliation: rebuild all firewall rules from current
        whitelist/blacklist database state.
        """
        whitelist_ips = [e.ip_address for e in self._whitelist.get_all()]
        blacklist_ips = [e.ip_address for e in self._blacklist.get_all()]

        stats = self._fw.sync_with_lists(whitelist_ips, blacklist_ips)
        self._audit(
            f"Firewall sync: {stats['allowed']} allow, "
            f"{stats['blocked']} block, {stats['removed']} removed"
        )
        return stats

    # ── Status & Queries ────────────────────────────────────────────────

    def get_all_rules(self) -> list:
        """Return all AI-IDS firewall rules."""
        return self._fw.list_rules()

    def get_blocked_ips(self) -> list[str]:
        """Return list of IPs blocked at firewall level."""
        return self._fw.list_blocked_ips()

    def get_allowed_ips(self) -> list[str]:
        """Return list of IPs allowed at firewall level."""
        return self._fw.list_allowed_ips()

    def is_blocked(self, ip_address: str) -> bool:
        """Check if an IP is blocked by firewall."""
        return self._fw.is_ip_blocked(ip_address)

    def is_allowed(self, ip_address: str) -> bool:
        """Check if an IP is allowed by firewall."""
        return self._fw.is_ip_allowed(ip_address)

    def remove_all_firewall_rules(self) -> int:
        """Nuclear option: remove ALL AI-IDS firewall rules."""
        count = self._fw.remove_all_rules()
        if count > 0:
            self._audit(f"Removed ALL {count} AI-IDS firewall rules")
        else:
            self._audit("Remove ALL requested — no rules removed (check admin privileges)")
        return count

    def get_firewall_status(self) -> dict:
        """Return a summary of the firewall state with admin and platform info."""
        rules = self._fw.list_rules()
        return {
            "total_rules": len(rules),
            "blocked_count": len([r for r in rules if "BLOCK" in r.rule_name.upper()]),
            "allowed_count": len([r for r in rules if "ALLOW" in r.rule_name.upper()]),
            "blocked_ips": self._fw.list_blocked_ips(),
            "allowed_ips": self._fw.list_allowed_ips(),
            "platform": self.platform,
            "is_windows": self._fw._is_windows,
            "is_admin": self.is_admin,
        }

    # ── Internal Audit ──────────────────────────────────────────────────

    def _audit(self, message: str) -> None:
        """Write an audit trail entry to the logs repository."""
        if self._logs is not None:
            try:
                self._logs.add(LogEntry(
                    source=LogSource.SYSTEM,
                    level=LogLevel.INFO,
                    message=f"[FIREWALL] {message}",
                ))
            except Exception:
                logger.debug("Failed to write firewall audit log: %s", message)
