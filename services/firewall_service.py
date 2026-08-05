"""
Windows Firewall Management Service Module.

Orchestrates firewall rule lifecycle in concert with the IP whitelist/blacklist
repositories and the AlertEngine. Provides high-level operations for:
- Auto-blocking attacking IPs on threat detection
- Syncing firewall rules when lists change
- Manual override for admin operations
"""

from __future__ import annotations

from typing import Final

from config.constants import LogLevel, LogSource
from core.entities.log_entry import LogEntry
from infrastructure.firewall.windows_firewall import WindowsFirewallManager
from infrastructure.logging.logger_factory import get_logger
from repositories.blacklist_repository import BlacklistRepository
from repositories.log_repository import LogRepository
from repositories.whitelist_repository import WhitelistRepository

logger = get_logger("services.firewall_service")


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

    def auto_block_on_threat(self, ip_address: str, reason: str = "") -> bool:
        """
        Called by AlertEngine when a threat is confirmed.

        - If IP is whitelisted → skip (admin trust override)
        - If IP is already blacklisted → add firewall block rule
        - Otherwise → add to blacklist + firewall block rule

        Returns True only if firewall rule was actually created.
        """
        if not ip_address or ip_address == "unknown":
            return False

        # Respect whitelist — admin trust overrides auto-block
        if self._whitelist.exists(ip_address):
            logger.info(
                "Auto-block SKIPPED for %s — IP is whitelisted (admin trust).", ip_address
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
