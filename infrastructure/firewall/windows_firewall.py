"""
Windows Firewall Dynamic Rule Management Module.

Provides a high-level abstraction over the Windows Advanced Firewall (netsh advfirewall)
for programmatic inbound IP blocking and allowlisting. Every rule is tagged with a
configurable prefix so that AI-IDS rules can be enumerated, audited, and bulk-removed
without disturbing manually created firewall policies.

Requires administrative privileges for mutating operations (add/delete rules).
Read-only operations (show rule, list) work without elevation.

Design Principles:
- Idempotent operations (adding an existing rule is a no-op)
- Thread-safe subprocess execution
- All rules are INBOUND + BLOCK/ALLOW as requested
- Every rule carries a description for audit trails
- Bulk sync support for whitelist/blacklist reconciliation
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from typing import Final, List, Optional

from infrastructure.logging.logger_factory import get_logger

logger = get_logger("infrastructure.firewall.windows_firewall")

# ── Rule Naming Convention ──────────────────────────────────────────────
RULE_PREFIX: Final[str] = "AI-IDS"
BLOCK_RULE_PREFIX: Final[str] = f"{RULE_PREFIX}-BLOCK"
ALLOW_RULE_PREFIX: Final[str] = f"{RULE_PREFIX}-ALLOW"


@dataclass(frozen=True)
class FirewallRule:
    """Immutable value object representing a single Windows Firewall rule."""
    rule_name: str
    action: str          # "Block" or "Allow"
    direction: str       # "Inbound"
    remote_ip: str
    enabled: bool
    description: str
    profile: str


class WindowsFirewallManager:
    """
    Manages Windows Defender Firewall inbound rules for IP-based threat mitigation.

    Requires administrative privileges for mutating operations.
    On non-Windows platforms all mutating methods are graceful no-ops.
    """

    def __init__(self, rule_prefix: str = RULE_PREFIX) -> None:
        self._prefix = rule_prefix
        self._is_windows = sys.platform == "win32"
        self._is_admin: bool | None = None  # lazy cached

    # ── Admin Check ─────────────────────────────────────────────────────

    @property
    def is_admin(self) -> bool:
        """Detect whether the current process has administrator privileges."""
        if self._is_admin is not None:
            return self._is_admin
        if not self._is_windows:
            self._is_admin = False
            return self._is_admin
        try:
            import ctypes
            self._is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            self._is_admin = False
        return self._is_admin

    # ── Core Operations ─────────────────────────────────────────────────

    def block_ip(self, ip_address: str, reason: str = "") -> bool:
        """
        Create an inbound BLOCK rule for the given IP address.

        Returns True if the rule was created or already existed.
        Returns False if not admin, not Windows, or netsh failed.
        """
        if not self._is_windows:
            logger.warning("Firewall block_ip skipped — not running on Windows.")
            return False
        if not self.is_admin:
            logger.error("Firewall block_ip requires administrator privileges.")
            return False

        rule_name = self._make_rule_name("BLOCK", ip_address)
        description = reason or f"AI-IDS auto-block for {ip_address}"

        if self._rule_exists(rule_name, direction="in"):
            logger.info("Firewall BLOCK rule already exists for %s.", ip_address)
            return True

        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}",
            "enable=yes",
            f"description={description}",
        ]
        return self._run(cmd, f"block IP {ip_address}")

    def allow_ip(self, ip_address: str, reason: str = "") -> bool:
        """
        Create an inbound ALLOW rule for the given IP address.

        Removes any existing block rule for this IP first, then creates allow.
        Returns True if the rule was created or already existed.
        """
        if not self._is_windows:
            logger.warning("Firewall allow_ip skipped — not running on Windows.")
            return False
        if not self.is_admin:
            logger.error("Firewall allow_ip requires administrator privileges.")
            return False

        rule_name = self._make_rule_name("ALLOW", ip_address)
        description = reason or f"AI-IDS whitelist for {ip_address}"

        # Remove any existing block rule for this IP first
        self.remove_block_rule(ip_address)

        if self._rule_exists(rule_name, direction="in"):
            logger.info("Firewall ALLOW rule already exists for %s.", ip_address)
            return True

        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=allow",
            f"remoteip={ip_address}",
            "enable=yes",
            f"description={description}",
        ]
        return self._run(cmd, f"allow IP {ip_address}")

    def remove_block_rule(self, ip_address: str) -> bool:
        """Remove the AI-IDS BLOCK rule for a specific IP."""
        rule_name = self._make_rule_name("BLOCK", ip_address)
        return self._remove_rule_by_name(rule_name)

    def remove_allow_rule(self, ip_address: str) -> bool:
        """Remove the AI-IDS ALLOW rule for a specific IP."""
        rule_name = self._make_rule_name("ALLOW", ip_address)
        return self._remove_rule_by_name(rule_name)

    def remove_rule(self, ip_address: str) -> bool:
        """Remove any AI-IDS rule (BLOCK or ALLOW) for a specific IP."""
        removed_block = self.remove_block_rule(ip_address)
        removed_allow = self.remove_allow_rule(ip_address)
        return removed_block or removed_allow

    def list_rules(self) -> List[FirewallRule]:
        """List all AI-IDS managed firewall rules by querying the Windows Firewall."""
        if not self._is_windows:
            return []

        rules: List[FirewallRule] = []

        for action in ["Block", "Allow"]:
            search_name = f"{self._prefix}-{action.upper()}"
            try:
                result = subprocess.run(
                    [
                        "netsh", "advfirewall", "firewall", "show", "rule",
                        f"name={search_name}",
                        "dir=in",
                    ],
                    capture_output=True, text=True, timeout=15,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if result.returncode != 0:
                    continue

                parsed = self._parse_show_output(result.stdout, action)
                rules.extend(parsed)

            except (subprocess.TimeoutExpired, OSError) as exc:
                logger.error("Failed to enumerate firewall rules: %s", exc)

        return rules

    def list_blocked_ips(self) -> List[str]:
        """Return a list of all IPs currently blocked by AI-IDS rules."""
        return [r.remote_ip for r in self.list_rules() if "BLOCK" in r.rule_name.upper()]

    def list_allowed_ips(self) -> List[str]:
        """Return a list of all IPs currently allowed by AI-IDS rules."""
        return [r.remote_ip for r in self.list_rules() if "ALLOW" in r.rule_name.upper()]

    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if an IP has an active AI-IDS BLOCK rule."""
        return ip_address in self.list_blocked_ips()

    def is_ip_allowed(self, ip_address: str) -> bool:
        """Check if an IP has an active AI-IDS ALLOW rule."""
        return ip_address in self.list_allowed_ips()

    def remove_all_rules(self) -> int:
        """Remove ALL AI-IDS managed firewall rules. Returns count removed."""
        if not self._is_windows:
            return 0
        if not self.is_admin:
            logger.error("remove_all_rules requires administrator privileges.")
            return 0

        count = 0
        for rule in self.list_rules():
            if self._remove_rule_by_name(rule.rule_name):
                count += 1
        return count

    def sync_with_lists(
        self,
        whitelist_ips: List[str],
        blacklist_ips: List[str],
    ) -> dict[str, int]:
        """
        Reconcile firewall rules with the current whitelist/blacklist state.
        - Whitelisted IPs → ALLOW rules (removes any BLOCK)
        - Blacklisted IPs → BLOCK rules (removes any ALLOW)
        - IPs not in either list → remove AI-IDS rules

        Returns a summary dict with counts.
        """
        stats = {"allowed": 0, "blocked": 0, "removed": 0}

        current_rules = self.list_rules()
        current_ips = {r.remote_ip for r in current_rules}
        desired_ips = set(whitelist_ips) | set(blacklist_ips)

        # Remove rules for IPs no longer in any list
        for ip in current_ips - desired_ips:
            if self.remove_rule(ip):
                stats["removed"] += 1

        # Create/update ALLOW rules for whitelisted IPs
        for ip in whitelist_ips:
            self.remove_block_rule(ip)
            if self.allow_ip(ip, "Whitelist sync"):
                stats["allowed"] += 1

        # Create/update BLOCK rules for blacklisted IPs
        for ip in blacklist_ips:
            self.remove_allow_rule(ip)
            if self.block_ip(ip, "Blacklist sync"):
                stats["blocked"] += 1

        logger.info(
            "Firewall sync complete: %d allowed, %d blocked, %d removed.",
            stats["allowed"], stats["blocked"], stats["removed"],
        )
        return stats

    # ── Internal Helpers ────────────────────────────────────────────────

    def _make_rule_name(self, action: str, ip_address: str) -> str:
        """Generate a deterministic, unique rule name."""
        safe_ip = ip_address.replace(".", "_").replace(":", "_")
        return f"{self._prefix}-{action}-{safe_ip}"

    def _rule_exists(self, rule_name: str, direction: str = "in") -> bool:
        """
        Check if a named rule already exists.

        Uses 'show rule name=<exact_name> dir=in' for precise matching.
        netsh show rule name= does substring matching by default,
        so we check the parsed output to ensure exact match.
        """
        if not self._is_windows:
            return False
        try:
            result = subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "show", "rule",
                    f"name={rule_name}",
                    f"dir={direction}",
                ],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode != 0:
                return False
            # netsh does substring matching on name=, so verify exact match
            for line in result.stdout.splitlines():
                if line.strip().startswith("Rule Name:"):
                    found_name = line.split(":", 1)[1].strip()
                    if found_name == rule_name:
                        return True
            return False
        except (subprocess.TimeoutExpired, OSError):
            return False

    def _remove_rule_by_name(self, rule_name: str) -> bool:
        """Delete a firewall rule by exact name."""
        if not self._is_windows:
            return False
        if not self.is_admin:
            return False
        if not self._rule_exists(rule_name):
            return False
        return self._run(
            [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}", "dir=in",
            ],
            f"remove rule '{rule_name}'",
        )

    def _parse_show_output(self, stdout: str, default_action: str) -> List[FirewallRule]:
        """
        Parse netsh advfirewall firewall show rule output into FirewallRule objects.

        The output format is blocks of key-value pairs separated by blank lines:
            Rule Name:                            AI-IDS-BLOCK-192_168_1_100
            ----------------------------------------------------------------------
            Enabled:                              Yes
            Direction:                            Inbound
            Profiles:                             Domain,Private,Public
            Grouping:                             ...
            LocalIP:                              Any
            RemoteIP:                             192.168.1.100
            ...
            Action:                               Block

        We split on blank lines to get rule blocks, then parse each block.
        """
        rules: List[FirewallRule] = []
        if not stdout or not stdout.strip():
            return rules

        # Split output into rule blocks (separated by blank lines only)
        # netsh uses "------" as a visual separator within a rule block,
        # but blank lines separate different rules.
        blocks = []
        current_block: list[str] = []

        for line in stdout.splitlines():
            stripped = line.strip()
            if stripped == "":
                if current_block:
                    blocks.append(current_block)
                    current_block = []
            elif stripped.startswith("---"):
                continue  # Skip separator lines, they don't end a block
            else:
                current_block.append(stripped)

        if current_block:
            blocks.append(current_block)

        for block in blocks:
            key_values: dict[str, str] = {}
            for line in block:
                if ":" in line:
                    key, _, value = line.partition(":")
                    key = key.strip()
                    value = value.strip()
                    if key and key not in ("Rule Name",):  # we handle Rule Name specially
                        key_values[key] = value

            # Extract rule name — first line of block should start with "Rule Name:"
            rule_name = ""
            first_line = block[0] if block else ""
            if first_line.startswith("Rule Name:"):
                rule_name = first_line.split(":", 1)[1].strip()

            if not rule_name:
                continue

            # Only include rules managed by AI-IDS
            if not rule_name.startswith(self._prefix):
                continue

            remote_ip = key_values.get("RemoteIP", "")
            if not remote_ip or remote_ip == "Any":
                continue

            rules.append(FirewallRule(
                rule_name=rule_name,
                action=key_values.get("Action", default_action),
                direction="Inbound",
                remote_ip=remote_ip,
                enabled=key_values.get("Enabled", "Yes") == "Yes",
                description=key_values.get("Description", ""),
                profile=key_values.get("Profiles", ""),
            ))

        return rules

    def _run(self, cmd: List[str], description: str) -> bool:
        """Execute a netsh command and return success status."""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode == 0:
                logger.info("Firewall %s succeeded.", description)
                return True
            stderr = result.stderr.strip()
            if "elevation" in stderr.lower() or "administrator" in stderr.lower():
                logger.error(
                    "Firewall %s failed — requires administrator privileges. "
                    "Run the application as Administrator.",
                    description,
                )
            else:
                logger.error("Firewall %s failed (rc=%d): %s", description, result.returncode, stderr)
            return False
        except subprocess.TimeoutExpired:
            logger.error("Firewall %s timed out (15s).", description)
            return False
        except OSError as exc:
            logger.error("Firewall %s OS error: %s", description, exc)
            return False
