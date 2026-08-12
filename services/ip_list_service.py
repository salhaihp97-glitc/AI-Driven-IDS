"""
Network Access Control Policy and IP List Service Module.

Coordinates domain business rules managing system network address filters. Provides 
centralized verification routines to audit, search, insert, and update persistent whitelist 
and blacklist exceptions used during pipeline packet processing and dashboard operations.
"""
from __future__ import annotations

from typing import Final

from config.constants import LogLevel, LogSource
from core.entities.ip_list_entry import BlacklistIP, WhitelistIP
from core.entities.log_entry import LogEntry
from core.exceptions import RecordNotFoundError
from repositories.blacklist_repository import BlacklistRepository
from repositories.log_repository import LogRepository
from repositories.whitelist_repository import WhitelistRepository
from utils.validators import validate_ip_address

class IpListService:
    """
    Core application component managing firewall policy logic and access list mutations.
    """

    def __init__(
        self,
        whitelist_repo: WhitelistRepository,
        blacklist_repo: BlacklistRepository,
        log_repository: LogRepository | None = None,
    ) -> None:
        """
        Initializes the access control service with dedicated domain repositories.
        """
        self._whitelist: Final[WhitelistRepository] = whitelist_repo
        self._blacklist: Final[BlacklistRepository] = blacklist_repo
        self._logs: Final[LogRepository | None] = log_repository

    def _log(self, message: str) -> None:
        """
        Appends an informational tracking action event cleanly to the global system audit repository.
        """
        if self._logs is not None:
            self._logs.add(LogEntry(source=LogSource.USER, level=LogLevel.INFO, message=message))

    # =========================================================================
    # Whitelist Core Operations
    # =========================================================================

    def add_to_whitelist(self, ip_address: str, reason: str = "") -> WhitelistIP:
        """
        Registers a new network address exclusion rule within the system whitelist.
        """
        validated_ip: Final[str] = validate_ip_address(ip_address)
        entry = self._whitelist.add(WhitelistIP(ip_address=validated_ip, reason=reason or None))
        self._log(f"Access Policy Modification: Added {validated_ip} to whitelist (reason: {reason or 'none'}).")
        return entry

    def update_whitelist_entry(self, entry_id: int, ip_address: str, reason: str = "") -> WhitelistIP:
        """
        Modifies properties of an existing persistent system whitelist configuration.
        """
        validated_ip: Final[str] = validate_ip_address(ip_address)
        existing = self._whitelist.get_by_id(entry_id)
        if existing is None:
            raise RecordNotFoundError(f"Access Policy Fault: Whitelist entry index ID {entry_id} does not exist.")
            
        existing.ip_address = validated_ip
        existing.reason = reason or None
        updated = self._whitelist.update(existing)
        self._log(f"Access Policy Modification: Updated whitelist index {entry_id} -> {validated_ip} (reason: {reason or 'none'}).")
        return updated

    def remove_from_whitelist(self, entry_id: int) -> bool:
        """
        Removes a target network address exception from the active whitelist.
        """
        removed: Final[bool] = self._whitelist.delete(entry_id)
        if removed:
            self._log(f"Access Policy Modification: Removed whitelist index entry ID={entry_id}.")
        return removed

    def is_whitelisted(self, ip_address: str) -> bool:
        """
        Evaluates whether an individual network tracking identifier matches a whitelisted rule.
        """
        return self._whitelist.exists(ip_address)

    def list_whitelist(self) -> list[WhitelistIP]:
        """
        Retrieves the complete set of all registered whitelisted records.
        """
        return self._whitelist.get_all()

    def search_whitelist(self, text: str) -> list[WhitelistIP]:
        """Performs character pattern searches against active whitelisted records."""
        return self._whitelist.search(text)

    def count_whitelist(self) -> int:
        """Returns the total number of whitelisted IP entries."""
        return self._whitelist.count()

    # =========================================================================
    # Blacklist Core Operations
    # =========================================================================

    def add_to_blacklist(self, ip_address: str, reason: str = "") -> BlacklistIP:
        """
        Registers an explicit drop-action block rule targeting a malicious network address.
        """
        validated_ip: Final[str] = validate_ip_address(ip_address)
        entry = self._blacklist.add(BlacklistIP(ip_address=validated_ip, reason=reason or None))
        self._log(f"Access Policy Modification: Added {validated_ip} to blacklist (reason: {reason or 'none'}).")
        return entry

    def update_blacklist_entry(self, entry_id: int, ip_address: str, reason: str = "") -> BlacklistIP:
        """
        Modifies properties of an active network blocking descriptor rule.
        """
        validated_ip: Final[str] = validate_ip_address(ip_address)
        existing = self._blacklist.get_by_id(entry_id)
        if existing is None:
            raise RecordNotFoundError(f"Access Policy Fault: Blacklist entry index ID {entry_id} does not exist.")
            
        existing.ip_address = validated_ip
        existing.reason = reason or None
        updated = self._blacklist.update(existing)
        self._log(f"Access Policy Modification: Updated blacklist index {entry_id} -> {validated_ip} (reason: {reason or 'none'}).")
        return updated

    def remove_from_blacklist(self, entry_id: int) -> bool:
        """
        Removes an active block rule from the tracking engine blacklist repository.
        """
        removed: Final[bool] = self._blacklist.delete(entry_id)
        if removed:
            self._log(f"Access Policy Modification: Removed blacklist index entry ID={entry_id}.")
        return removed

    def is_blacklisted(self, ip_address: str) -> bool:
        """
        Evaluates whether an individual network host identifier matches a blacklisted drop rule.
        """
        return self._blacklist.exists(ip_address)

    def get_blacklist_entry(self, ip_address: str) -> BlacklistIP | None:
        """
        Returns the persistent blacklist record for *ip_address* — including the stored
        block reason — or ``None`` when the IP is not currently blocked.
        """
        return self._blacklist.get_by_ip(ip_address)

    def get_whitelist_entry(self, ip_address: str) -> WhitelistIP | None:
        """
        Returns the persistent whitelist record for *ip_address* — including the stored
        trust reason — or ``None`` when the IP is not currently whitelisted.
        """
        return self._whitelist.get_by_ip(ip_address)

    def list_blacklist(self) -> list[BlacklistIP]:
        """
        Retrieves the complete set of all active explicitly blocked network entities.
        """
        return self._blacklist.get_all()

    def search_blacklist(self, text: str) -> list[BlacklistIP]:
        """Performs character pattern searches against explicitly blocked network elements."""
        return self._blacklist.search(text)

    def count_blacklist(self) -> int:
        """Returns the total number of blacklisted IP entries."""
        return self._blacklist.count()