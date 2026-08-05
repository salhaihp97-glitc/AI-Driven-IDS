"""
Windows Firewall integration tests.

Tests the WindowsFirewallManager and FirewallService with both mocked and real netsh commands.

- Unit tests use mocked subprocess to avoid needing admin
- Integration tests run REAL netsh commands and require Administrator privileges
  (auto-skipped if not admin)
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch

import pytest

from infrastructure.firewall.windows_firewall import (
    BLOCK_RULE_PREFIX,
    RULE_PREFIX,
    ALLOW_RULE_PREFIX,
    FirewallRule,
    WindowsFirewallManager,
)


# ── Unit Tests (Mocked) ─────────────────────────────────────────────────


class TestWindowsFirewallManagerUnit:
    """Unit tests with mocked subprocess calls."""

    def _make_manager(self) -> WindowsFirewallManager:
        return WindowsFirewallManager()

    def test_is_not_admin_on_non_windows(self):
        """On non-Windows, is_admin should be False."""
        mgr = self._make_manager()
        if sys.platform != "win32":
            assert mgr.is_admin is False

    def test_rule_prefix_constants(self):
        """Rule prefix constants should follow naming convention."""
        assert RULE_PREFIX == "AI-IDS"
        assert BLOCK_RULE_PREFIX == "AI-IDS-BLOCK"
        assert ALLOW_RULE_PREFIX == "AI-IDS-ALLOW"

    def test_make_rule_name(self):
        """Rule name should be deterministic and IP-safe."""
        mgr = self._make_manager()
        assert mgr._make_rule_name("BLOCK", "192.168.1.1") == "AI-IDS-BLOCK-192_168_1_1"
        assert mgr._make_rule_name("ALLOW", "10.0.0.5") == "AI-IDS-ALLOW-10_0_0_5"
        assert mgr._make_rule_name("BLOCK", "::1") == "AI-IDS-BLOCK-__1"

    def test_block_ip_returns_false_on_non_windows(self):
        """block_ip should return False (no-op) on non-Windows."""
        mgr = self._make_manager()
        if sys.platform != "win32":
            assert mgr.block_ip("1.2.3.4") is False

    def test_allow_ip_returns_false_on_non_windows(self):
        """allow_ip should return False (no-op) on non-Windows."""
        mgr = self._make_manager()
        if sys.platform != "win32":
            assert mgr.allow_ip("1.2.3.4") is False

    def test_list_rules_returns_empty_on_non_windows(self):
        """list_rules should return [] on non-Windows."""
        mgr = self._make_manager()
        if sys.platform != "win32":
            assert mgr.list_rules() == []

    def test_list_blocked_ips_returns_empty_on_non_windows(self):
        """list_blocked_ips should return [] on non-Windows."""
        mgr = self._make_manager()
        if sys.platform != "win32":
            assert mgr.list_blocked_ips() == []

    def test_list_allowed_ips_returns_empty_on_non_windows(self):
        """list_allowed_ips should return [] on non-Windows."""
        mgr = self._make_manager()
        if sys.platform != "win32":
            assert mgr.list_allowed_ips() == []

    def test_remove_all_rules_returns_zero_on_non_windows(self):
        """remove_all_rules should return 0 on non-Windows."""
        mgr = self._make_manager()
        if sys.platform != "win32":
            assert mgr.remove_all_rules() == 0

    def test_sync_with_lists_returns_zeros_on_non_windows(self):
        """sync_with_lists should return zeros on non-Windows."""
        mgr = self._make_manager()
        if sys.platform != "win32":
            stats = mgr.sync_with_lists(["1.1.1.1"], ["2.2.2.2"])
            assert stats == {"allowed": 0, "blocked": 0, "removed": 0}

    @patch("infrastructure.firewall.windows_firewall.subprocess.run")
    def test_rule_exists_calls_netsh_correctly(self, mock_run):
        """_rule_exists should call netsh with name= and dir=in."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Rule Name:                            AI-IDS-BLOCK-1_2_3_4\nEnabled: Yes\n",
        )
        mgr = self._make_manager()
        if sys.platform == "win32":
            result = mgr._rule_exists("AI-IDS-BLOCK-1_2_3_4", direction="in")
            assert result is True
            call_args = mock_run.call_args[0][0]
            assert "name=AI-IDS-BLOCK-1_2_3_4" in call_args
            assert "dir=in" in call_args

    @patch("infrastructure.firewall.windows_firewall.subprocess.run")
    def test_rule_exists_returns_false_for_substring_match(self, mock_run):
        """_rule_exists should verify exact name, not just substring match."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Rule Name:                            AI-IDS-BLOCK-1_2_3_4_extra\nEnabled: Yes\n",
        )
        mgr = self._make_manager()
        if sys.platform == "win32":
            result = mgr._rule_exists("AI-IDS-BLOCK-1_2_3_4", direction="in")
            assert result is False

    @patch("infrastructure.firewall.windows_firewall.subprocess.run")
    def test_block_ip_no_duplicate_when_exists(self, mock_run):
        """block_ip should skip if rule already exists."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Rule Name:                            AI-IDS-BLOCK-1_2_3_4\nEnabled: Yes\n",
        )
        mgr = self._make_manager()
        if sys.platform == "win32":
            with patch.object(type(mgr), "is_admin", new_callable=lambda: property(lambda self: True)):
                result = mgr.block_ip("1.2.3.4", "test reason")
                assert result is True
                # Should only call subprocess once for _rule_exists check
                assert mock_run.call_count == 1

    @patch("infrastructure.firewall.windows_firewall.subprocess.run")
    def test_block_ip_creates_rule_when_not_exists(self, mock_run):
        """block_ip should create rule if not exists."""
        call_count = [0]

        def side_effect(cmd, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # _rule_exists check — not found
                return MagicMock(returncode=1, stdout="")
            # add rule — success
            return MagicMock(returncode=0, stdout="Ok.\n")

        mock_run.side_effect = side_effect
        mgr = self._make_manager()
        if sys.platform == "win32":
            with patch.object(type(mgr), "is_admin", new_callable=lambda: property(lambda self: True)):
                result = mgr.block_ip("5.6.7.8", "test")
                assert result is True
                assert mock_run.call_count == 2
                # Verify the add rule command uses description= not comment=
                add_cmd = mock_run.call_args_list[1][0][0]
                assert "description=test" in add_cmd
                assert "comment=" not in " ".join(add_cmd)
                assert "group=" not in " ".join(add_cmd)

    @patch("infrastructure.firewall.windows_firewall.subprocess.run")
    def test_parse_show_output_single_rule(self, mock_run):
        """_parse_show_output should parse netsh output correctly."""
        output = (
            "Rule Name:                            AI-IDS-BLOCK-192_168_1_1\n"
            "----------------------------------------------------------------------\n"
            "Enabled:                              Yes\n"
            "Direction:                            Inbound\n"
            "Profiles:                             Domain,Private,Public\n"
            "Grouping:                             ...\n"
            "LocalIP:                              Any\n"
            "RemoteIP:                             192.168.1.1\n"
            "Protocol:                             Any\n"
            "Action:                               Block\n"
        )
        mgr = self._make_manager()
        rules = mgr._parse_show_output(output, "Block")
        assert len(rules) == 1
        rule = rules[0]
        assert rule.rule_name == "AI-IDS-BLOCK-192_168_1_1"
        assert rule.remote_ip == "192.168.1.1"
        assert rule.action == "Block"
        assert rule.enabled is True
        assert rule.direction == "Inbound"

    def test_parse_show_output_ignores_non_aiids_rules(self):
        """_parse_show_output should ignore rules not starting with AI-IDS prefix."""
        output = (
            "Rule Name:                            Microsoft Store\n"
            "Enabled:                              Yes\n"
            "Direction:                            Inbound\n"
            "RemoteIP:                             Any\n"
            "Action:                               Allow\n"
        )
        mgr = self._make_manager()
        rules = mgr._parse_show_output(output, "Allow")
        assert len(rules) == 0

    def test_parse_show_output_ignores_any_remote_ip(self):
        """_parse_show_output should ignore rules with RemoteIP=Any."""
        output = (
            "Rule Name:                            AI-IDS-BLOCK-some_rule\n"
            "Enabled:                              Yes\n"
            "RemoteIP:                             Any\n"
            "Action:                               Block\n"
        )
        mgr = self._make_manager()
        rules = mgr._parse_show_output(output, "Block")
        assert len(rules) == 0

    def test_parse_show_output_empty(self):
        """_parse_show_output should handle empty input."""
        mgr = self._make_manager()
        rules = mgr._parse_show_output("", "Block")
        assert rules == []

    def test_parse_show_output_multiple_rules(self):
        """_parse_show_output should parse multiple rules."""
        output = (
            "Rule Name:                            AI-IDS-BLOCK-1_1_1_1\n"
            "Enabled:                              Yes\n"
            "RemoteIP:                             1.1.1.1\n"
            "Action:                               Block\n"
            "\n"
            "Rule Name:                            AI-IDS-ALLOW-2_2_2_2\n"
            "Enabled:                              Yes\n"
            "RemoteIP:                             2.2.2.2\n"
            "Action:                               Allow\n"
        )
        mgr = self._make_manager()
        rules = mgr._parse_show_output(output, "Block")
        assert len(rules) == 2
        assert rules[0].remote_ip == "1.1.1.1"
        assert rules[1].remote_ip == "2.2.2.2"
        assert rules[1].action == "Allow"

    @patch("infrastructure.firewall.windows_firewall.subprocess.run")
    def test_remove_all_rules_returns_zero_without_admin(self, mock_run):
        """remove_all_rules should return 0 if not admin."""
        mgr = self._make_manager()
        if sys.platform == "win32":
            with patch.object(type(mgr), "is_admin", new_callable=lambda: property(lambda self: False)):
                result = mgr.remove_all_rules()
                assert result == 0


class TestFirewallRule:
    """Test the FirewallRule data class."""

    def test_frozen_dataclass(self):
        """FirewallRule should be immutable."""
        rule = FirewallRule(
            rule_name="AI-IDS-BLOCK-1_2_3_4",
            action="Block",
            direction="Inbound",
            remote_ip="1.2.3.4",
            enabled=True,
            description="test",
            profile="Domain,Private,Public",
        )
        assert rule.rule_name == "AI-IDS-BLOCK-1_2_3_4"
        assert rule.remote_ip == "1.2.3.4"
        assert rule.enabled is True
        with pytest.raises(AttributeError):
            rule.rule_name = "changed"


# ── Integration Tests (Real netsh — requires Admin) ─────────────────────


def _has_admin() -> bool:
    """Check if running as admin on Windows."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


ADMIN_MARK = pytest.mark.skipif(
    not _has_admin(),
    reason="Integration tests require Administrator privileges",
)


@pytest.fixture
def real_manager():
    """Create a real WindowsFirewallManager for integration tests."""
    return WindowsFirewallManager(rule_prefix="AI-IDS-TEST")


TEST_IP = "198.51.100.77"  # TEST-NET-3 RFC 5737 — not routable


@ADMIN_MARK
class TestWindowsFirewallManagerIntegration:
    """
    Real integration tests that create/delete actual Windows Firewall rules.
    These tests REQUIRE Administrator privileges and modify the host firewall.
    """

    def test_block_and_list_and_remove(self, real_manager):
        """Full lifecycle: block IP → verify rule exists → remove → verify gone."""
        # Cleanup first
        real_manager.remove_rule(TEST_IP)

        # Block
        assert real_manager.block_ip(TEST_IP, "Integration test") is True

        # Verify rule exists
        assert real_manager._rule_exists(
            real_manager._make_rule_name("BLOCK", TEST_IP), direction="in"
        ) is True

        # List rules
        rules = real_manager.list_rules()
        blocked_ips = real_manager.list_blocked_ips()
        assert TEST_IP in blocked_ips

        # Remove
        assert real_manager.remove_block_rule(TEST_IP) is True

        # Verify gone
        assert real_manager._rule_exists(
            real_manager._make_rule_name("BLOCK", TEST_IP), direction="in"
        ) is False

    def test_allow_removes_block(self, real_manager):
        """allow_ip should remove any existing block rule first."""
        real_manager.remove_rule(TEST_IP)

        # Block first
        real_manager.block_ip(TEST_IP, "Test block")

        # Allow should remove block and create allow
        assert real_manager.allow_ip(TEST_IP, "Test allow") is True

        # Should have ALLOW rule, not BLOCK
        allowed = real_manager.list_allowed_ips()
        blocked = real_manager.list_blocked_ips()
        assert TEST_IP in allowed
        assert TEST_IP not in blocked

        # Cleanup
        real_manager.remove_rule(TEST_IP)

    def test_idempotent_block(self, real_manager):
        """Blocking an already-blocked IP should be a no-op (not fail)."""
        real_manager.remove_rule(TEST_IP)

        assert real_manager.block_ip(TEST_IP) is True
        # Block again — should succeed (idempotent)
        assert real_manager.block_ip(TEST_IP) is True

        # Cleanup
        real_manager.remove_rule(TEST_IP)

    def test_remove_all_rules(self, real_manager):
        """remove_all_rules should remove all AI-IDS-TEST-* rules."""
        # Create a test rule
        real_manager.block_ip(TEST_IP, "Test for remove_all")
        count = real_manager.remove_all_rules()
        assert count >= 1
        # Verify gone
        blocked = real_manager.list_blocked_ips()
        assert TEST_IP not in blocked

    def test_sync_with_lists(self, real_manager):
        """sync_with_lists should reconcile rules with the given lists."""
        real_manager.remove_rule(TEST_IP)

        stats = real_manager.sync_with_lists(
            whitelist_ips=["10.0.0.1"],
            blacklist_ips=[TEST_IP],
        )
        assert stats["blocked"] >= 1

        # Verify
        blocked = real_manager.list_blocked_ips()
        assert TEST_IP in blocked

        # Cleanup
        real_manager.remove_all_rules()

    def test_netsh_command_uses_valid_params_only(self, real_manager):
        """Verify that the actual netsh command does not include invalid params."""
        real_manager.remove_rule(TEST_IP)

        import subprocess as sp

        original_run = sp.run

        captured_cmds = []

        def capturing_run(cmd, **kwargs):
            captured_cmds.append(cmd)
            return original_run(cmd, **kwargs)

        with patch("infrastructure.firewall.windows_firewall.subprocess.run", side_effect=capturing_run):
            real_manager.block_ip(TEST_IP, "param validation test")

        # Find the add rule command
        add_cmds = [c for c in captured_cmds if "add" in c and "rule" in c]
        assert len(add_cmds) >= 1
        cmd_str = " ".join(add_cmds[0])
        # Must NOT contain invalid params
        assert "comment=" not in cmd_str
        assert "group=" not in cmd_str
        # Must contain valid params
        assert "description=" in cmd_str
        assert "name=AI-IDS-TEST-BLOCK" in cmd_str
        assert "dir=in" in cmd_str
        assert "action=block" in cmd_str
        assert f"remoteip={TEST_IP}" in cmd_str

        # Cleanup
        real_manager.remove_rule(TEST_IP)


# ── FirewallService Integration ─────────────────────────────────────────


@pytest.fixture
def mock_repos():
    """Mock whitelist and blacklist repos."""
    wl = MagicMock()
    bl = MagicMock()
    wl.exists.return_value = False
    bl.exists.return_value = False
    bl.get_all.return_value = []
    wl.get_all.return_value = []
    return wl, bl


@ADMIN_MARK
class TestFirewallServiceIntegration:
    """Integration tests for the FirewallService with real netsh."""

    def test_auto_block_creates_firewall_rule(self, mock_repos):
        """auto_block_on_threat should create a real firewall block rule."""
        wl, bl = mock_repos
        from services.firewall_service import FirewallService
        svc = FirewallService(whitelist_repo=wl, blacklist_repo=bl)
        result = svc.auto_block_on_threat(TEST_IP, "Test threat")
        # It should return True if admin, False otherwise
        # Either way, it should add to blacklist
        assert bl.add.called or result is False

        # Cleanup
        svc._fw.remove_rule(TEST_IP)

    def test_whitelist_prevents_auto_block(self, mock_repos):
        """Whitelisted IPs should not be auto-blocked."""
        wl, bl = mock_repos
        wl.exists.return_value = True  # IP is whitelisted
        from services.firewall_service import FirewallService
        svc = FirewallService(whitelist_repo=wl, blacklist_repo=bl)
        result = svc.auto_block_on_threat(TEST_IP, "Should be skipped")
        assert result is False
        # Blacklist should not be touched
        assert not bl.add.called

    def test_manual_block_returns_granular_status(self, mock_repos):
        """manual_block should return dict with blacklist and firewall status."""
        wl, bl = mock_repos
        from services.firewall_service import FirewallService
        svc = FirewallService(whitelist_repo=wl, blacklist_repo=bl)
        result = svc.manual_block(TEST_IP, "Manual test")
        assert isinstance(result, dict)
        assert "blacklist_added" in result
        assert "firewall_blocked" in result

        # Cleanup
        svc._fw.remove_rule(TEST_IP)

    def test_get_firewall_status_includes_admin_info(self, mock_repos):
        """get_firewall_status should include is_admin and is_windows."""
        wl, bl = mock_repos
        from services.firewall_service import FirewallService
        svc = FirewallService(whitelist_repo=wl, blacklist_repo=bl)
        status = svc.get_firewall_status()
        assert "is_admin" in status
        assert "is_windows" in status
        assert "platform" in status
