"""Rule Rollback and Expiration Management for Mini-IDS.

Handles automatic expiration of temporary blocking rules, manual operator unblocking,
and clean shutdown rollback to ensure zero orphaned firewall rules.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from prevention.base_adapter import BaseFirewallAdapter
from prevention.policy_engine import ActionStatus
from storage.database import DatabaseManager

logger = logging.getLogger(__name__)


class RollbackManager:
    """Manages active rule cleanup, timed expiration, and unblock workflows."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db = db_manager

    def unblock_action(
        self,
        action_id: str,
        adapter: BaseFirewallAdapter,
        operator: str = "Operator",
        reason: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Manually unblock an active prevention action and remove the rule."""
        action = self.db.get_prevention_action(action_id)
        if not action:
            return False, f"Action ID '{action_id}' not found."

        rule_name = action.get("rule_name")
        target_ip = action.get("target_ip", "")
        success, msg = adapter.remove_rule(rule_name)
        now = time.time()

        if success or "not found" in msg.lower():
            self.db.update_prevention_action_status(
                action_id=action_id,
                status=ActionStatus.ROLLED_BACK.value,
                rolled_back_at=now,
            )
            self.db.insert_audit_event(
                actor=operator,
                action="MANUAL_UNBLOCK",
                target=target_ip,
                mode=action.get("mode", ""),
                result="SUCCESS",
                details={"action_id": action_id, "rule_name": rule_name, "reason": reason or "Operator requested unblock."},
                timestamp=now,
            )
            logger.info("Manual unblock succeeded for rule '%s' (IP %s)", rule_name, target_ip)
            return True, f"Successfully unblocked {target_ip} (Rule: {rule_name})"
        else:
            self.db.insert_audit_event(
                actor=operator,
                action="MANUAL_UNBLOCK",
                target=target_ip,
                mode=action.get("mode", ""),
                result="FAILURE",
                details={"action_id": action_id, "rule_name": rule_name, "error": msg},
                timestamp=now,
            )
            return False, f"Failed to remove rule '{rule_name}': {msg}"

    def check_and_expire_rules(self, adapter: BaseFirewallAdapter) -> int:
        """Scan active/verified actions and roll back any whose expiration timestamp has passed."""
        now = time.time()
        active_actions = self.db.get_prevention_actions(limit=500)
        expired_count = 0

        for act in active_actions:
            status = act.get("status")
            if status not in [ActionStatus.ACTIVE.value, ActionStatus.VERIFIED.value]:
                continue

            expires_at = act.get("expires_at")
            if expires_at and now >= expires_at:
                action_id = act.get("action_id")
                rule_name = act.get("rule_name")
                target_ip = act.get("target_ip", "")

                adapter.remove_rule(rule_name)
                self.db.update_prevention_action_status(
                    action_id=action_id,
                    status=ActionStatus.EXPIRED.value,
                    rolled_back_at=now,
                )
                self.db.insert_audit_event(
                    actor="EXPIRATION_MONITOR",
                    action="AUTO_EXPIRE_RULE",
                    target=target_ip,
                    mode=act.get("mode", ""),
                    result="SUCCESS",
                    details={"action_id": action_id, "rule_name": rule_name, "expired_at": now},
                    timestamp=now,
                )
                expired_count += 1
                logger.info("Auto-expired prevention rule '%s' for IP %s", rule_name, target_ip)

        return expired_count

    def rollback_all_active(self, adapter: BaseFirewallAdapter, reason: str = "Clean Shutdown") -> int:
        """Emergency or graceful shutdown cleanup of all active rules."""
        active_actions = self.db.get_prevention_actions(limit=500)
        rolled_back_count = 0
        now = time.time()

        for act in active_actions:
            if act.get("status") in [ActionStatus.ACTIVE.value, ActionStatus.VERIFIED.value]:
                rule_name = act.get("rule_name")
                adapter.remove_rule(rule_name)
                self.db.update_prevention_action_status(
                    action_id=act.get("action_id"),
                    status=ActionStatus.ROLLED_BACK.value,
                    rolled_back_at=now,
                )
                self.db.insert_audit_event(
                    actor="SHUTDOWN_HANDLER",
                    action="CLEAN_SHUTDOWN_ROLLBACK",
                    target=act.get("target_ip", ""),
                    mode=act.get("mode", ""),
                    result="SUCCESS",
                    details={"rule_name": rule_name, "reason": reason},
                    timestamp=now,
                )
                rolled_back_count += 1

        return rolled_back_count
