"""Firewall Verification Subsystem for Mini-IDS.

Ensures that no prevention action is reported as active or verified unless the underlying
adapter (simulation state or OS firewall) affirmatively confirms that the rule is enforced.
"""

import logging
import time
from typing import Any, Dict, Optional, Tuple

from prevention.base_adapter import BaseFirewallAdapter
from prevention.policy_engine import ActionStatus
from storage.database import DatabaseManager

logger = logging.getLogger(__name__)


class VerificationManager:
    """Verifies active enforcement of prevention actions against the configured adapter."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db = db_manager

    def verify_action(
        self,
        action_id: str,
        adapter: BaseFirewallAdapter,
        rule_name: str,
        target_ip: str,
    ) -> bool:
        """Query the adapter to verify rule presence and update persistent status."""
        is_verified = adapter.verify_rule(rule_name, target_ip)
        now = time.time()

        if is_verified:
            self.db.update_prevention_action_status(
                action_id=action_id,
                status=ActionStatus.VERIFIED.value,
                verified_at=now,
            )
            self.db.insert_audit_event(
                actor="VERIFICATION_ENGINE",
                action="VERIFY_RULE",
                target=target_ip,
                mode=adapter.__class__.__name__,
                result="SUCCESS",
                details={"action_id": action_id, "rule_name": rule_name, "verified": True},
                timestamp=now,
            )
            logger.info("Rule '%s' for IP %s verified successfully.", rule_name, target_ip)
            return True
        else:
            self.db.update_prevention_action_status(
                action_id=action_id,
                status=ActionStatus.FAILED.value,
                error_message="Verification check failed: Rule not detected in active table.",
            )
            self.db.insert_audit_event(
                actor="VERIFICATION_ENGINE",
                action="VERIFY_RULE",
                target=target_ip,
                mode=adapter.__class__.__name__,
                result="FAILURE",
                details={"action_id": action_id, "rule_name": rule_name, "verified": False},
                timestamp=now,
            )
            logger.warning("Verification check failed for rule '%s' (target: %s).", rule_name, target_ip)
            return False
