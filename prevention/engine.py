"""Master Prevention Engine Orchestrator for Mini-IDS.

Coordinates policy evaluation, manual approval queues, OS/simulation firewall execution,
verification checks, automatic rule rollback, and comprehensive audit logging.
"""

import logging
import platform
import time
from typing import Any, Dict, List, Optional, Tuple

from prevention.approval_manager import ApprovalManager
from prevention.base_adapter import BaseFirewallAdapter
from prevention.linux_firewall_adapter import LinuxFirewallAdapter
from prevention.policy_engine import (
    ActionStatus,
    ActionType,
    PolicyEngine,
    PreventionAction,
    PreventionMode,
    RiskLevel,
)
from prevention.rollback import RollbackManager
from prevention.simulation_adapter import SimulationAdapter
from prevention.verification import VerificationManager
from prevention.windows_firewall_adapter import WindowsFirewallAdapter
from storage.database import DatabaseManager

logger = logging.getLogger(__name__)


class PreventionEngine:
    """End-to-end intrusion prevention orchestrator."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        initial_mode: PreventionMode = PreventionMode.SIMULATION,
        block_threshold: float = 0.70,
        rate_limit_threshold: float = 0.50,
        default_block_duration: int = 300,
        custom_allowlist: Optional[List[str]] = None,
    ) -> None:
        self.db = db_manager or DatabaseManager()
        self.db.init_db()

        self.policy_engine = PolicyEngine(
            default_mode=initial_mode,
            block_threshold=block_threshold,
            rate_limit_threshold=rate_limit_threshold,
            default_block_duration=default_block_duration,
            custom_allowlist=custom_allowlist,
        )

        self.approval_manager = ApprovalManager(self.db)
        self.verification_manager = VerificationManager(self.db)
        self.rollback_manager = RollbackManager(self.db)

        # Adapters
        self.simulation_adapter = SimulationAdapter()
        self.windows_adapter = WindowsFirewallAdapter()
        self.linux_adapter = LinuxFirewallAdapter()

    @property
    def mode(self) -> PreventionMode:
        return self.policy_engine.mode

    @mode.setter
    def mode(self, new_mode: PreventionMode) -> None:
        self.set_mode(new_mode)

    def set_mode(self, new_mode: PreventionMode) -> None:
        """Switch operational prevention mode with audit trail."""
        old_mode = self.policy_engine.mode
        self.policy_engine.mode = new_mode
        self.db.insert_audit_event(
            actor="SYSTEM_OPERATOR",
            action="CHANGE_PREVENTION_MODE",
            target=f"{old_mode.value} -> {new_mode.value}",
            mode=new_mode.value,
            result="SUCCESS",
            details={"previous_mode": old_mode.value, "new_mode": new_mode.value},
        )
        logger.info("Prevention mode switched: %s -> %s", old_mode.value, new_mode.value)

    def get_active_adapter(self, mode: Optional[PreventionMode] = None) -> BaseFirewallAdapter:
        """Select appropriate adapter based on requested mode and host OS."""
        eff_mode = mode or self.mode
        if eff_mode == PreventionMode.AUTHORIZED_ENFORCEMENT:
            if platform.system().lower() == "windows":
                return self.windows_adapter
            elif platform.system().lower() == "linux":
                return self.linux_adapter
        return self.simulation_adapter

    def process_threat(
        self,
        src_ip: str,
        rule_name: str,
        alert_id: Optional[str] = None,
        dst_ip: Optional[str] = None,
        target_port: Optional[int] = None,
        protocol: Optional[str] = None,
        heuristic_severity: Optional[str] = None,
        ml_confidence: Optional[float] = None,
        anomaly_score: Optional[float] = None,
        predicted_class: Optional[str] = None,
        source_tag: Optional[str] = None,
    ) -> PreventionAction:
        """Process an alert or flow observation through policy evaluation and execution."""
        # 1. Evaluate policy
        action = self.policy_engine.evaluate(
            src_ip=src_ip,
            rule_name=rule_name,
            alert_id=alert_id,
            dst_ip=dst_ip,
            target_port=target_port,
            protocol=protocol,
            heuristic_severity=heuristic_severity,
            ml_confidence=ml_confidence,
            anomaly_score=anomaly_score,
            predicted_class=predicted_class,
            source_tag=source_tag,
        )

        # 2. Persist initial action recommendation
        self.db.insert_prevention_action(action.to_dict())

        # 3. Log initial recommendation audit event
        self.db.insert_audit_event(
            actor="POLICY_ENGINE",
            action="POLICY_EVALUATION",
            target=src_ip,
            mode=action.mode.value,
            result="SUCCESS",
            details={
                "action_id": action.action_id,
                "action_type": action.action_type.value,
                "status": action.status.value,
                "threat_score": action.threat_score,
                "risk_level": action.risk_level.value,
                "rule_name": rule_name,
                "details": action.details,
            },
        )

        # 4. Execute or Queue according to mode and action type
        if action.action_type != ActionType.BLOCK_IP:
            # Low risk or non-blocking: remains LOG_ALERT / RATE_LIMIT
            return action

        if action.mode == PreventionMode.SIMULATION:
            self._execute_simulated(action)
        elif action.mode == PreventionMode.MANUAL_APPROVAL:
            logger.info("Action '%s' queued in Manual Approval Queue for %s", action.action_id, src_ip)
        elif action.mode == PreventionMode.AUTHORIZED_ENFORCEMENT:
            self._execute_enforced(action)

        return action

    def _execute_simulated(self, action: PreventionAction) -> None:
        """Execute simulated block without host modification."""
        rule_name = f"MiniIDS_Block_{action.action_id}_{action.target_ip.replace('.', '_').replace(':', '_')}"
        adapter = self.simulation_adapter

        success, msg = adapter.apply_rule(
            rule_name=rule_name,
            target_ip=action.target_ip,
            protocol=action.protocol,
            port=action.target_port,
            duration_seconds=action.duration_seconds,
        )
        now = time.time()
        action.executed_at = now
        action.rule_name = rule_name

        if success:
            action.status = ActionStatus.ACTIVE
            self.db.update_prevention_action_status(
                action_id=action.action_id,
                status=ActionStatus.ACTIVE.value,
                executed_at=now,
            )
            # Verify simulated presence
            if self.verification_manager.verify_action(action.action_id, adapter, rule_name, action.target_ip):
                action.status = ActionStatus.VERIFIED
                action.verified_at = now

            self.db.insert_audit_event(
                actor="SIMULATION_ENGINE",
                action="SIMULATE_BLOCK",
                target=action.target_ip,
                mode=PreventionMode.SIMULATION.value,
                result="SUCCESS",
                details={"action_id": action.action_id, "rule_name": rule_name, "message": msg},
                timestamp=now,
            )
        else:
            action.status = ActionStatus.FAILED
            action.error_message = msg
            self.db.update_prevention_action_status(
                action_id=action.action_id,
                status=ActionStatus.FAILED.value,
                error_message=msg,
            )

    def _execute_enforced(self, action: PreventionAction) -> None:
        """Execute real OS firewall rule (opt-in Authorized Enforcement mode)."""
        adapter = self.get_active_adapter(mode=PreventionMode.AUTHORIZED_ENFORCEMENT)
        avail, reason = adapter.is_available()

        if not avail:
            err_msg = f"Enforcement blocked by safety check: {reason}"
            logger.warning(err_msg)
            action.status = ActionStatus.FAILED
            action.error_message = err_msg
            self.db.update_prevention_action_status(
                action_id=action.action_id,
                status=ActionStatus.FAILED.value,
                error_message=err_msg,
            )
            self.db.insert_audit_event(
                actor="ENFORCEMENT_ENGINE",
                action="ENFORCE_BLOCK",
                target=action.target_ip,
                mode=PreventionMode.AUTHORIZED_ENFORCEMENT.value,
                result="FAILURE",
                details={"action_id": action.action_id, "error": err_msg},
            )
            return

        rule_name = f"MiniIDS_Block_{action.action_id}_{action.target_ip.replace('.', '_').replace(':', '_')}"
        success, msg = adapter.apply_rule(
            rule_name=rule_name,
            target_ip=action.target_ip,
            protocol=action.protocol,
            port=action.target_port,
            duration_seconds=action.duration_seconds,
        )
        now = time.time()
        action.executed_at = now
        action.rule_name = rule_name

        if success:
            action.status = ActionStatus.ACTIVE
            self.db.update_prevention_action_status(
                action_id=action.action_id,
                status=ActionStatus.ACTIVE.value,
                executed_at=now,
            )
            # Verify rule presence in OS firewall
            if self.verification_manager.verify_action(action.action_id, adapter, rule_name, action.target_ip):
                action.status = ActionStatus.VERIFIED
                action.verified_at = now
            else:
                action.status = ActionStatus.FAILED

            self.db.insert_audit_event(
                actor="ENFORCEMENT_ENGINE",
                action="ENFORCE_BLOCK",
                target=action.target_ip,
                mode=PreventionMode.AUTHORIZED_ENFORCEMENT.value,
                result="SUCCESS",
                details={"action_id": action.action_id, "rule_name": rule_name, "message": msg},
                timestamp=now,
            )
        else:
            action.status = ActionStatus.FAILED
            action.error_message = msg
            self.db.update_prevention_action_status(
                action_id=action.action_id,
                status=ActionStatus.FAILED.value,
                error_message=msg,
            )
            self.db.insert_audit_event(
                actor="ENFORCEMENT_ENGINE",
                action="ENFORCE_BLOCK",
                target=action.target_ip,
                mode=PreventionMode.AUTHORIZED_ENFORCEMENT.value,
                result="FAILURE",
                details={"action_id": action.action_id, "rule_name": rule_name, "error": msg},
                timestamp=now,
            )

    def approve_and_execute(
        self,
        action_id: str,
        operator: str = "Admin_Operator",
        reason: Optional[str] = None,
    ) -> bool:
        """Approve an item in the queue and immediately execute the action."""
        if not self.approval_manager.approve_action(action_id, operator=operator, reason=reason):
            return False

        action_dict = self.db.get_prevention_action(action_id)
        if not action_dict:
            return False

        action = PreventionAction(
            action_id=action_dict["action_id"],
            target_ip=action_dict["target_ip"],
            action_type=ActionType(action_dict["action_type"]),
            mode=PreventionMode(action_dict["mode"]),
            status=ActionStatus(action_dict["status"]),
            threat_score=action_dict["threat_score"],
            risk_level=RiskLevel(action_dict["risk_level"]),
            rule_name=action_dict["rule_name"],
            duration_seconds=action_dict["duration_seconds"],
            alert_id=action_dict.get("alert_id"),
            target_port=action_dict.get("target_port"),
            protocol=action_dict.get("protocol"),
            details=action_dict.get("details", {}),
        )

        # If mode is manual approval, execute via simulation or enforcement based on config
        # By default, approved items execute via the active adapter
        if self.mode == PreventionMode.AUTHORIZED_ENFORCEMENT:
            self._execute_enforced(action)
        else:
            self._execute_simulated(action)

        return action.status in [ActionStatus.ACTIVE, ActionStatus.VERIFIED]

    def reject(self, action_id: str, operator: str = "Admin_Operator", reason: Optional[str] = None) -> bool:
        """Reject a pending prevention action."""
        return self.approval_manager.reject_action(action_id, operator=operator, reason=reason)

    def unblock(self, action_id: str, operator: str = "Admin_Operator", reason: Optional[str] = None) -> Tuple[bool, str]:
        """Manually unblock an active rule."""
        action = self.db.get_prevention_action(action_id)
        if not action:
            return False, f"Action ID '{action_id}' not found."

        mode_str = action.get("mode", PreventionMode.SIMULATION.value)
        adapter = self.get_active_adapter(mode=PreventionMode(mode_str))
        return self.rollback_manager.unblock_action(action_id, adapter, operator=operator, reason=reason)

    def expire_timed_rules(self) -> int:
        """Check all active rules and automatically roll back any expired entries."""
        adapter = self.get_active_adapter()
        return self.rollback_manager.check_and_expire_rules(adapter)

    def shutdown(self) -> int:
        """Clean shutdown hook to roll back all active rules and avoid orphan firewall rules."""
        adapter = self.get_active_adapter()
        return self.rollback_manager.rollback_all_active(adapter, reason="System Shutdown")
