"""Simulation Firewall Adapter for Safe, Non-Intrusive Testing.

Implements a completely safe, in-memory firewall adapter that records all rule lifecycle
events without executing any operating system or kernel firewall commands.
Ideal for educational demonstration, offline PCAP replay, and non-administrative environments.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from prevention.base_adapter import BaseFirewallAdapter

logger = logging.getLogger(__name__)


class SimulationAdapter(BaseFirewallAdapter):
    """Zero-privilege simulated firewall driver."""

    def __init__(self) -> None:
        self._simulated_rules: Dict[str, Dict[str, Any]] = {}

    def is_available(self) -> Tuple[bool, str]:
        """Simulation adapter is universally available across all platforms."""
        return True, "Simulation mode active (safe, zero OS modification)"

    def apply_rule(
        self,
        rule_name: str,
        target_ip: str,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
        duration_seconds: int = 300,
    ) -> Tuple[bool, str]:
        """Record rule creation in simulated state."""
        clean_rule = rule_name if rule_name.startswith(self.RULE_PREFIX) else f"{self.RULE_PREFIX}{rule_name}"
        now = time.time()
        self._simulated_rules[clean_rule] = {
            "rule_name": clean_rule,
            "target_ip": target_ip,
            "protocol": protocol or "ANY",
            "port": port,
            "applied_at": now,
            "expires_at": now + duration_seconds,
            "duration_seconds": duration_seconds,
            "mode": "SIMULATION",
            "is_active": True,
        }
        logger.info("[SIMULATION] Firewall rule '%s' applied for IP %s (duration %ds)", clean_rule, target_ip, duration_seconds)
        return True, f"[SIMULATED] Successfully created rule '{clean_rule}' blocking {target_ip}"

    def verify_rule(self, rule_name: str, target_ip: str) -> bool:
        """Verify rule presence in simulated storage."""
        clean_rule = rule_name if rule_name.startswith(self.RULE_PREFIX) else f"{self.RULE_PREFIX}{rule_name}"
        rule = self._simulated_rules.get(clean_rule)
        if not rule:
            return False
        # Check expiration
        if time.time() > rule["expires_at"]:
            rule["is_active"] = False
            return False
        return rule.get("is_active", False) and rule.get("target_ip") == target_ip

    def remove_rule(self, rule_name: str) -> Tuple[bool, str]:
        """Remove rule from simulated storage."""
        clean_rule = rule_name if rule_name.startswith(self.RULE_PREFIX) else f"{self.RULE_PREFIX}{rule_name}"
        if clean_rule in self._simulated_rules:
            self._simulated_rules[clean_rule]["is_active"] = False
            del self._simulated_rules[clean_rule]
            logger.info("[SIMULATION] Firewall rule '%s' removed", clean_rule)
            return True, f"[SIMULATED] Successfully removed rule '{clean_rule}'"
        return False, f"[SIMULATED] Rule '{clean_rule}' not found in active simulated rules"

    def list_active_rules(self) -> List[Dict[str, Any]]:
        """Return list of active, non-expired simulated rules."""
        now = time.time()
        active = []
        for r_name, r_data in list(self._simulated_rules.items()):
            if now <= r_data["expires_at"] and r_data.get("is_active"):
                active.append(r_data.copy())
            else:
                self._simulated_rules.pop(r_name, None)
        return active
