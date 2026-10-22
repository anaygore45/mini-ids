"""Response Policy Engine and Threat Scoring for Mini-IDS.

Calculates composite threat scores (0.0 to 1.0), maps risk levels, enforces strict
allowlists to prevent self-lockout, guards offline PCAP data from touching host firewalls,
and generates prioritized prevention recommendations.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
import ipaddress
import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import uuid

logger = logging.getLogger(__name__)


class PreventionMode(str, Enum):
    """Operational execution mode of the prevention engine."""
    SIMULATION = "SIMULATION"                      # Safe default: Zero OS changes, marks SIMULATED
    MANUAL_APPROVAL = "MANUAL_APPROVAL"            # Recommendation queue: human operator decides
    AUTHORIZED_ENFORCEMENT = "AUTHORIZED_ENFORCEMENT"  # Direct automated firewall enforcement (opt-in)


class ActionType(str, Enum):
    """Supported prevention action types."""
    BLOCK_IP = "BLOCK_IP"
    RATE_LIMIT = "RATE_LIMIT"
    DROP_FLOW = "DROP_FLOW"
    QUARANTINE = "QUARANTINE"
    LOG_ALERT = "LOG_ALERT"


class ActionStatus(str, Enum):
    """Lifecycle statuses of a prevention action."""
    RECOMMENDED = "RECOMMENDED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"
    ACTIVE = "ACTIVE"
    VERIFIED = "VERIFIED"
    EXPIRED = "EXPIRED"
    ROLLED_BACK = "ROLLED_BACK"
    FAILED = "FAILED"


class RiskLevel(str, Enum):
    """Threat severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Default protected IP addresses and subnets that must never be blocked
DEFAULT_ALLOWLIST: Set[str] = {
    "127.0.0.1",
    "::1",
    "localhost",
    "0.0.0.0",
    "255.255.255.255",
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
}


@dataclass
class PreventionAction:
    """Representation of an evaluated prevention action."""
    action_id: str
    target_ip: str
    action_type: ActionType
    mode: PreventionMode
    status: ActionStatus
    threat_score: float
    risk_level: RiskLevel
    rule_name: str
    duration_seconds: int = 300
    alert_id: Optional[str] = None
    target_port: Optional[int] = None
    protocol: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    approved_by: Optional[str] = None
    executed_at: Optional[float] = None
    verified_at: Optional[float] = None
    rolled_back_at: Optional[float] = None
    details: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["action_type"] = self.action_type.value
        d["mode"] = self.mode.value
        d["status"] = self.status.value
        d["risk_level"] = self.risk_level.value
        return d


class PolicyEngine:
    """Evaluates security detections and computes risk-calibrated response recommendations."""

    def __init__(
        self,
        default_mode: PreventionMode = PreventionMode.SIMULATION,
        block_threshold: float = 0.70,
        rate_limit_threshold: float = 0.50,
        default_block_duration: int = 300,
        custom_allowlist: Optional[List[str]] = None,
    ) -> None:
        self.mode = default_mode
        self.block_threshold = block_threshold
        self.rate_limit_threshold = rate_limit_threshold
        self.default_block_duration = default_block_duration
        self.allowlist: Set[str] = set(DEFAULT_ALLOWLIST)
        if custom_allowlist:
            for item in custom_allowlist:
                self.allowlist.add(item.strip())

    def add_to_allowlist(self, ip_or_cidr: str) -> None:
        """Add an IP or network CIDR to the protected allowlist."""
        self.allowlist.add(ip_or_cidr.strip())

    def remove_from_allowlist(self, ip_or_cidr: str) -> None:
        """Remove an item from the allowlist (ignoring critical defaults)."""
        clean = ip_or_cidr.strip()
        if clean not in DEFAULT_ALLOWLIST and clean in self.allowlist:
            self.allowlist.remove(clean)

    def is_allowlisted(self, ip_str: Optional[str]) -> Tuple[bool, str]:
        """Check if an IP address is protected by the allowlist."""
        if not ip_str:
            return True, "Empty IP address is protected by default."

        ip_clean = ip_str.strip()

        # Check IP address object properties first
        try:
            ip_obj = ipaddress.ip_address(ip_clean)
            if ip_obj.is_loopback:
                return True, "Loopback interface (127.0.0.1 / ::1) is strictly protected."
            if ip_obj.is_multicast or ip_obj.is_reserved:
                return True, "Multicast and reserved addresses are strictly protected."

            # Check CIDR networks in allowlist
            for entry in self.allowlist:
                if "/" in entry:
                    try:
                        net = ipaddress.ip_network(entry, strict=False)
                        if ip_obj in net:
                            return True, f"IP belongs to protected network subnet {entry}."
                    except ValueError:
                        continue
        except ValueError:
            pass

        if ip_clean in self.allowlist or ip_clean.lower() == "localhost":
            return True, f"IP '{ip_clean}' matches an exact entry in the protected allowlist."

        return False, ""

    def calculate_threat_score(
        self,
        rule_name: str,
        heuristic_severity: Optional[str] = None,
        ml_confidence: Optional[float] = None,
        anomaly_score: Optional[float] = None,
        predicted_class: Optional[str] = None,
    ) -> Tuple[float, RiskLevel]:
        """Compute normalized composite threat score (0.0 to 1.0) and RiskLevel."""
        weights = {"rule": 0.40, "ml": 0.45, "anomaly": 0.15}

        # 1. Rule component
        rule_score = 0.60
        sev = (heuristic_severity or "").upper()
        if sev == "CRITICAL":
            rule_score = 1.0
        elif sev == "HIGH":
            rule_score = 0.85
        elif sev == "MEDIUM":
            rule_score = 0.60
        elif sev == "LOW":
            rule_score = 0.30

        # Known aggressive rules boost
        rule_upper = rule_name.upper()
        if "DDOS" in rule_upper:
            rule_score = max(rule_score, 0.90)
        elif "PORTSCAN" in rule_upper or "SYN" in rule_upper or "ATTACK" in rule_upper:
            rule_score = max(rule_score, 0.80)

        # 2. ML Classifier component
        ml_score = 0.0
        if ml_confidence is not None:
            pred_cls = str(predicted_class or "").upper()
            if pred_cls not in ["BENIGN", "0"]:
                ml_score = float(ml_confidence)
            else:
                ml_score = 0.05
        else:
            # Rebalance weight to rule if ML unavailable
            weights["rule"] = 0.75
            weights["ml"] = 0.0
            weights["anomaly"] = 0.25

        # 3. Anomaly component
        anom_score = 0.0
        if anomaly_score is not None:
            # Calibrated anomaly score where 1.0 is highest outlier
            anom_score = min(1.0, max(0.0, float(anomaly_score)))

        composite = (
            weights["rule"] * rule_score
            + weights["ml"] * ml_score
            + weights["anomaly"] * anom_score
        )
        composite = round(min(1.0, max(0.0, composite)), 4)

        if composite >= 0.85:
            risk = RiskLevel.CRITICAL
        elif composite >= 0.70:
            risk = RiskLevel.HIGH
        elif composite >= 0.45:
            risk = RiskLevel.MEDIUM
        else:
            risk = RiskLevel.LOW

        return composite, risk

    def evaluate(
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
        mode_override: Optional[PreventionMode] = None,
    ) -> PreventionAction:
        """Evaluate a threat observation and return a prioritized PreventionAction."""
        effective_mode = mode_override or self.mode

        # Check offline capture safeguard:
        # PCAP or Demo traffic is strictly prohibited from touching host firewalls
        is_offline_data = str(source_tag).lower() in ["pcap", "offline", "demo", "sample"]
        if is_offline_data and effective_mode == PreventionMode.AUTHORIZED_ENFORCEMENT:
            logger.warning("Downgrading mode to SIMULATION: Traffic originated from offline capture / demo.")
            effective_mode = PreventionMode.SIMULATION

        threat_score, risk_level = self.calculate_threat_score(
            rule_name=rule_name,
            heuristic_severity=heuristic_severity,
            ml_confidence=ml_confidence,
            anomaly_score=anomaly_score,
            predicted_class=predicted_class,
        )

        # Allowlist Protection Check
        allowlisted, allowlist_reason = self.is_allowlisted(src_ip)

        action_id = f"act_{uuid.uuid4().hex[:12]}"
        now = time.time()
        duration = self.default_block_duration

        if allowlisted:
            # Must never block allowlisted addresses
            action_type = ActionType.LOG_ALERT
            initial_status = ActionStatus.RECOMMENDED
            reason = f"ALLOWLIST PROTECTED: {allowlist_reason}"
        elif threat_score >= self.block_threshold:
            action_type = ActionType.BLOCK_IP
            if effective_mode == PreventionMode.MANUAL_APPROVAL:
                initial_status = ActionStatus.AWAITING_APPROVAL
            else:
                initial_status = ActionStatus.RECOMMENDED
            reason = f"Threat score ({threat_score:.2f}) meets or exceeds blocking threshold ({self.block_threshold:.2f})."
        elif threat_score >= self.rate_limit_threshold:
            action_type = ActionType.RATE_LIMIT
            initial_status = ActionStatus.RECOMMENDED
            reason = f"Threat score ({threat_score:.2f}) warrants flow rate limiting."
        else:
            action_type = ActionType.LOG_ALERT
            initial_status = ActionStatus.RECOMMENDED
            reason = f"Threat score ({threat_score:.2f}) is below active prevention threshold."

        action = PreventionAction(
            action_id=action_id,
            alert_id=alert_id,
            timestamp=now,
            target_ip=src_ip,
            target_port=target_port,
            protocol=protocol,
            action_type=action_type,
            mode=effective_mode,
            status=initial_status,
            threat_score=threat_score,
            risk_level=risk_level,
            rule_name=rule_name,
            duration_seconds=duration,
            expires_at=now + duration if action_type == ActionType.BLOCK_IP else None,
            details={
                "dst_ip": dst_ip,
                "reason": reason,
                "ml_confidence": ml_confidence,
                "anomaly_score": anomaly_score,
                "predicted_class": predicted_class,
                "source_tag": source_tag or "live",
                "allowlisted": allowlisted,
            },
        )
        return action
