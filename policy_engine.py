"""
SecureShip Policy Engine

Pure, deterministic evaluation module for container security scan results.
This module does not perform I/O, execute external commands, or interact with Docker.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

DECISION_APPROVED = "APPROVED"
DECISION_BLOCKED = "BLOCKED"

@dataclass
class PolicyEvaluationResult:
    decision: str  # "APPROVED" or "BLOCKED"
    reason: str
    policy_version: int
    evaluated_at: str
    violated_rules: List[str]
    counts: Dict[str, int]
    is_passing: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PolicyEngine:
    """Deterministic security gate policy evaluator."""

    @staticmethod
    def evaluate(scan_summary: Dict[str, Any], policy: Dict[str, Any]) -> PolicyEvaluationResult:
        """
        Evaluate a scan summary against a policy snapshot.

        Parameters:
            scan_summary: Dictionary containing scan metrics:
                - status: "SUCCESS", "FAILED", "ERROR", etc.
                - critical_count: int
                - high_count: int
                - medium_count: int
                - low_count: int
                - unknown_count: int
                - total_vulnerabilities: int
                - (optional) error_message: str
            policy: Dictionary containing policy configuration:
                - version: int
                - block_critical: bool/int
                - block_high: bool/int
                - max_critical: int
                - max_high: int
                - max_medium: int
                - max_low: int
                - reject_unknown: bool/int
                - reject_on_error: bool/int

        Returns:
            PolicyEvaluationResult with APPROVED or BLOCKED decision.
        """
        evaluated_at = datetime.now(timezone.utc).isoformat()
        policy_version = int(policy.get("version", 1))

        counts = {
            "critical": int(scan_summary.get("critical_count", 0)),
            "high": int(scan_summary.get("high_count", 0)),
            "medium": int(scan_summary.get("medium_count", 0)),
            "low": int(scan_summary.get("low_count", 0)),
            "unknown": int(scan_summary.get("unknown_count", 0)),
            "total": int(scan_summary.get("total_vulnerabilities", 0))
        }

        violated_rules: List[str] = []

        # Rule 1: Scan integrity & status check
        scan_status = str(scan_summary.get("status", "")).upper()
        reject_on_error = bool(policy.get("reject_on_error", True))

        if scan_status != "SUCCESS":
            err_msg = scan_summary.get("error_message") or f"Scan status was '{scan_status}'"
            if reject_on_error:
                violated_rules.append(f"Scan was not successful ({err_msg}). Security policy fails closed on scan failures.")
                return PolicyEvaluationResult(
                    decision=DECISION_BLOCKED,
                    reason=f"Scan failed or incomplete ({err_msg}). Unverified images cannot be approved.",
                    policy_version=policy_version,
                    evaluated_at=evaluated_at,
                    violated_rules=violated_rules,
                    counts=counts,
                    is_passing=False
                )

        # Rule 2: Critical Severity Check
        block_critical = bool(policy.get("block_critical", True))
        max_critical = int(policy.get("max_critical", 0))
        if block_critical and counts["critical"] > 0:
            violated_rules.append(f"Found {counts['critical']} CRITICAL vulnerability(ies) (Policy blocks on any critical)")
        elif counts["critical"] > max_critical:
            violated_rules.append(f"CRITICAL count ({counts['critical']}) exceeds allowed threshold of {max_critical}")

        # Rule 3: High Severity Check
        block_high = bool(policy.get("block_high", True))
        max_high = int(policy.get("max_high", 0))
        if block_high and counts["high"] > 0:
            violated_rules.append(f"Found {counts['high']} HIGH vulnerability(ies) (Policy blocks on any high)")
        elif counts["high"] > max_high:
            violated_rules.append(f"HIGH count ({counts['high']}) exceeds allowed threshold of {max_high}")

        # Rule 4: Medium Severity Threshold
        max_medium = int(policy.get("max_medium", 999))
        if counts["medium"] > max_medium:
            violated_rules.append(f"MEDIUM count ({counts['medium']}) exceeds allowed threshold of {max_medium}")

        # Rule 5: Low Severity Threshold
        max_low = int(policy.get("max_low", 999))
        if counts["low"] > max_low:
            violated_rules.append(f"LOW count ({counts['low']}) exceeds allowed threshold of {max_low}")

        # Rule 6: Unknown Severity Policy
        # Conservative handling: Unclassified vulnerabilities may represent uncharacterized zero-days
        reject_unknown = bool(policy.get("reject_unknown", True))
        if reject_unknown and counts["unknown"] > 0:
            violated_rules.append(f"Found {counts['unknown']} vulnerability(ies) with UNKNOWN severity. Conservative policy disallows unclassified risks.")

        # Final Decision
        if violated_rules:
            reason = "Policy violated: " + "; ".join(violated_rules)
            return PolicyEvaluationResult(
                decision=DECISION_BLOCKED,
                reason=reason,
                policy_version=policy_version,
                evaluated_at=evaluated_at,
                violated_rules=violated_rules,
                counts=counts,
                is_passing=False
            )

        reason = (
            f"Image satisfies security policy v{policy_version}. "
            f"Findings within thresholds: 0 Critical, 0 High, {counts['medium']} Medium, {counts['low']} Low. "
            "Note: Passing verifies policy compliance at scan time and does not guarantee complete absence of unknown risks."
        )

        return PolicyEvaluationResult(
            decision=DECISION_APPROVED,
            reason=reason,
            policy_version=policy_version,
            evaluated_at=evaluated_at,
            violated_rules=[],
            counts=counts,
            is_passing=True
        )
