"""
Unit Tests for SecureShip Policy Engine
Validates deterministic security gate evaluations and threshold enforcement.
"""

import pytest
from policy_engine import PolicyEngine, DECISION_APPROVED, DECISION_BLOCKED

@pytest.fixture
def baseline_policy():
    return {
        "version": 1,
        "name": "Standard Zero-Tolerance Policy",
        "block_critical": 1,
        "block_high": 1,
        "max_critical": 0,
        "max_high": 0,
        "max_medium": 10,
        "max_low": 20,
        "reject_unknown": 1,
        "reject_on_error": 1
    }

def test_clean_scan_approved(baseline_policy):
    """Clean scan with 0 critical, 0 high, and allowed low/medium passes."""
    scan = {
        "status": "SUCCESS",
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 2,
        "low_count": 5,
        "unknown_count": 0,
        "total_vulnerabilities": 7
    }
    result = PolicyEngine.evaluate(scan, baseline_policy)
    assert result.decision == DECISION_APPROVED
    assert result.is_passing is True
    assert len(result.violated_rules) == 0
    assert result.policy_version == 1

def test_critical_vulnerability_blocks(baseline_policy):
    """Any CRITICAL vulnerability must block deployment."""
    scan = {
        "status": "SUCCESS",
        "critical_count": 1,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "unknown_count": 0,
        "total_vulnerabilities": 1
    }
    result = PolicyEngine.evaluate(scan, baseline_policy)
    assert result.decision == DECISION_BLOCKED
    assert result.is_passing is False
    assert any("CRITICAL" in r for r in result.violated_rules)

def test_high_vulnerability_blocks(baseline_policy):
    """Any HIGH vulnerability must block deployment under zero-tolerance."""
    scan = {
        "status": "SUCCESS",
        "critical_count": 0,
        "high_count": 2,
        "medium_count": 0,
        "low_count": 0,
        "unknown_count": 0,
        "total_vulnerabilities": 2
    }
    result = PolicyEngine.evaluate(scan, baseline_policy)
    assert result.decision == DECISION_BLOCKED
    assert result.is_passing is False
    assert any("HIGH" in r for r in result.violated_rules)

def test_medium_exceeding_threshold_blocks(baseline_policy):
    """Medium vulnerabilities exceeding configured threshold must block."""
    scan = {
        "status": "SUCCESS",
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 15,  # Max is 10
        "low_count": 0,
        "unknown_count": 0,
        "total_vulnerabilities": 15
    }
    result = PolicyEngine.evaluate(scan, baseline_policy)
    assert result.decision == DECISION_BLOCKED
    assert any("MEDIUM" in r for r in result.violated_rules)

def test_unknown_severity_blocks_by_default(baseline_policy):
    """Conservative policy rejects unclassified/unknown severity."""
    scan = {
        "status": "SUCCESS",
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "unknown_count": 1,
        "total_vulnerabilities": 1
    }
    result = PolicyEngine.evaluate(scan, baseline_policy)
    assert result.decision == DECISION_BLOCKED
    assert any("UNKNOWN" in r for r in result.violated_rules)

def test_failed_scan_fails_closed(baseline_policy):
    """Failed scan status must immediately result in BLOCKED decision."""
    scan = {
        "status": "FAILED",
        "error_message": "Trivy exited with code 1",
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "unknown_count": 0,
        "total_vulnerabilities": 0
    }
    result = PolicyEngine.evaluate(scan, baseline_policy)
    assert result.decision == DECISION_BLOCKED
    assert result.is_passing is False
    assert "Scan was not successful" in result.violated_rules[0]

def test_incomplete_scan_fails_closed(baseline_policy):
    """Incomplete scan (status != SUCCESS) must not be approved."""
    scan = {
        "status": "INCOMPLETE",
        "critical_count": 0,
        "high_count": 0,
        "total_vulnerabilities": 0
    }
    result = PolicyEngine.evaluate(scan, baseline_policy)
    assert result.decision == DECISION_BLOCKED

def test_policy_custom_thresholds_honored():
    """Custom policy allowing 1 High vulnerability."""
    custom_policy = {
        "version": 2,
        "block_critical": 1,
        "block_high": 0,
        "max_critical": 0,
        "max_high": 1,
        "max_medium": 50,
        "max_low": 50,
        "reject_unknown": 0,
        "reject_on_error": 1
    }
    scan = {
        "status": "SUCCESS",
        "critical_count": 0,
        "high_count": 1,  # Permitted by custom policy
        "medium_count": 5,
        "low_count": 10,
        "unknown_count": 1,
        "total_vulnerabilities": 17
    }
    result = PolicyEngine.evaluate(scan, custom_policy)
    assert result.decision == DECISION_APPROVED
    assert result.policy_version == 2
