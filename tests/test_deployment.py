"""
Unit Tests for Deployment Gate Enforcement and Lifecycle
Validates the 8 mandatory security gates before container launch.
"""

import pytest
from unittest.mock import patch, MagicMock
from deployment_service import DeploymentService, DeploymentGateError
from database import save_scan, init_db

@pytest.fixture(autouse=True)
def setup_db():
    init_db()

def test_deployment_without_scan_denied():
    """Attempting deployment with a non-existent scan ID is denied."""
    result = DeploymentService.deploy_image(scan_id="non_existent_scan_999", image_ref="app:1.0")
    assert result["status"] == "DENIED"
    assert "No scan record found" in result["reason"]

def test_deployment_blocked_scan_denied():
    """Attempting deployment for an image that failed policy is denied."""
    scan_id = "test_blocked_scan_001"
    save_scan({
        "id": scan_id,
        "image_ref": "vulnerable-app:1.0",
        "image_digest": "sha256:1111",
        "image_id": "sha256:2222",
        "status": "SUCCESS",
        "policy_version": 1,
        "policy_decision": "BLOCKED",
        "decision_reason": "Policy violated: Found 1 CRITICAL vulnerability",
        "total_vulnerabilities": 1,
        "critical_count": 1,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "unknown_count": 0,
        "report_file": "report.json",
        "duration_seconds": 1.2
    }, [])

    result = DeploymentService.deploy_image(scan_id=scan_id, image_ref="vulnerable-app:1.0")
    assert result["status"] == "DENIED"
    assert "Scan decision was 'BLOCKED'" in result["reason"]

def test_deployment_image_ref_mismatch_denied():
    """Deploying a different image tag than what was scanned is denied."""
    scan_id = "test_approved_scan_002"
    save_scan({
        "id": scan_id,
        "image_ref": "app:clean-1.0",
        "image_digest": "sha256:aaaa",
        "image_id": "sha256:bbbb",
        "status": "SUCCESS",
        "policy_version": 1,
        "policy_decision": "APPROVED",
        "decision_reason": "Clean scan",
        "total_vulnerabilities": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "unknown_count": 0,
        "report_file": "report.json"
    }, [])

    result = DeploymentService.deploy_image(scan_id=scan_id, image_ref="app:different-tag")
    assert result["status"] == "DENIED"
    assert "Image reference mismatch" in result["reason"]

@patch("deployment_service.DockerService.get_docker_status")
@patch("deployment_service.DockerService.inspect_image")
@patch("deployment_service.DockerService.find_free_port")
@patch("deployment_service.DockerService.run_container")
def test_approved_deployment_executes_container(mock_run, mock_port, mock_inspect, mock_docker_status):
    """When all 8 gates pass, container is started on localhost."""
    mock_docker_status.return_value = (True, "Docker Engine 25.0")
    mock_inspect.return_value = (True, "sha256:bbbb", "sha256:aaaa")
    mock_port.return_value = 5022
    mock_run.return_value = (True, "cont12345678", None)

    scan_id = "test_valid_scan_003"
    save_scan({
        "id": scan_id,
        "image_ref": "secureship-clean:1.0",
        "image_digest": "sha256:aaaa",
        "image_id": "sha256:bbbb",
        "status": "SUCCESS",
        "policy_version": 1,
        "policy_decision": "APPROVED",
        "decision_reason": "Approved",
        "total_vulnerabilities": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "unknown_count": 0,
        "report_file": "clean.json"
    }, [])

    result = DeploymentService.deploy_image(scan_id=scan_id, image_ref="secureship-clean:1.0")
    assert result["status"] == "DEPLOYED"
    assert result["container_id"] == "cont12345678"
    assert result["host_port"] == 5022
    assert "http://127.0.0.1:5022" in result["app_url"]

def test_stop_unregistered_deployment_fails():
    """Stopping a non-existent deployment ID raises ValueError."""
    with pytest.raises(ValueError):
        DeploymentService.stop_deployment("dep_non_existent")
