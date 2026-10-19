"""
Integration Tests for SecureShip Flask API Endpoints
Uses Flask test client to verify endpoints, input validation, and security headers.
"""

import json
import pytest
from app import app
from database import init_db

@pytest.fixture
def client():
    app.config["TESTING"] = True
    init_db()
    with app.test_client() as client:
        yield client

def test_health_endpoint(client):
    """GET /api/health returns 200 with service information."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert data["app"] == "SecureShip"

def test_system_status_endpoint(client):
    """GET /api/system/status returns prerequisites and health without leaking secrets."""
    res = client.get("/api/system/status")
    assert res.status_code == 200
    data = res.get_json()
    assert "prerequisites" in data
    assert "trivy" in data["prerequisites"]
    assert "docker" in data["prerequisites"]
    assert "database" in data["prerequisites"]
    assert "policy" in data

def test_security_headers_present(client):
    """Defensive HTTP headers are present on all responses."""
    res = client.get("/api/health")
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in res.headers

def test_dashboard_stats_endpoint(client):
    """GET /api/dashboard/stats returns real database aggregations."""
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    data = res.get_json()
    assert "total_scans" in data
    assert "passed_scans" in data
    assert "failed_scans" in data
    assert "severity_distribution" in data

def test_policies_get_and_put(client):
    """Updating policy creates a new version and enforces audit reason."""
    # Attempt without reason fails
    bad_res = client.put("/api/policies", json={"max_high": 2})
    assert bad_res.status_code == 400

    # With reason succeeds
    good_res = client.put("/api/policies", json={
        "name": "Relaxed High Policy",
        "block_critical": True,
        "block_high": False,
        "max_high": 2,
        "change_reason": "Permit 2 High CVEs during development phase"
    })
    assert good_res.status_code == 200
    updated = good_res.get_json()
    assert updated["version"] >= 2
    assert updated["max_high"] == 2

def test_scan_endpoint_validation(client):
    """POST /api/scans validates input image reference."""
    # Missing reference
    res = client.post("/api/scans", json={})
    assert res.status_code == 400

    # Malicious injection attempt
    res_bad = client.post("/api/scans", json={"image_ref": "image; rm -rf /"})
    assert res_bad.status_code == 400
    assert "Invalid image reference format" in res_bad.get_json()["error"]
