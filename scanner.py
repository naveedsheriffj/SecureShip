"""
SecureShip Scanner Integration

Safe, structured integration with Trivy security scanner.
Uses subprocess with argument lists (never shell=True) and strict input validation.
"""

import os
import re
import json
import time
import uuid
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

from config import (
    TRIVY_BIN,
    REPORTS_DIR,
    TRIVY_TIMEOUT,
    IMAGE_REF_REGEX
)
from policy_engine import PolicyEngine
from database import get_active_policy, save_scan

logger = logging.getLogger(__name__)

class ImageReferenceError(ValueError):
    pass

class ScannerExecutionError(RuntimeError):
    pass

class ScannerService:
    """Manages container vulnerability scans using Trivy."""

    @staticmethod
    def validate_image_reference(image_ref: str) -> str:
        """
        Validate image reference format against strict allowlist regex.
        Prevents command injection and illegal characters.
        """
        if not image_ref or not isinstance(image_ref, str):
            raise ImageReferenceError("Image reference cannot be empty.")
        
        image_ref = image_ref.strip()
        if len(image_ref) > 256:
            raise ImageReferenceError("Image reference exceeds maximum allowed length of 256 characters.")

        if not re.match(IMAGE_REF_REGEX, image_ref):
            raise ImageReferenceError(
                f"Invalid image reference format: '{image_ref}'. Must contain only alphanumeric characters, dots, slashes, dashes, colons, or sha256 digests."
            )
        return image_ref

    @staticmethod
    def get_trivy_version() -> Tuple[bool, str]:
        """Detect if Trivy is available and retrieve its version string."""
        try:
            res = subprocess.run(
                [TRIVY_BIN, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            if res.returncode == 0:
                output = res.stdout.strip()
                # Parse "Version: x.y.z" or first line
                match = re.search(r"Version:\s*([^\s]+)", output, re.IGNORECASE)
                if match:
                    return True, match.group(1)
                return True, output.split("\n")[0]
            return False, f"Trivy returned code {res.returncode}: {res.stderr.strip()}"
        except FileNotFoundError:
            return False, "Trivy binary not found in system PATH."
        except subprocess.TimeoutExpired:
            return False, "Timed out checking Trivy version."
        except Exception as e:
            return False, f"Error checking Trivy: {str(e)}"

    @classmethod
    def execute_trivy_scan(cls, image_ref: str, report_filepath: str) -> Tuple[int, str, str, float]:
        """
        Execute Trivy scan subprocess safely.
        Never uses shell=True.
        """
        cmd = [
            TRIVY_BIN,
            "image",
            "--format", "json",
            "--output", report_filepath,
            "--quiet",
            image_ref
        ]

        logger.info("Executing Trivy scan: %s (Output: %s)", " ".join(cmd), report_filepath)
        start_time = time.time()

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=TRIVY_TIMEOUT,
                check=False
            )
            duration = round(time.time() - start_time, 2)
            return proc.returncode, proc.stdout, proc.stderr, duration
        except subprocess.TimeoutExpired:
            duration = round(time.time() - start_time, 2)
            raise ScannerExecutionError(f"Trivy scan timed out after {TRIVY_TIMEOUT} seconds.")
        except FileNotFoundError:
            duration = round(time.time() - start_time, 2)
            raise ScannerExecutionError(f"Trivy executable '{TRIVY_BIN}' could not be executed.")
        except Exception as e:
            duration = round(time.time() - start_time, 2)
            raise ScannerExecutionError(f"Subprocess error executing Trivy: {str(e)}")

    @classmethod
    def parse_trivy_report(cls, report_path: str) -> Tuple[Dict[str, int], List[Dict[str, Any]], Optional[str], Optional[str]]:
        """
        Safely parse Trivy JSON report file.
        Returns:
            (severity_counts, findings_list, image_digest, image_id)
        """
        if not os.path.exists(report_path) or os.path.getsize(report_path) == 0:
            raise ScannerExecutionError("Trivy report file is missing or empty.")

        try:
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ScannerExecutionError(f"Invalid JSON in Trivy report: {str(e)}")

        if not isinstance(data, dict):
            raise ScannerExecutionError("Malformed Trivy report: root element is not an object.")

        # Extract image metadata if present
        metadata = data.get("Metadata", {})
        image_digest = metadata.get("RepoDigests", [None])[0] if isinstance(metadata.get("RepoDigests"), list) and metadata.get("RepoDigests") else None
        image_id = metadata.get("ImageID")

        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0,
            "total": 0
        }
        findings: List[Dict[str, Any]] = []

        # Trivy groups results by target (OS packages, lockfiles, etc.)
        results = data.get("Results", [])
        if not isinstance(results, list):
            raise ScannerExecutionError("Malformed Trivy report: 'Results' is not a list.")

        for target_result in results:
            if not isinstance(target_result, dict):
                continue
            target_name = target_result.get("Target", "Container Image")
            vulns = target_result.get("Vulnerabilities", [])
            if not isinstance(vulns, list):
                continue

            for v in vulns:
                if not isinstance(v, dict):
                    continue
                vuln_id = v.get("VulnerabilityID", "UNKNOWN")
                pkg_name = v.get("PkgName", "unknown")
                installed_ver = v.get("InstalledVersion", "unknown")
                fixed_ver = v.get("FixedVersion", "")
                sev = str(v.get("Severity", "UNKNOWN")).upper()
                title = v.get("Title") or ""
                desc = v.get("Description") or ""
                url = v.get("PrimaryURL") or (v.get("References", [""])[0] if v.get("References") else "")

                # Normalize severity
                if sev == "CRITICAL":
                    counts["critical"] += 1
                elif sev == "HIGH":
                    counts["high"] += 1
                elif sev == "MEDIUM":
                    counts["medium"] += 1
                elif sev == "LOW":
                    counts["low"] += 1
                else:
                    counts["unknown"] += 1
                counts["total"] += 1

                findings.append({
                    "vulnerability_id": vuln_id,
                    "pkg_name": pkg_name,
                    "installed_version": installed_ver,
                    "fixed_version": fixed_ver,
                    "severity": sev,
                    "title": title[:200],
                    "description": desc[:500],
                    "primary_url": url,
                    "target": target_name
                })

        return counts, findings, image_digest, image_id

    @classmethod
    def scan_image(cls, image_ref: str, policy_version: Optional[int] = None, image_id_hint: Optional[str] = None) -> Dict[str, Any]:
        """
        Orchestrate complete scan process:
        1. Validate reference
        2. Verify Trivy availability
        3. Execute Trivy scan
        4. Parse report safely
        5. Evaluate policy
        6. Persist to database
        7. Return structured scan summary
        """
        validated_ref = cls.validate_image_reference(image_ref)
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        report_filename = f"{scan_id}.json"
        report_filepath = str(REPORTS_DIR / report_filename)

        active_policy = get_active_policy()
        target_policy = active_policy

        # Check scanner availability
        trivy_avail, trivy_ver = cls.get_trivy_version()
        if not trivy_avail:
            # Fails closed per security requirement
            err = f"Trivy scanner is not available: {trivy_ver}"
            logger.error(err)
            scan_data = {
                "id": scan_id,
                "image_ref": validated_ref,
                "image_digest": None,
                "image_id": image_id_hint,
                "scanner_name": "trivy",
                "scanner_version": "unavailable",
                "status": "ERROR",
                "policy_version": target_policy["version"],
                "policy_decision": "BLOCKED",
                "decision_reason": f"Scan rejected: {err}. Security policy requires verified scan completion before approval.",
                "total_vulnerabilities": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "unknown_count": 0,
                "report_file": None,
                "duration_seconds": 0.0,
                "error_message": err,
                "is_fixture": False
            }
            save_scan(scan_data, [])
            return scan_data

        try:
            ret_code, stdout, stderr, duration = cls.execute_trivy_scan(validated_ref, report_filepath)
            
            # Trivy returns 0 on success. If report file exists, parse it
            counts, findings, img_digest, parsed_img_id = cls.parse_trivy_report(report_filepath)
            final_img_id = parsed_img_id or image_id_hint

            # Prepare summary for policy evaluation
            scan_summary = {
                "status": "SUCCESS",
                "critical_count": counts["critical"],
                "high_count": counts["high"],
                "medium_count": counts["medium"],
                "low_count": counts["low"],
                "unknown_count": counts["unknown"],
                "total_vulnerabilities": counts["total"],
                "error_message": None
            }

            policy_result = PolicyEngine.evaluate(scan_summary, target_policy)

            scan_data = {
                "id": scan_id,
                "image_ref": validated_ref,
                "image_digest": img_digest,
                "image_id": final_img_id,
                "scanner_name": "trivy",
                "scanner_version": trivy_ver,
                "status": "SUCCESS",
                "policy_version": target_policy["version"],
                "policy_decision": policy_result.decision,
                "decision_reason": policy_result.reason,
                "total_vulnerabilities": counts["total"],
                "critical_count": counts["critical"],
                "high_count": counts["high"],
                "medium_count": counts["medium"],
                "low_count": counts["low"],
                "unknown_count": counts["unknown"],
                "report_file": report_filename,
                "duration_seconds": duration,
                "error_message": None,
                "is_fixture": False
            }

            save_scan(scan_data, findings)
            scan_data["findings"] = findings
            return scan_data

        except ScannerExecutionError as e:
            logger.error("Scanner execution failed: %s", str(e))
            # Policy evaluation for failed scan
            scan_summary = {
                "status": "FAILED",
                "error_message": str(e),
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "unknown_count": 0,
                "total_vulnerabilities": 0
            }
            policy_result = PolicyEngine.evaluate(scan_summary, target_policy)

            scan_data = {
                "id": scan_id,
                "image_ref": validated_ref,
                "image_digest": None,
                "image_id": image_id_hint,
                "scanner_name": "trivy",
                "scanner_version": trivy_ver,
                "status": "FAILED",
                "policy_version": target_policy["version"],
                "policy_decision": policy_result.decision,
                "decision_reason": policy_result.reason,
                "total_vulnerabilities": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "unknown_count": 0,
                "report_file": None,
                "duration_seconds": 0.0,
                "error_message": str(e),
                "is_fixture": False
            }
            save_scan(scan_data, [])
            scan_data["findings"] = []
            return scan_data

    @classmethod
    def process_test_fixture(cls, image_ref: str, fixture_type: str) -> Dict[str, Any]:
        """
        Record a clearly labelled demo fixture for offline policy validation.
        Explicitly marked with is_fixture=True.
        """
        validated_ref = cls.validate_image_reference(image_ref)
        scan_id = f"fixture_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        active_policy = get_active_policy()

        findings: List[Dict[str, Any]] = []

        if fixture_type == "vulnerable":
            # Simulated high & critical findings for demonstration
            findings = [
                {
                    "vulnerability_id": "CVE-2023-38545",
                    "pkg_name": "curl",
                    "installed_version": "7.88.1-10",
                    "fixed_version": "7.88.1-10+deb12u3",
                    "severity": "CRITICAL",
                    "title": "SOCKS5 heap buffer overflow in curl",
                    "description": "Heap-based buffer overflow in curl SOCKS5 handshake implementation allows remote code execution.",
                    "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-38545",
                    "target": "OS Packages (Debian)"
                },
                {
                    "vulnerability_id": "CVE-2023-44487",
                    "pkg_name": "nghttp2",
                    "installed_version": "1.52.0-1",
                    "fixed_version": "1.52.0-1+deb12u1",
                    "severity": "HIGH",
                    "title": "HTTP/2 Rapid Reset Denial of Service",
                    "description": "Rapid stream reset attacks can exhaust server resources leading to denial of service.",
                    "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
                    "target": "OS Packages (Debian)"
                },
                {
                    "vulnerability_id": "CVE-2023-29491",
                    "pkg_name": "ncurses",
                    "installed_version": "6.4-4",
                    "fixed_version": "6.4-4+deb12u1",
                    "severity": "MEDIUM",
                    "title": "Minor memory leak in tic/infocmp",
                    "description": "A denial of service flaw in terminfo parser.",
                    "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-29491",
                    "target": "OS Packages (Debian)"
                }
            ]
            counts = {"critical": 1, "high": 1, "medium": 1, "low": 0, "unknown": 0, "total": 3}
            status = "SUCCESS"
        elif fixture_type == "clean":
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 1, "unknown": 0, "total": 1}
            findings = [
                {
                    "vulnerability_id": "CVE-2024-0001",
                    "pkg_name": "tzdata",
                    "installed_version": "2024a-0",
                    "fixed_version": "2024b-0",
                    "severity": "LOW",
                    "title": "Minor informational update for historical timezone rule",
                    "description": "Non-exploitable documentation discrepancy in daylight saving rule.",
                    "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
                    "target": "tzdata"
                }
            ]
            status = "SUCCESS"
        else:
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "total": 0}
            status = "FAILED"

        scan_summary = {
            "status": status,
            "critical_count": counts["critical"],
            "high_count": counts["high"],
            "medium_count": counts["medium"],
            "low_count": counts["low"],
            "unknown_count": counts["unknown"],
            "total_vulnerabilities": counts["total"],
            "error_message": "Simulated scanner crash" if status != "SUCCESS" else None
        }

        policy_result = PolicyEngine.evaluate(scan_summary, active_policy)

        # Write fixture json file
        report_filename = f"{scan_id}.json"
        report_filepath = str(REPORTS_DIR / report_filename)
        with open(report_filepath, "w", encoding="utf-8") as f:
            json.dump({
                "SchemaVersion": 2,
                "ArtifactName": validated_ref,
                "Metadata": {
                    "ImageID": f"sha256:{uuid.uuid4().hex}{uuid.uuid4().hex}",
                    "RepoDigests": [f"{validated_ref}@sha256:{uuid.uuid4().hex}"]
                },
                "Results": [
                    {
                        "Target": "OS Packages (Debian)",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": f["vulnerability_id"],
                                "PkgName": f["pkg_name"],
                                "InstalledVersion": f["installed_version"],
                                "FixedVersion": f["fixed_version"],
                                "Severity": f["severity"],
                                "Title": f["title"],
                                "Description": f["description"],
                                "PrimaryURL": f["primary_url"]
                            }
                            for f in findings
                        ]
                    }
                ]
            }, f, indent=2)

        scan_data = {
            "id": scan_id,
            "image_ref": validated_ref,
            "image_digest": f"sha256:{uuid.uuid4().hex}",
            "image_id": f"sha256:{uuid.uuid4().hex[:12]}",
            "scanner_name": "trivy-mock-fixture",
            "scanner_version": "fixture-mode",
            "status": status,
            "policy_version": active_policy["version"],
            "policy_decision": policy_result.decision,
            "decision_reason": f"[DEMO FIXTURE] {policy_result.reason}",
            "total_vulnerabilities": counts["total"],
            "critical_count": counts["critical"],
            "high_count": counts["high"],
            "medium_count": counts["medium"],
            "low_count": counts["low"],
            "unknown_count": counts["unknown"],
            "report_file": report_filename,
            "duration_seconds": 0.05,
            "error_message": scan_summary["error_message"],
            "is_fixture": True
        }

        save_scan(scan_data, findings)
        scan_data["findings"] = findings
        return scan_data
