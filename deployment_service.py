"""
SecureShip Deployment Service

Strict DevSecOps gatekeeper for local container deployments.
Enforces 8 mandatory pre-flight checks before permitting any deployment.
"""

import uuid
import logging
from datetime import datetime
from typing import Dict, Any, Tuple, Optional

from config import DEPLOYMENT_HOST
from database import (
    get_scan,
    get_active_policy,
    get_policy_by_version,
    save_deployment,
    update_deployment_status,
    get_deployment,
    log_audit
)
from policy_engine import PolicyEngine, DECISION_APPROVED
from docker_service import DockerService, DockerServiceError
from scanner import ScannerService

logger = logging.getLogger(__name__)

class DeploymentGateError(Exception):
    def __init__(self, message: str, check_number: int, check_name: str):
        super().__init__(message)
        self.check_number = check_number
        self.check_name = check_name

class DeploymentService:
    """Controls container delivery through multi-layered security gates."""

    @classmethod
    def verify_security_gates(cls, scan_id: str, requested_image_ref: str) -> Dict[str, Any]:
        """
        Verify all 8 mandatory security gates before deployment.
        Returns validated gate metadata if all 8 pass, otherwise raises DeploymentGateError.
        """
        # Gate 1: Completed, valid scan exists
        scan = get_scan(scan_id)
        if not scan:
            raise DeploymentGateError(
                f"No scan record found with ID '{scan_id}'. Deployment requires an existing completed scan.",
                1, "Scan Existence"
            )

        if scan["status"] != "SUCCESS":
            raise DeploymentGateError(
                f"Scan '{scan_id}' has status '{scan['status']}'. Incomplete or failed scans cannot be deployed.",
                1, "Scan Completion"
            )

        # Gate 2: The scan belongs to the requested image
        if scan["image_ref"] != requested_image_ref:
            raise DeploymentGateError(
                f"Image reference mismatch: Scan '{scan_id}' was performed for '{scan['image_ref']}', but deployment requested '{requested_image_ref}'.",
                2, "Image Reference Match"
            )

        # Gate 3: Image reference is syntactically permitted
        try:
            ScannerService.validate_image_reference(requested_image_ref)
        except Exception as e:
            raise DeploymentGateError(
                f"Image reference failed validation: {str(e)}",
                3, "Image Format Allowlist"
            )

        # Gate 4: Scan passed policy at scan time
        if scan["policy_decision"] != DECISION_APPROVED:
            raise DeploymentGateError(
                f"Deployment blocked: Scan decision was '{scan['policy_decision']}'. Reason: {scan.get('decision_reason', 'Policy violation')}",
                4, "Scan Policy Approval"
            )

        # Gate 5: Re-evaluate against the currently active policy (detect if policy changed)
        current_active_policy = get_active_policy()
        recheck_summary = {
            "status": "SUCCESS",
            "critical_count": scan["critical_count"],
            "high_count": scan["high_count"],
            "medium_count": scan["medium_count"],
            "low_count": scan["low_count"],
            "unknown_count": scan["unknown_count"],
            "total_vulnerabilities": scan["total_vulnerabilities"]
        }
        current_eval = PolicyEngine.evaluate(recheck_summary, current_active_policy)
        if current_eval.decision != DECISION_APPROVED:
            raise DeploymentGateError(
                f"Deployment blocked by current policy revision (v{current_active_policy['version']}): {current_eval.reason}. The image no longer satisfies updated security criteria.",
                5, "Active Policy Re-evaluation"
            )

        # Gate 6: Current image identity matches scanned image identity (prevent mutable tag hijacking)
        docker_avail, _ = DockerService.get_docker_status()
        if docker_avail and not scan.get("is_fixture"):
            exists, current_img_id, current_digest = DockerService.inspect_image(requested_image_ref)
            if not exists:
                raise DeploymentGateError(
                    f"Target image '{requested_image_ref}' does not exist in local Docker storage.",
                    6, "Local Image Availability"
                )
            # If we had an image ID at scan time, verify it hasn't changed
            if scan.get("image_id") and current_img_id and scan["image_id"] != current_img_id:
                raise DeploymentGateError(
                    f"Image identity mismatch! Scanned image ID '{scan['image_id']}' differs from current image ID '{current_img_id}'. The image tag has been modified since the security scan.",
                    6, "Immutable Image Verification"
                )

        # Gate 7: Disallow deploying test fixtures as real containers
        if scan.get("is_fixture"):
            # Fixtures are permitted to test gate decisions, but cannot launch real containers
            raise DeploymentGateError(
                "Scan record is a marked test fixture. Real container deployment requires an authentic Trivy scan.",
                7, "Authentic Scan Verification"
            )

        # Gate 8: Deployment environment prerequisites check
        if not docker_avail:
            raise DeploymentGateError(
                "Docker daemon is not running or unavailable on this host. Cannot proceed to container execution.",
                8, "Docker Daemon Health"
            )

        return {
            "scan": scan,
            "policy": current_active_policy,
            "image_ref": requested_image_ref
        }

    @classmethod
    def deploy_image(cls, scan_id: str, image_ref: str) -> Dict[str, Any]:
        """
        Execute gated deployment if and only if all 8 security gates pass.
        """
        dep_id = f"dep_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        active_policy = get_active_policy()

        try:
            # Run the 8 security checks
            gate_meta = cls.verify_security_gates(scan_id, image_ref)
            scan = gate_meta["scan"]

            # Allocate restricted host port
            host_port = DockerService.find_free_port()
            container_name = f"secureship_{dep_id}"

            # Run container
            success, container_id, err = DockerService.run_container(
                image_ref=image_ref,
                container_name=container_name,
                host_port=host_port,
                target_port=5000
            )

            if not success:
                record = {
                    "id": dep_id,
                    "image_ref": image_ref,
                    "image_digest": scan.get("image_digest"),
                    "scan_id": scan_id,
                    "policy_version": active_policy["version"],
                    "container_id": None,
                    "container_name": container_name,
                    "host_port": host_port,
                    "app_url": None,
                    "status": "FAILED",
                    "reason": f"Container startup failed: {err}"
                }
                save_deployment(record)
                return record

            app_url = f"http://{DEPLOYMENT_HOST}:{host_port}"
            record = {
                "id": dep_id,
                "image_ref": image_ref,
                "image_digest": scan.get("image_digest"),
                "scan_id": scan_id,
                "policy_version": active_policy["version"],
                "container_id": container_id,
                "container_name": container_name,
                "host_port": host_port,
                "app_url": app_url,
                "status": "DEPLOYED",
                "reason": f"All 8 security gates passed. Deployed successfully to {app_url}"
            }
            save_deployment(record)
            return record

        except DeploymentGateError as e:
            logger.warning("Deployment denied at Gate %s (%s): %s", e.check_number, e.check_name, str(e))
            record = {
                "id": dep_id,
                "image_ref": image_ref,
                "image_digest": None,
                "scan_id": scan_id,
                "policy_version": active_policy["version"],
                "container_id": None,
                "container_name": None,
                "host_port": None,
                "app_url": None,
                "status": "DENIED",
                "reason": f"[Gate {e.check_number}: {e.check_name}] {str(e)}"
            }
            save_deployment(record)
            return record

    @classmethod
    def stop_deployment(cls, dep_id: str) -> Dict[str, Any]:
        """
        Safely stop a SecureShip-managed container.
        Only containers recorded in SecureShip database can be stopped.
        """
        dep = get_deployment(dep_id)
        if not dep:
            raise ValueError(f"Deployment record '{dep_id}' not found.")

        if dep["status"] != "DEPLOYED":
            return {"success": False, "message": f"Deployment '{dep_id}' is already {dep['status']}."}

        target = dep.get("container_id") or dep.get("container_name")
        if not target:
            update_deployment_status(dep_id, "STOPPED", stopped=True, reason="No container was running.")
            return {"success": True, "message": "Updated status to STOPPED."}

        success, err = DockerService.stop_container(target)
        if success:
            update_deployment_status(dep_id, "STOPPED", stopped=True, reason="Container stopped cleanly via SecureShip.")
            return {"success": True, "message": f"Container {target} stopped and removed successfully."}
        else:
            update_deployment_status(dep_id, "ERROR", reason=f"Failed to stop container: {err}")
            return {"success": False, "message": f"Failed to stop container: {err}"}
