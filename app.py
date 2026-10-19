"""
SecureShip - Secure Container Delivery Platform
Main Application Server (Flask)
"""

import os
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from flask import (
    Flask,
    request,
    jsonify,
    send_from_directory,
    send_file,
    Response
)

from config import (
    APP_VERSION,
    HOST,
    PORT,
    DEBUG,
    SECRET_KEY,
    DATABASE_PATH,
    REPORTS_DIR,
    ALLOWED_BUNDLED_APPS
)
from database import (
    init_db,
    get_active_policy,
    list_policies,
    update_policy,
    get_scan,
    list_scans,
    count_scans,
    get_deployment,
    list_deployments,
    get_dashboard_stats,
    list_audit_events
)
from scanner import ScannerService, ImageReferenceError, ScannerExecutionError
from docker_service import DockerService, DockerServiceError
from deployment_service import DeploymentService
from audit_service import AuditService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger("secureship")

# Paths for static frontend
FRONTEND_DIR = Path(__file__).resolve().parent / "frontend"

app = Flask(
    __name__,
    static_folder=str(FRONTEND_DIR),
    static_url_path=""
)
app.secret_key = SECRET_KEY

# Initialize database schema on startup
with app.app_context():
    init_db()

# --- Security Headers ---
@app.after_request
def add_security_headers(response: Response) -> Response:
    """Inject defensive HTTP headers to protect against common web threats."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response

# --- Frontend Static Routes ---
@app.route("/")
def serve_index():
    return send_from_directory(str(FRONTEND_DIR), "index.html")

# --- System & Health Endpoints ---
@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "app": "SecureShip",
        "version": APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

@app.route("/api/system/status", methods=["GET"])
def system_status():
    trivy_ok, trivy_info = ScannerService.get_trivy_version()
    docker_ok, docker_info = DockerService.get_docker_status()
    db_ok = os.path.exists(DATABASE_PATH)
    active_pol = get_active_policy()

    return jsonify({
        "application": {
            "name": "SecureShip",
            "version": APP_VERSION,
            "status": "ONLINE"
        },
        "prerequisites": {
            "trivy": {
                "available": trivy_ok,
                "version": trivy_info,
                "guidance": "Install with 'winget install AquaSecurity.Trivy' or download from github.com/aquasecurity/trivy" if not trivy_ok else "Operational"
            },
            "docker": {
                "available": docker_ok,
                "version": docker_info,
                "guidance": "Start Docker Desktop on Windows to enable local container build and deployment" if not docker_ok else "Operational"
            },
            "database": {
                "available": db_ok,
                "path": DATABASE_PATH,
                "status": "CONNECTED"
            }
        },
        "policy": {
            "version": active_pol["version"],
            "name": active_pol["name"],
            "block_critical": bool(active_pol["block_critical"]),
            "block_high": bool(active_pol["block_high"])
        }
    })

# --- Dashboard Endpoints ---
@app.route("/api/dashboard/stats", methods=["GET"])
def dashboard_stats():
    stats = get_dashboard_stats()
    return jsonify(stats)

@app.route("/api/dashboard/activity", methods=["GET"])
def dashboard_activity():
    audit_events = list_audit_events(limit=20)
    deployments = list_deployments(limit=10)
    return jsonify({
        "audit_events": audit_events,
        "recent_deployments": deployments
    })

# --- Bundled Examples Endpoints ---
@app.route("/api/examples", methods=["GET"])
def list_examples():
    apps = [{"key": k, "description": desc} for k, desc in ALLOWED_BUNDLED_APPS.items()]
    return jsonify({"examples": apps})

@app.route("/api/build", methods=["POST"])
def build_image():
    data = request.get_json(silent=True) or {}
    app_key = data.get("app_key", "").strip()
    tag = data.get("tag", "").strip()

    if not app_key or not tag:
        return jsonify({"error": "Both 'app_key' and 'tag' are required."}), 400

    try:
        result = DockerService.build_bundled_image(app_key=app_key, tag=tag)
        AuditService.record(
            action="DOCKER_BUILD",
            target=tag,
            details=f"Built bundled app '{app_key}' as '{tag}' (Duration: {result.get('duration_seconds')}s)",
            outcome="SUCCESS" if result["success"] else "FAILED"
        )
        return jsonify(result), 200 if result["success"] else 400
    except (DockerServiceError, ImageReferenceError) as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Unexpected error in /api/build")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

# --- Scanning Endpoints ---
@app.route("/api/scans", methods=["POST"])
def trigger_scan():
    data = request.get_json(silent=True) or {}
    image_ref = data.get("image_ref", "").strip()

    if not image_ref:
        return jsonify({"error": "Field 'image_ref' is required."}), 400

    try:
        # Check if Docker has this image and retrieve its ID hint
        _, img_id, _ = DockerService.inspect_image(image_ref)
        scan_data = ScannerService.scan_image(image_ref=image_ref, image_id_hint=img_id)
        return jsonify(scan_data), 201
    except ImageReferenceError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Unexpected error during scan")
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

@app.route("/api/scans/fixture", methods=["POST"])
def trigger_fixture_scan():
    """
    Clearly labeled test fixture runner for policy-engine demonstration.
    """
    data = request.get_json(silent=True) or {}
    image_ref = data.get("image_ref", "secureship-test:fixture").strip()
    fixture_type = data.get("fixture_type", "vulnerable").strip()

    try:
        scan_data = ScannerService.process_test_fixture(image_ref=image_ref, fixture_type=fixture_type)
        return jsonify(scan_data), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/scans", methods=["GET"])
def get_scans_list():
    try:
        limit = min(int(request.args.get("limit", 50)), 100)
        page = max(int(request.args.get("page", 1)), 1)
        offset = (page - 1) * limit
        status_filter = request.args.get("status")

        scans = list_scans(limit=limit, offset=offset, status_filter=status_filter)
        total_count = count_scans(status_filter=status_filter)

        return jsonify({
            "scans": scans,
            "page": page,
            "limit": limit,
            "total": total_count,
            "total_pages": (total_count + limit - 1) // limit if total_count > 0 else 1
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/scans/<scan_id>", methods=["GET"])
def get_scan_details(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan '{scan_id}' not found."}), 404
    return jsonify(scan)

@app.route("/api/scans/<scan_id>/report", methods=["GET"])
def download_scan_report(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan '{scan_id}' not found."}), 404

    report_file = scan.get("report_file")
    if not report_file:
        return jsonify({"error": "No raw JSON report available for this scan."}), 404

    # Prevent directory traversal attacks
    safe_filename = os.path.basename(report_file)
    target_path = REPORTS_DIR / safe_filename

    if not target_path.is_file():
        return jsonify({"error": "Report file was not found on disk."}), 404

    as_attachment = request.args.get("download", "false").lower() == "true"
    return send_file(
        str(target_path),
        mimetype="application/json",
        as_attachment=as_attachment,
        download_name=safe_filename
    )

# --- Policies Endpoints ---
@app.route("/api/policies", methods=["GET"])
def get_policies():
    active_pol = get_active_policy()
    all_pols = list_policies()
    return jsonify({
        "active_policy": active_pol,
        "history": all_pols
    })

@app.route("/api/policies", methods=["PUT"])
def set_policy():
    data = request.get_json(silent=True) or {}
    reason = data.get("change_reason", "").strip()
    if not reason:
        return jsonify({"error": "A 'change_reason' must be provided for audit tracking."}), 400

    try:
        new_policy = update_policy(data, reason)
        return jsonify(new_policy), 200
    except Exception as e:
        logger.exception("Failed to update policy")
        return jsonify({"error": f"Failed to update policy: {str(e)}"}), 500

# --- Deployment Endpoints ---
@app.route("/api/deployments", methods=["POST"])
def create_deployment():
    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan_id", "").strip()
    image_ref = data.get("image_ref", "").strip()

    if not scan_id or not image_ref:
        return jsonify({"error": "Both 'scan_id' and 'image_ref' are required."}), 400

    try:
        dep_result = DeploymentService.deploy_image(scan_id=scan_id, image_ref=image_ref)
        status_code = 201 if dep_result["status"] == "DEPLOYED" else 403
        return jsonify(dep_result), status_code
    except Exception as e:
        logger.exception("Unexpected error in deployment")
        return jsonify({"error": f"Deployment error: {str(e)}"}), 500

@app.route("/api/deployments", methods=["GET"])
def get_deployments_list():
    try:
        limit = min(int(request.args.get("limit", 50)), 100)
        deployments = list_deployments(limit=limit)
        return jsonify({"deployments": deployments})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/deployments/<deployment_id>", methods=["GET"])
def get_deployment_detail(deployment_id: str):
    dep = get_deployment(deployment_id)
    if not dep:
        return jsonify({"error": f"Deployment '{deployment_id}' not found."}), 404
    return jsonify(dep)

@app.route("/api/deployments/<deployment_id>/stop", methods=["POST"])
def stop_deployment_endpoint(deployment_id: str):
    try:
        res = DeploymentService.stop_deployment(deployment_id)
        return jsonify(res), 200 if res.get("success") else 400
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": f"Error stopping deployment: {str(e)}"}), 500

@app.route("/api/audit", methods=["GET"])
def get_audit_trail():
    limit = min(int(request.args.get("limit", 50)), 100)
    events = list_audit_events(limit=limit)
    return jsonify({"audit_events": events})

# Global error handler
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Endpoint not found."}), 404
    return send_from_directory(str(FRONTEND_DIR), "index.html")

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error."}), 500

if __name__ == "__main__":
    logger.info("Starting SecureShip server on %s:%s (App Version: %s)", HOST, PORT, APP_VERSION)
    app.run(host=HOST, port=PORT, debug=DEBUG)
