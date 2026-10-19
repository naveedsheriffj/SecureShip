import sqlite3
import json
import logging
from typing import Optional, Dict, Any, List
from config import DATABASE_PATH

logger = logging.getLogger(__name__)

def get_db_connection() -> sqlite3.Connection:
    """Create a thread-safe connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    """Initialize database tables and create the default policy if not present."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Policies table (stores snapshots and policy history)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version INTEGER UNIQUE NOT NULL,
                name TEXT NOT NULL,
                block_critical BOOLEAN NOT NULL DEFAULT 1,
                block_high BOOLEAN NOT NULL DEFAULT 1,
                max_critical INTEGER NOT NULL DEFAULT 0,
                max_high INTEGER NOT NULL DEFAULT 0,
                max_medium INTEGER NOT NULL DEFAULT 999,
                max_low INTEGER NOT NULL DEFAULT 999,
                reject_unknown BOOLEAN NOT NULL DEFAULT 1,
                reject_on_error BOOLEAN NOT NULL DEFAULT 1,
                change_reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN NOT NULL DEFAULT 1
            )
        """)

        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                image_ref TEXT NOT NULL,
                image_digest TEXT,
                image_id TEXT,
                scanner_name TEXT DEFAULT 'trivy',
                scanner_version TEXT,
                status TEXT NOT NULL,
                policy_version INTEGER NOT NULL,
                policy_decision TEXT NOT NULL,
                decision_reason TEXT,
                total_vulnerabilities INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                unknown_count INTEGER DEFAULT 0,
                report_file TEXT,
                duration_seconds REAL DEFAULT 0.0,
                error_message TEXT,
                is_fixture BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Vulnerabilities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                vulnerability_id TEXT NOT NULL,
                pkg_name TEXT NOT NULL,
                installed_version TEXT,
                fixed_version TEXT,
                severity TEXT NOT NULL,
                title TEXT,
                description TEXT,
                primary_url TEXT,
                target TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)

        # Deployments table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS deployments (
                id TEXT PRIMARY KEY,
                image_ref TEXT NOT NULL,
                image_digest TEXT,
                scan_id TEXT,
                policy_version INTEGER NOT NULL,
                container_id TEXT,
                container_name TEXT,
                host_port INTEGER,
                app_url TEXT,
                status TEXT NOT NULL,
                reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                stopped_at TIMESTAMP
            )
        """)

        # Audit events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                target TEXT,
                details TEXT,
                outcome TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_image ON scans(image_ref)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities(scan_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_deployments_created ON deployments(created_at)")

        # Seed default policy (Version 1) if table is empty
        cursor.execute("SELECT COUNT(*) as cnt FROM policies")
        if cursor.fetchone()["cnt"] == 0:
            cursor.execute("""
                INSERT INTO policies (
                    version, name, block_critical, block_high,
                    max_critical, max_high, max_medium, max_low,
                    reject_unknown, reject_on_error, change_reason, is_active
                ) VALUES (
                    1, 'Standard Zero-Tolerance Policy', 1, 1,
                    0, 0, 999, 999,
                    1, 1, 'Initial default baseline policy: Block on any CRITICAL or HIGH vulnerability, or scanner error', 1
                )
            """)
            cursor.execute("""
                INSERT INTO audit_events (action, target, details, outcome)
                VALUES ('SYSTEM_INIT', 'database', 'Initialized database schema and seeded baseline policy v1', 'SUCCESS')
            """)

        conn.commit()
    logger.info("Database initialized successfully at %s", DATABASE_PATH)

def get_active_policy() -> Dict[str, Any]:
    """Retrieve the currently active security policy."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM policies 
            WHERE is_active = 1 
            ORDER BY version DESC 
            LIMIT 1
        """)
        row = cursor.fetchone()
        if row:
            return dict(row)
        # Fallback if somehow missing
        return {
            "version": 1,
            "name": "Standard Zero-Tolerance Policy",
            "block_critical": 1,
            "block_high": 1,
            "max_critical": 0,
            "max_high": 0,
            "max_medium": 999,
            "max_low": 999,
            "reject_unknown": 1,
            "reject_on_error": 1,
            "change_reason": "Default fallback",
            "is_active": 1
        }

def get_policy_by_version(version: int) -> Optional[Dict[str, Any]]:
    """Retrieve a specific policy version snapshot."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM policies WHERE version = ?", (version,))
        row = cursor.fetchone()
        return dict(row) if row else None

def list_policies() -> List[Dict[str, Any]]:
    """List all historical and active policies."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM policies ORDER BY version DESC")
        return [dict(r) for r in cursor.fetchall()]

def update_policy(data: Dict[str, Any], reason: str) -> Dict[str, Any]:
    """Create a new policy version, mark previous ones inactive, and log audit event."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(version) as max_v FROM policies")
        max_v = cursor.fetchone()["max_v"] or 0
        new_version = max_v + 1

        # Deactivate previous active policies
        cursor.execute("UPDATE policies SET is_active = 0 WHERE is_active = 1")

        name = data.get("name", f"Policy Revision v{new_version}")
        block_critical = 1 if data.get("block_critical", True) else 0
        block_high = 1 if data.get("block_high", True) else 0
        max_critical = int(data.get("max_critical", 0))
        max_high = int(data.get("max_high", 0))
        max_medium = int(data.get("max_medium", 999))
        max_low = int(data.get("max_low", 999))
        reject_unknown = 1 if data.get("reject_unknown", True) else 0
        reject_on_error = 1 if data.get("reject_on_error", True) else 0

        cursor.execute("""
            INSERT INTO policies (
                version, name, block_critical, block_high,
                max_critical, max_high, max_medium, max_low,
                reject_unknown, reject_on_error, change_reason, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """, (
            new_version, name, block_critical, block_high,
            max_critical, max_high, max_medium, max_low,
            reject_unknown, reject_on_error, reason
        ))

        cursor.execute("""
            INSERT INTO audit_events (action, target, details, outcome)
            VALUES ('POLICY_UPDATE', ?, ?, 'SUCCESS')
        """, (
            f"policy_v{new_version}",
            f"Updated to version {new_version}. Reason: {reason}. Block Critical: {block_critical}, Block High: {block_high}"
        ))

        conn.commit()

        cursor.execute("SELECT * FROM policies WHERE version = ?", (new_version,))
        return dict(cursor.fetchone())

def save_scan(scan_data: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
    """Save scan record and findings within an atomic transaction."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO scans (
                id, image_ref, image_digest, image_id, scanner_name, scanner_version,
                status, policy_version, policy_decision, decision_reason,
                total_vulnerabilities, critical_count, high_count, medium_count,
                low_count, unknown_count, report_file, duration_seconds,
                error_message, is_fixture
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_data["id"],
            scan_data["image_ref"],
            scan_data.get("image_digest"),
            scan_data.get("image_id"),
            scan_data.get("scanner_name", "trivy"),
            scan_data.get("scanner_version"),
            scan_data["status"],
            scan_data["policy_version"],
            scan_data["policy_decision"],
            scan_data.get("decision_reason"),
            scan_data.get("total_vulnerabilities", 0),
            scan_data.get("critical_count", 0),
            scan_data.get("high_count", 0),
            scan_data.get("medium_count", 0),
            scan_data.get("low_count", 0),
            scan_data.get("unknown_count", 0),
            scan_data.get("report_file"),
            scan_data.get("duration_seconds", 0.0),
            scan_data.get("error_message"),
            1 if scan_data.get("is_fixture") else 0
        ))

        for f in findings:
            cursor.execute("""
                INSERT INTO vulnerabilities (
                    scan_id, vulnerability_id, pkg_name, installed_version,
                    fixed_version, severity, title, description, primary_url, target
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_data["id"],
                f.get("vulnerability_id", "UNKNOWN-CVE"),
                f.get("pkg_name", "unknown"),
                f.get("installed_version", "unknown"),
                f.get("fixed_version", ""),
                f.get("severity", "UNKNOWN").upper(),
                f.get("title", ""),
                f.get("description", ""),
                f.get("primary_url", ""),
                f.get("target", "")
            ))

        cursor.execute("""
            INSERT INTO audit_events (action, target, details, outcome)
            VALUES ('SCAN_RECORDED', ?, ?, ?)
        """, (
            scan_data["image_ref"],
            f"Scan {scan_data['id']} recorded with decision {scan_data['policy_decision']}. Total CVEs: {scan_data.get('total_vulnerabilities', 0)}",
            scan_data["policy_decision"]
        ))

        conn.commit()
    return scan_data["id"]

def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full scan details with associated findings."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan_row = cursor.fetchone()
        if not scan_row:
            return None

        scan = dict(scan_row)
        cursor.execute("SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY severity DESC, vulnerability_id ASC", (scan_id,))
        scan["findings"] = [dict(r) for r in cursor.fetchall()]
        return scan

def list_scans(limit: int = 50, offset: int = 0, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """List scans with pagination and optional status filter."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM scans"
        params: List[Any] = []
        if status_filter:
            query += " WHERE policy_decision = ?"
            params.append(status_filter)
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]

def count_scans(status_filter: Optional[str] = None) -> int:
    """Count total scans matching optional status filter."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if status_filter:
            cursor.execute("SELECT COUNT(*) as cnt FROM scans WHERE policy_decision = ?", (status_filter,))
        else:
            cursor.execute("SELECT COUNT(*) as cnt FROM scans")
        return cursor.fetchone()["cnt"]

def save_deployment(dep_data: Dict[str, Any]) -> str:
    """Save a new deployment attempt and record audit."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO deployments (
                id, image_ref, image_digest, scan_id, policy_version,
                container_id, container_name, host_port, app_url,
                status, reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            dep_data["id"],
            dep_data["image_ref"],
            dep_data.get("image_digest"),
            dep_data["scan_id"],
            dep_data["policy_version"],
            dep_data.get("container_id"),
            dep_data.get("container_name"),
            dep_data.get("host_port"),
            dep_data.get("app_url"),
            dep_data["status"],
            dep_data.get("reason")
        ))

        cursor.execute("""
            INSERT INTO audit_events (action, target, details, outcome)
            VALUES ('DEPLOYMENT_EVENT', ?, ?, ?)
        """, (
            dep_data["image_ref"],
            f"Deployment {dep_data['id']} for scan {dep_data['scan_id']}: {dep_data.get('reason')}",
            dep_data["status"]
        ))

        conn.commit()
    return dep_data["id"]

def update_deployment_status(dep_id: str, status: str, stopped: bool = False, reason: Optional[str] = None):
    """Update status of a deployment record."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if stopped:
            cursor.execute("""
                UPDATE deployments 
                SET status = ?, stopped_at = CURRENT_TIMESTAMP, reason = COALESCE(?, reason)
                WHERE id = ?
            """, (status, reason, dep_id))
        else:
            cursor.execute("""
                UPDATE deployments 
                SET status = ?, reason = COALESCE(?, reason)
                WHERE id = ?
            """, (status, reason, dep_id))

        cursor.execute("""
            INSERT INTO audit_events (action, target, details, outcome)
            VALUES ('DEPLOYMENT_UPDATE', ?, ?, ?)
        """, (
            dep_id,
            f"Deployment {dep_id} status updated to {status}: {reason or ''}",
            status
        ))
        conn.commit()

def get_deployment(dep_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve deployment record by ID."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM deployments WHERE id = ?", (dep_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def list_deployments(limit: int = 50) -> List[Dict[str, Any]]:
    """List recent deployments."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM deployments ORDER BY created_at DESC LIMIT ?", (limit,))
        return [dict(r) for r in cursor.fetchall()]

def list_audit_events(limit: int = 50) -> List[Dict[str, Any]]:
    """List recent audit events."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_events ORDER BY created_at DESC LIMIT ?", (limit,))
        return [dict(r) for r in cursor.fetchall()]

def log_audit(action: str, target: str, details: str, outcome: str):
    """Log an audit event."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_events (action, target, details, outcome)
            VALUES (?, ?, ?, ?)
        """, (action, target, details, outcome))
        conn.commit()

def get_dashboard_stats() -> Dict[str, Any]:
    """Calculate aggregated dashboard statistics directly from database records."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) as total_scans FROM scans")
        total_scans = cursor.fetchone()["total_scans"]

        cursor.execute("SELECT COUNT(*) as passed FROM scans WHERE policy_decision = 'APPROVED'")
        passed_scans = cursor.fetchone()["passed"]

        cursor.execute("SELECT COUNT(*) as failed FROM scans WHERE policy_decision = 'BLOCKED'")
        failed_scans = cursor.fetchone()["failed"]

        cursor.execute("SELECT SUM(critical_count) as total_crit, SUM(high_count) as total_high, SUM(medium_count) as total_med, SUM(low_count) as total_low FROM scans")
        sum_row = cursor.fetchone()
        total_critical = sum_row["total_crit"] or 0
        total_high = sum_row["total_high"] or 0
        total_medium = sum_row["total_med"] or 0
        total_low = sum_row["total_low"] or 0

        cursor.execute("SELECT COUNT(DISTINCT image_ref) as distinct_images FROM scans")
        distinct_images = cursor.fetchone()["distinct_images"]

        cursor.execute("SELECT COUNT(*) as active_deployments FROM deployments WHERE status = 'DEPLOYED'")
        active_deployments = cursor.fetchone()["active_deployments"]

        # Trend over recent scans
        cursor.execute("""
            SELECT id, image_ref, policy_decision, critical_count, high_count, created_at 
            FROM scans 
            ORDER BY created_at DESC 
            LIMIT 10
        """)
        recent_scans = [dict(r) for r in cursor.fetchall()]

        # Active policy snapshot
        cursor.execute("SELECT * FROM policies WHERE is_active = 1 ORDER BY version DESC LIMIT 1")
        policy_row = cursor.fetchone()
        active_policy = dict(policy_row) if policy_row else None

        return {
            "total_scans": total_scans,
            "passed_scans": passed_scans,
            "failed_scans": failed_scans,
            "distinct_images": distinct_images,
            "active_deployments": active_deployments,
            "severity_distribution": {
                "critical": total_critical,
                "high": total_high,
                "medium": total_medium,
                "low": total_low
            },
            "recent_scans": recent_scans,
            "active_policy": active_policy
        }
