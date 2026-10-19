"""
SecureShip Audit Service

Centralized tracking of all security decisions, policy updates, and deployments.
"""

from typing import List, Dict, Any
from database import log_audit, list_audit_events

class AuditService:
    @staticmethod
    def record(action: str, target: str, details: str, outcome: str):
        log_audit(action=action, target=target, details=details, outcome=outcome)

    @staticmethod
    def get_recent(limit: int = 50) -> List[Dict[str, Any]]:
        return list_audit_events(limit=limit)
