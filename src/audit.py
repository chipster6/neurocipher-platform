"""Core audit functionality"""
from datetime import datetime
from typing import List, Dict, Optional


class AuditFinding:
    """Represents an audit finding or compliance issue"""

    def __init__(self, title: str, description: str, severity: str, category: str) -> None:
        self.id: Optional[int] = None
        self.title: str = title
        self.description: str = description
        self.severity: str = severity  # critical, high, medium, low
        self.category: str = category
        self.status: str = "open"  # open, in_progress, resolved, closed
        self.created_date: datetime = datetime.now()
        self.updated_date: datetime = datetime.now()
        self.assigned_to: Optional[str] = None
        self.due_date: Optional[datetime] = None

    def assign_to(self, assignee: str) -> None:
        """Assign finding to a person"""
        self.assigned_to = assignee
        self.updated_date = datetime.now()

    def update_status(self, new_status: str) -> None:
        """Update the status of the finding"""
        valid_statuses: List[str] = ["open", "in_progress", "resolved", "closed"]
        if new_status in valid_statuses:
            self.status = new_status
            self.updated_date = datetime.now()
        else:
            raise ValueError(f"Invalid status: {new_status}")


class AuditManager:
    """Manages audit findings and compliance tracking"""

    def __init__(self) -> None:
        self.findings: List[AuditFinding] = []
        self.next_id: int = 1

    def create_finding(self, title: str, description: str, severity: str, category: str) -> AuditFinding:
        """Create a new audit finding"""
        finding: AuditFinding = AuditFinding(title, description, severity, category)
        finding.id = self.next_id
        self.next_id += 1
        self.findings.append(finding)
        return finding

    def get_findings_by_status(self, status: str) -> List[AuditFinding]:
        """Get all findings with a specific status"""
        return [f for f in self.findings if f.status == status]

    def get_findings_by_severity(self, severity: str) -> List[AuditFinding]:
        """Get all findings with a specific severity"""
        return [f for f in self.findings if f.severity == severity]

    def get_summary(self) -> Dict[str, int]:
        """Get a summary of findings by status"""
        summary: Dict[str, int] = {"open": 0, "in_progress": 0, "resolved": 0, "closed": 0}
        for finding in self.findings:
            summary[finding.status] += 1
        return summary
