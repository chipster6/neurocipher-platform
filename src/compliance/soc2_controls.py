#!/usr/bin/env python3
"""
SOC 2 Type II Controls Implementation for AuditHound
Implements comprehensive Trust Services Criteria (TSC) controls
"""

import os
import json
import logging
import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import time

# Import our security components
from src.security.config_manager import get_config
from src.security.secrets_manager import SecretsManager

logger = logging.getLogger(__name__)

class SOC2Category(Enum):
    """SOC 2 Trust Services Criteria Categories"""
    SECURITY = "security"
    AVAILABILITY = "availability"
    PROCESSING_INTEGRITY = "processing_integrity"
    CONFIDENTIALITY = "confidentiality"
    PRIVACY = "privacy"

class ControlType(Enum):
    """Types of SOC 2 controls"""
    POLICY = "policy"
    PROCEDURE = "procedure"
    TECHNICAL = "technical"
    ADMINISTRATIVE = "administrative"

class ControlFrequency(Enum):
    """Control execution frequency"""
    CONTINUOUS = "continuous"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    ANNUALLY = "annually"

class ControlStatus(Enum):
    """Control implementation status"""
    IMPLEMENTED = "implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    NOT_IMPLEMENTED = "not_implemented"
    REMEDIATION_REQUIRED = "remediation_required"

@dataclass
class SOC2Control:
    """Individual SOC 2 control definition"""
    control_id: str
    category: SOC2Category
    control_type: ControlType
    title: str
    description: str
    control_objective: str
    frequency: ControlFrequency
    status: ControlStatus = ControlStatus.NOT_IMPLEMENTED
    
    # Implementation details
    implementation_notes: str = ""
    evidence_location: str = ""
    responsible_party: str = ""
    review_date: Optional[datetime] = None
    next_review: Optional[datetime] = None
    
    # Testing and validation
    last_tested: Optional[datetime] = None
    test_results: List[Dict[str, Any]] = field(default_factory=list)
    exceptions: List[str] = field(default_factory=list)
    
    # Metrics and monitoring
    metrics: Dict[str, Any] = field(default_factory=dict)
    automated_monitoring: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "control_id": self.control_id,
            "category": self.category.value,
            "control_type": self.control_type.value,
            "title": self.title,
            "description": self.description,
            "control_objective": self.control_objective,
            "frequency": self.frequency.value,
            "status": self.status.value,
            "implementation_notes": self.implementation_notes,
            "evidence_location": self.evidence_location,
            "responsible_party": self.responsible_party,
            "review_date": self.review_date.isoformat() if self.review_date else None,
            "next_review": self.next_review.isoformat() if self.next_review else None,
            "last_tested": self.last_tested.isoformat() if self.last_tested else None,
            "test_results": self.test_results,
            "exceptions": self.exceptions,
            "metrics": self.metrics,
            "automated_monitoring": self.automated_monitoring
        }

class SOC2Logger:
    """SOC 2 compliant logging system"""
    
    def __init__(self, log_directory: str = "logs/soc2"):
        """Initialize SOC 2 logging"""
        self.log_directory = Path(log_directory)
        self.log_directory.mkdir(parents=True, exist_ok=True)
        
        # Create separate logs for different categories
        self.access_log = self.log_directory / "access_log.jsonl"
        self.change_log = self.log_directory / "change_management.jsonl"
        self.incident_log = self.log_directory / "incidents.jsonl"
        self.audit_log = self.log_directory / "audit_trail.jsonl"
        self.system_log = self.log_directory / "system_events.jsonl"
        
        # Initialize log files with headers if they don't exist
        for log_file in [self.access_log, self.change_log, self.incident_log, self.audit_log, self.system_log]:
            if not log_file.exists():
                self._initialize_log_file(log_file)
    
    def _initialize_log_file(self, log_file: Path):
        """Initialize log file with header"""
        header = {
            "log_initialized": datetime.now().isoformat(),
            "log_file": str(log_file),
            "format_version": "1.0",
            "compliance": "SOC 2 Type II"
        }
        
        with open(log_file, 'w') as f:
            f.write(json.dumps(header) + '\n')
    
    def log_access(self, user_id: str, resource: str, action: str, 
                   result: str, ip_address: str = None, **kwargs):
        """Log access events for CC6.1 - Logical Access Controls"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "access",
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "result": result,
            "ip_address": ip_address,
            "session_id": kwargs.get("session_id"),
            "user_agent": kwargs.get("user_agent"),
            "additional_data": kwargs
        }
        
        self._write_log_entry(self.access_log, event)
    
    def log_change(self, change_id: str, change_type: str, description: str,
                   requestor: str, approver: str, status: str, **kwargs):
        """Log change management events for CC8.1 - Change Management"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "change",
            "change_id": change_id,
            "change_type": change_type,
            "description": description,
            "requestor": requestor,
            "approver": approver,
            "status": status,
            "implementation_date": kwargs.get("implementation_date"),
            "rollback_plan": kwargs.get("rollback_plan"),
            "testing_results": kwargs.get("testing_results"),
            "additional_data": kwargs
        }
        
        self._write_log_entry(self.change_log, event)
    
    def log_incident(self, incident_id: str, severity: str, category: str,
                     description: str, status: str, **kwargs):
        """Log security incidents for CC7.4 - Incident Response"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "incident",
            "incident_id": incident_id,
            "severity": severity,
            "category": category,
            "description": description,
            "status": status,
            "detected_by": kwargs.get("detected_by"),
            "assigned_to": kwargs.get("assigned_to"),
            "resolution_time": kwargs.get("resolution_time"),
            "root_cause": kwargs.get("root_cause"),
            "remediation_actions": kwargs.get("remediation_actions"),
            "additional_data": kwargs
        }
        
        self._write_log_entry(self.incident_log, event)
    
    def log_audit_event(self, event_type: str, description: str, 
                       performed_by: str, **kwargs):
        """Log audit events for CC4.1 - Monitoring Controls"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "audit",
            "audit_event_type": event_type,
            "description": description,
            "performed_by": performed_by,
            "system_component": kwargs.get("system_component"),
            "before_state": kwargs.get("before_state"),
            "after_state": kwargs.get("after_state"),
            "additional_data": kwargs
        }
        
        self._write_log_entry(self.audit_log, event)
    
    def log_system_event(self, event_type: str, component: str, 
                        status: str, **kwargs):
        """Log system events for availability monitoring"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "system",
            "system_event_type": event_type,
            "component": component,
            "status": status,
            "cpu_usage": kwargs.get("cpu_usage"),
            "memory_usage": kwargs.get("memory_usage"),
            "disk_usage": kwargs.get("disk_usage"),
            "response_time": kwargs.get("response_time"),
            "additional_data": kwargs
        }
        
        self._write_log_entry(self.system_log, event)
    
    def _write_log_entry(self, log_file: Path, event: Dict[str, Any]):
        """Write log entry to file with integrity check"""
        # Add integrity hash
        event_json = json.dumps(event, sort_keys=True)
        event["integrity_hash"] = hashlib.sha256(event_json.encode()).hexdigest()
        
        # Write to log file
        with open(log_file, 'a') as f:
            f.write(json.dumps(event) + '\n')
    
    def get_log_summary(self, days: int = 30) -> Dict[str, Any]:
        """Get summary of logs for the specified period"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        summary = {
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
                "days": days
            },
            "access_events": self._count_events(self.access_log, start_date, end_date),
            "changes": self._count_events(self.change_log, start_date, end_date),
            "incidents": self._count_events(self.incident_log, start_date, end_date),
            "audit_events": self._count_events(self.audit_log, start_date, end_date),
            "system_events": self._count_events(self.system_log, start_date, end_date)
        }
        
        return summary
    
    def _count_events(self, log_file: Path, start_date: datetime, end_date: datetime) -> int:
        """Count events in log file within date range"""
        if not log_file.exists():
            return 0
        
        count = 0
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        event_time = datetime.fromisoformat(event.get("timestamp", ""))
                        if start_date <= event_time <= end_date:
                            count += 1
                    except (json.JSONDecodeError, ValueError):
                        continue
        except Exception as e:
            logger.error(f"Error reading log file {log_file}: {e}")
        
        return count

class ChangeManagement:
    """SOC 2 compliant change management system"""
    
    def __init__(self, change_directory: str = "changes"):
        """Initialize change management system"""
        self.change_directory = Path(change_directory)
        self.change_directory.mkdir(parents=True, exist_ok=True)
        self.soc2_logger = SOC2Logger()
        
        # Change tracking
        self.changes_file = self.change_directory / "changes_register.json"
        self.changes = self._load_changes()
    
    def _load_changes(self) -> Dict[str, Any]:
        """Load existing changes from file"""
        if self.changes_file.exists():
            try:
                with open(self.changes_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading changes: {e}")
        return {"changes": [], "metadata": {"created": datetime.now().isoformat()}}
    
    def _save_changes(self):
        """Save changes to file"""
        try:
            with open(self.changes_file, 'w') as f:
                json.dump(self.changes, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving changes: {e}")
    
    def create_change_request(self, title: str, description: str, 
                            change_type: str, requestor: str,
                            business_justification: str,
                            risk_assessment: str = "low",
                            **kwargs) -> str:
        """Create a new change request"""
        change_id = f"CHG-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        
        change_request = {
            "change_id": change_id,
            "title": title,
            "description": description,
            "change_type": change_type,
            "requestor": requestor,
            "business_justification": business_justification,
            "risk_assessment": risk_assessment,
            "status": "submitted",
            "created_date": datetime.now().isoformat(),
            "target_implementation": kwargs.get("target_implementation"),
            "affected_systems": kwargs.get("affected_systems", []),
            "rollback_plan": kwargs.get("rollback_plan", ""),
            "testing_plan": kwargs.get("testing_plan", ""),
            "approval_workflow": [],
            "implementation_log": [],
            "post_implementation_review": None
        }
        
        self.changes["changes"].append(change_request)
        self._save_changes()
        
        # Log the change request
        self.soc2_logger.log_change(
            change_id=change_id,
            change_type=change_type,
            description=f"Change request created: {title}",
            requestor=requestor,
            approver="pending",
            status="submitted",
            business_justification=business_justification,
            risk_assessment=risk_assessment
        )
        
        logger.info(f"Change request created: {change_id}")
        return change_id
    
    def approve_change(self, change_id: str, approver: str, 
                      approval_notes: str = "") -> bool:
        """Approve a change request"""
        change = self._find_change(change_id)
        if not change:
            return False
        
        approval = {
            "approver": approver,
            "approval_date": datetime.now().isoformat(),
            "approval_notes": approval_notes,
            "decision": "approved"
        }
        
        change["approval_workflow"].append(approval)
        change["status"] = "approved"
        self._save_changes()
        
        # Log the approval
        self.soc2_logger.log_change(
            change_id=change_id,
            change_type=change["change_type"],
            description=f"Change approved: {change['title']}",
            requestor=change["requestor"],
            approver=approver,
            status="approved",
            approval_notes=approval_notes
        )
        
        return True
    
    def implement_change(self, change_id: str, implementer: str,
                        implementation_notes: str) -> bool:
        """Mark change as implemented"""
        change = self._find_change(change_id)
        if not change or change["status"] != "approved":
            return False
        
        implementation = {
            "implementer": implementer,
            "implementation_date": datetime.now().isoformat(),
            "implementation_notes": implementation_notes,
            "status": "completed"
        }
        
        change["implementation_log"].append(implementation)
        change["status"] = "implemented"
        self._save_changes()
        
        # Log the implementation
        self.soc2_logger.log_change(
            change_id=change_id,
            change_type=change["change_type"],
            description=f"Change implemented: {change['title']}",
            requestor=change["requestor"],
            approver=implementer,
            status="implemented",
            implementation_notes=implementation_notes
        )
        
        return True
    
    def _find_change(self, change_id: str) -> Optional[Dict[str, Any]]:
        """Find change by ID"""
        for change in self.changes["changes"]:
            if change["change_id"] == change_id:
                return change
        return None
    
    def get_change_status(self, change_id: str) -> Dict[str, Any]:
        """Get status of a specific change"""
        change = self._find_change(change_id)
        if change:
            return {
                "change_id": change_id,
                "status": change["status"],
                "title": change["title"],
                "requestor": change["requestor"],
                "created_date": change["created_date"],
                "approval_count": len(change["approval_workflow"]),
                "implementation_count": len(change["implementation_log"])
            }
        return {"error": "Change not found"}
    
    def get_pending_changes(self) -> List[Dict[str, Any]]:
        """Get all pending changes requiring approval"""
        return [change for change in self.changes["changes"] 
                if change["status"] in ["submitted", "approved"]]

class IncidentResponse:
    """SOC 2 compliant incident response system"""
    
    def __init__(self, incident_directory: str = "incidents"):
        """Initialize incident response system"""
        self.incident_directory = Path(incident_directory)
        self.incident_directory.mkdir(parents=True, exist_ok=True)
        self.soc2_logger = SOC2Logger()
        
        # Incident tracking
        self.incidents_file = self.incident_directory / "incidents_register.json"
        self.incidents = self._load_incidents()
        
        # Incident response procedures
        self.procedures = self._load_incident_procedures()
    
    def _load_incidents(self) -> Dict[str, Any]:
        """Load existing incidents from file"""
        if self.incidents_file.exists():
            try:
                with open(self.incidents_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading incidents: {e}")
        return {"incidents": [], "metadata": {"created": datetime.now().isoformat()}}
    
    def _save_incidents(self):
        """Save incidents to file"""
        try:
            with open(self.incidents_file, 'w') as f:
                json.dump(self.incidents, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving incidents: {e}")
    
    def _load_incident_procedures(self) -> Dict[str, Any]:
        """Load incident response procedures"""
        return {
            "security_breach": {
                "steps": [
                    "Immediate containment",
                    "Evidence preservation",
                    "Impact assessment", 
                    "Notification procedures",
                    "Recovery actions",
                    "Post-incident review"
                ],
                "notification_timeline": "Within 1 hour",
                "escalation_criteria": "Data exposure, system compromise"
            },
            "availability_incident": {
                "steps": [
                    "Service status assessment",
                    "User notification",
                    "Root cause analysis",
                    "Service restoration",
                    "Communication updates",
                    "Post-mortem"
                ],
                "notification_timeline": "Within 15 minutes",
                "escalation_criteria": "Service downtime > 30 minutes"
            },
            "data_incident": {
                "steps": [
                    "Data exposure assessment",
                    "Immediate containment",
                    "Legal/compliance notification",
                    "Affected party notification",
                    "Remediation actions",
                    "Regulatory reporting"
                ],
                "notification_timeline": "Within 30 minutes",
                "escalation_criteria": "PII exposure, regulatory data"
            }
        }
    
    def create_incident(self, title: str, description: str, 
                       severity: str, category: str,
                       detected_by: str, **kwargs) -> str:
        """Create a new security incident"""
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        
        incident = {
            "incident_id": incident_id,
            "title": title,
            "description": description,
            "severity": severity,  # critical, high, medium, low
            "category": category,  # security_breach, availability_incident, data_incident
            "detected_by": detected_by,
            "status": "open",
            "created_date": datetime.now().isoformat(),
            "detection_method": kwargs.get("detection_method", "manual"),
            "affected_systems": kwargs.get("affected_systems", []),
            "potential_impact": kwargs.get("potential_impact", ""),
            "initial_response": kwargs.get("initial_response", ""),
            "timeline": [],
            "evidence": [],
            "response_team": [],
            "communications": [],
            "resolution": None,
            "lessons_learned": None
        }
        
        self.incidents["incidents"].append(incident)
        self._save_incidents()
        
        # Log the incident
        self.soc2_logger.log_incident(
            incident_id=incident_id,
            severity=severity,
            category=category,
            description=f"Incident created: {title}",
            status="open",
            detected_by=detected_by,
            detection_method=kwargs.get("detection_method")
        )
        
        # Auto-assign based on severity and category
        self._auto_assign_incident(incident_id, severity, category)
        
        logger.info(f"Incident created: {incident_id}")
        return incident_id
    
    def _auto_assign_incident(self, incident_id: str, severity: str, category: str):
        """Auto-assign incident based on severity and type"""
        incident = self._find_incident(incident_id)
        if not incident:
            return
        
        # Default response team based on category
        response_teams = {
            "security_breach": ["security_team", "legal_team", "management"],
            "availability_incident": ["engineering_team", "operations_team"],
            "data_incident": ["security_team", "legal_team", "compliance_team", "management"]
        }
        
        assigned_team = response_teams.get(category, ["engineering_team"])
        
        # Escalate based on severity
        if severity in ["critical", "high"]:
            assigned_team.append("management")
            if severity == "critical":
                assigned_team.append("executive_team")
        
        incident["response_team"] = list(set(assigned_team))
        self._save_incidents()
    
    def update_incident(self, incident_id: str, update_type: str,
                       description: str, updated_by: str) -> bool:
        """Update incident with new information"""
        incident = self._find_incident(incident_id)
        if not incident:
            return False
        
        update = {
            "timestamp": datetime.now().isoformat(),
            "update_type": update_type,
            "description": description,
            "updated_by": updated_by
        }
        
        incident["timeline"].append(update)
        self._save_incidents()
        
        # Log the update
        self.soc2_logger.log_incident(
            incident_id=incident_id,
            severity=incident["severity"],
            category=incident["category"],
            description=f"Incident updated: {description}",
            status=incident["status"],
            updated_by=updated_by
        )
        
        return True
    
    def close_incident(self, incident_id: str, resolution_summary: str,
                      root_cause: str, closed_by: str,
                      lessons_learned: str = "") -> bool:
        """Close an incident with resolution details"""
        incident = self._find_incident(incident_id)
        if not incident:
            return False
        
        resolution = {
            "closed_date": datetime.now().isoformat(),
            "closed_by": closed_by,
            "resolution_summary": resolution_summary,
            "root_cause": root_cause,
            "resolution_time_hours": self._calculate_resolution_time(incident["created_date"])
        }
        
        incident["resolution"] = resolution
        incident["lessons_learned"] = lessons_learned
        incident["status"] = "closed"
        self._save_incidents()
        
        # Log the closure
        self.soc2_logger.log_incident(
            incident_id=incident_id,
            severity=incident["severity"],
            category=incident["category"],
            description=f"Incident closed: {resolution_summary}",
            status="closed",
            closed_by=closed_by,
            resolution_time=resolution["resolution_time_hours"],
            root_cause=root_cause
        )
        
        return True
    
    def _calculate_resolution_time(self, created_date: str) -> float:
        """Calculate resolution time in hours"""
        try:
            created = datetime.fromisoformat(created_date)
            now = datetime.now()
            return (now - created).total_seconds() / 3600
        except:
            return 0.0
    
    def _find_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Find incident by ID"""
        for incident in self.incidents["incidents"]:
            if incident["incident_id"] == incident_id:
                return incident
        return None
    
    def get_open_incidents(self) -> List[Dict[str, Any]]:
        """Get all open incidents"""
        return [incident for incident in self.incidents["incidents"] 
                if incident["status"] == "open"]
    
    def get_incident_metrics(self, days: int = 30) -> Dict[str, Any]:
        """Get incident metrics for specified period"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        period_incidents = []
        for incident in self.incidents["incidents"]:
            created = datetime.fromisoformat(incident["created_date"])
            if start_date <= created <= end_date:
                period_incidents.append(incident)
        
        # Calculate metrics
        total_incidents = len(period_incidents)
        by_severity = {}
        by_category = {}
        avg_resolution_time = 0
        
        for incident in period_incidents:
            # Count by severity
            severity = incident["severity"]
            by_severity[severity] = by_severity.get(severity, 0) + 1
            
            # Count by category
            category = incident["category"]
            by_category[category] = by_category.get(category, 0) + 1
            
            # Calculate average resolution time
            if incident.get("resolution"):
                avg_resolution_time += incident["resolution"]["resolution_time_hours"]
        
        if total_incidents > 0:
            avg_resolution_time = avg_resolution_time / total_incidents
        
        return {
            "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
            "total_incidents": total_incidents,
            "by_severity": by_severity,
            "by_category": by_category,
            "average_resolution_time_hours": avg_resolution_time,
            "open_incidents": len(self.get_open_incidents())
        }

class SOC2ControlsManager:
    """Main SOC 2 controls management system"""
    
    def __init__(self, controls_directory: str = "soc2_controls"):
        """Initialize SOC 2 controls manager"""
        self.controls_directory = Path(controls_directory)
        self.controls_directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize subsystems
        self.logger = SOC2Logger()
        self.change_mgmt = ChangeManagement()
        self.incident_response = IncidentResponse()
        
        # Load control definitions
        self.controls = self._initialize_soc2_controls()
        self.controls_file = self.controls_directory / "controls_register.json"
        self._save_controls()
        
        logger.info("SOC 2 Controls Manager initialized")
    
    def _initialize_soc2_controls(self) -> Dict[str, SOC2Control]:
        """Initialize all SOC 2 control definitions"""
        controls = {}
        
        # CC1 - Control Environment
        controls["CC1.1"] = SOC2Control(
            control_id="CC1.1",
            category=SOC2Category.SECURITY,
            control_type=ControlType.POLICY,
            title="Entity Management Oversight",
            description="Management establishes oversight responsibility for internal controls",
            control_objective="Ensure proper governance and oversight of security controls",
            frequency=ControlFrequency.QUARTERLY
        )
        
        # CC2 - Communication and Information
        controls["CC2.1"] = SOC2Control(
            control_id="CC2.1",
            category=SOC2Category.SECURITY,
            control_type=ControlType.PROCEDURE,
            title="Internal Communication",
            description="Management communicates information necessary for effective operation of internal controls",
            control_objective="Ensure security policies and procedures are communicated to all personnel",
            frequency=ControlFrequency.QUARTERLY
        )
        
        # CC3 - Risk Assessment
        controls["CC3.1"] = SOC2Control(
            control_id="CC3.1",
            category=SOC2Category.SECURITY,
            control_type=ControlType.PROCEDURE,
            title="Risk Identification and Assessment",
            description="Management identifies and assesses risks relevant to achieving objectives",
            control_objective="Identify, assess, and mitigate security risks",
            frequency=ControlFrequency.QUARTERLY
        )
        
        # CC4 - Monitoring Activities
        controls["CC4.1"] = SOC2Control(
            control_id="CC4.1",
            category=SOC2Category.SECURITY,
            control_type=ControlType.TECHNICAL,
            title="Ongoing Monitoring",
            description="Management establishes and operates monitoring activities",
            control_objective="Continuously monitor security controls effectiveness",
            frequency=ControlFrequency.CONTINUOUS,
            automated_monitoring=True
        )
        
        # CC5 - Control Activities
        controls["CC5.1"] = SOC2Control(
            control_id="CC5.1",
            category=SOC2Category.SECURITY,
            control_type=ControlType.TECHNICAL,
            title="Control Activity Design",
            description="Management designs control activities to achieve objectives",
            control_objective="Implement technical security controls",
            frequency=ControlFrequency.CONTINUOUS,
            automated_monitoring=True
        )
        
        # CC6 - Logical and Physical Access Controls
        controls["CC6.1"] = SOC2Control(
            control_id="CC6.1",
            category=SOC2Category.SECURITY,
            control_type=ControlType.TECHNICAL,
            title="Logical Access Controls",
            description="Restrict logical access to information assets through access control software",
            control_objective="Ensure only authorized users can access systems and data",
            frequency=ControlFrequency.CONTINUOUS,
            automated_monitoring=True
        )
        
        controls["CC6.2"] = SOC2Control(
            control_id="CC6.2",
            category=SOC2Category.SECURITY,
            control_type=ControlType.TECHNICAL,
            title="Authentication and Authorization",
            description="Prior to issuing system credentials, identify and authenticate users",
            control_objective="Implement strong authentication and authorization mechanisms",
            frequency=ControlFrequency.CONTINUOUS,
            automated_monitoring=True
        )
        
        controls["CC6.3"] = SOC2Control(
            control_id="CC6.3",
            category=SOC2Category.SECURITY,
            control_type=ControlType.TECHNICAL,
            title="Network Security",
            description="Restrict network access through network security devices",
            control_objective="Protect network infrastructure from unauthorized access",
            frequency=ControlFrequency.CONTINUOUS,
            automated_monitoring=True
        )
        
        # CC7 - System Operations
        controls["CC7.1"] = SOC2Control(
            control_id="CC7.1",
            category=SOC2Category.SECURITY,
            control_type=ControlType.TECHNICAL,
            title="System Monitoring",
            description="Detect and respond to system threats and security incidents",
            control_objective="Monitor systems for security threats and anomalies",
            frequency=ControlFrequency.CONTINUOUS,
            automated_monitoring=True
        )
        
        controls["CC7.2"] = SOC2Control(
            control_id="CC7.2",
            category=SOC2Category.SECURITY,
            control_type=ControlType.TECHNICAL,
            title="System Backup and Recovery",
            description="Back up data and implement disaster recovery procedures",
            control_objective="Ensure data availability and business continuity",
            frequency=ControlFrequency.DAILY,
            automated_monitoring=True
        )
        
        controls["CC7.4"] = SOC2Control(
            control_id="CC7.4",
            category=SOC2Category.SECURITY,
            control_type=ControlType.PROCEDURE,
            title="Incident Response",
            description="Respond to security incidents in accordance with procedures",
            control_objective="Effectively respond to and manage security incidents",
            frequency=ControlFrequency.CONTINUOUS
        )
        
        # CC8 - Change Management
        controls["CC8.1"] = SOC2Control(
            control_id="CC8.1",
            category=SOC2Category.SECURITY,
            control_type=ControlType.PROCEDURE,
            title="Change Management Process",
            description="Authorize, design, develop, configure, document, test, approve, and implement changes",
            control_objective="Ensure all changes are properly authorized, tested, and documented",
            frequency=ControlFrequency.CONTINUOUS
        )
        
        # Availability Controls
        controls["A1.1"] = SOC2Control(
            control_id="A1.1",
            category=SOC2Category.AVAILABILITY,
            control_type=ControlType.TECHNICAL,
            title="Availability Monitoring",
            description="Monitor system availability and performance",
            control_objective="Ensure systems meet availability commitments",
            frequency=ControlFrequency.CONTINUOUS,
            automated_monitoring=True
        )
        
        controls["A1.2"] = SOC2Control(
            control_id="A1.2",
            category=SOC2Category.AVAILABILITY,
            control_type=ControlType.TECHNICAL,
            title="Capacity Management",
            description="Monitor and manage system capacity to meet processing requirements",
            control_objective="Ensure adequate system capacity for processing needs",
            frequency=ControlFrequency.CONTINUOUS,
            automated_monitoring=True
        )
        
        # Processing Integrity Controls
        controls["PI1.1"] = SOC2Control(
            control_id="PI1.1",
            category=SOC2Category.PROCESSING_INTEGRITY,
            control_type=ControlType.TECHNICAL,
            title="Data Processing Integrity",
            description="Design and implement controls to ensure complete and accurate processing",
            control_objective="Ensure data processing is complete, valid, and accurate",
            frequency=ControlFrequency.CONTINUOUS,
            automated_monitoring=True
        )
        
        # Confidentiality Controls
        controls["C1.1"] = SOC2Control(
            control_id="C1.1",
            category=SOC2Category.CONFIDENTIALITY,
            control_type=ControlType.TECHNICAL,
            title="Data Encryption",
            description="Encrypt confidential information during transmission and storage",
            control_objective="Protect confidential information through encryption",
            frequency=ControlFrequency.CONTINUOUS,
            automated_monitoring=True
        )
        
        # Privacy Controls
        controls["P1.1"] = SOC2Control(
            control_id="P1.1",
            category=SOC2Category.PRIVACY,
            control_type=ControlType.POLICY,
            title="Privacy Notice",
            description="Provide notice about privacy practices",
            control_objective="Inform individuals about privacy practices and data collection",
            frequency=ControlFrequency.ANNUALLY
        )
        
        return controls
    
    def _save_controls(self):
        """Save controls to file"""
        controls_data = {
            "controls": {k: v.to_dict() for k, v in self.controls.items()},
            "metadata": {
                "last_updated": datetime.now().isoformat(),
                "total_controls": len(self.controls)
            }
        }
        
        try:
            with open(self.controls_file, 'w') as f:
                json.dump(controls_data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving controls: {e}")
    
    def update_control_status(self, control_id: str, status: ControlStatus,
                            implementation_notes: str = "",
                            evidence_location: str = "",
                            responsible_party: str = "") -> bool:
        """Update the implementation status of a control"""
        if control_id not in self.controls:
            return False
        
        control = self.controls[control_id]
        control.status = status
        control.implementation_notes = implementation_notes
        control.evidence_location = evidence_location
        control.responsible_party = responsible_party
        control.review_date = datetime.now()
        
        # Set next review date based on frequency
        frequency_days = {
            ControlFrequency.CONTINUOUS: 30,
            ControlFrequency.DAILY: 30,
            ControlFrequency.WEEKLY: 30,
            ControlFrequency.MONTHLY: 90,
            ControlFrequency.QUARTERLY: 90,
            ControlFrequency.ANNUALLY: 365
        }
        
        days_to_add = frequency_days.get(control.frequency, 90)
        control.next_review = datetime.now() + timedelta(days=days_to_add)
        
        self._save_controls()
        
        # Log the control update
        self.logger.log_audit_event(
            event_type="control_update",
            description=f"Control {control_id} status updated to {status.value}",
            performed_by=responsible_party,
            control_id=control_id,
            status=status.value,
            implementation_notes=implementation_notes
        )
        
        return True
    
    def test_control(self, control_id: str, test_description: str,
                    test_result: str, tester: str,
                    exceptions: List[str] = None) -> bool:
        """Record control testing results"""
        if control_id not in self.controls:
            return False
        
        control = self.controls[control_id]
        
        test_record = {
            "test_date": datetime.now().isoformat(),
            "test_description": test_description,
            "test_result": test_result,
            "tester": tester,
            "exceptions": exceptions or []
        }
        
        control.test_results.append(test_record)
        control.last_tested = datetime.now()
        
        if exceptions:
            control.exceptions.extend(exceptions)
        
        self._save_controls()
        
        # Log the control test
        self.logger.log_audit_event(
            event_type="control_test",
            description=f"Control {control_id} tested: {test_result}",
            performed_by=tester,
            control_id=control_id,
            test_result=test_result,
            exceptions=exceptions
        )
        
        return True
    
    def get_control_dashboard(self) -> Dict[str, Any]:
        """Get SOC 2 controls dashboard"""
        total_controls = len(self.controls)
        implemented = len([c for c in self.controls.values() if c.status == ControlStatus.IMPLEMENTED])
        partially_implemented = len([c for c in self.controls.values() if c.status == ControlStatus.PARTIALLY_IMPLEMENTED])
        not_implemented = len([c for c in self.controls.values() if c.status == ControlStatus.NOT_IMPLEMENTED])
        remediation_required = len([c for c in self.controls.values() if c.status == ControlStatus.REMEDIATION_REQUIRED])
        
        # Controls by category
        by_category = {}
        for control in self.controls.values():
            category = control.category.value
            if category not in by_category:
                by_category[category] = {"total": 0, "implemented": 0}
            by_category[category]["total"] += 1
            if control.status == ControlStatus.IMPLEMENTED:
                by_category[category]["implemented"] += 1
        
        # Controls requiring review
        requiring_review = []
        for control_id, control in self.controls.items():
            if control.next_review and control.next_review <= datetime.now():
                requiring_review.append(control_id)
        
        return {
            "summary": {
                "total_controls": total_controls,
                "implemented": implemented,
                "partially_implemented": partially_implemented,
                "not_implemented": not_implemented,
                "remediation_required": remediation_required,
                "implementation_percentage": (implemented / total_controls * 100) if total_controls > 0 else 0
            },
            "by_category": by_category,
            "requiring_review": requiring_review,
            "recent_changes": len(self.change_mgmt.get_pending_changes()),
            "open_incidents": len(self.incident_response.get_open_incidents())
        }
    
    def generate_soc2_report(self) -> Dict[str, Any]:
        """Generate comprehensive SOC 2 compliance report"""
        # Get controls status
        controls_dashboard = self.get_control_dashboard()
        
        # Get logging summary
        log_summary = self.logger.get_log_summary(days=90)
        
        # Get incident metrics
        incident_metrics = self.incident_response.get_incident_metrics(days=90)
        
        # Get change management summary
        pending_changes = self.change_mgmt.get_pending_changes()
        
        report = {
            "report_date": datetime.now().isoformat(),
            "reporting_period": "90 days",
            "controls_summary": controls_dashboard,
            "logging_summary": log_summary,
            "incident_metrics": incident_metrics,
            "change_management": {
                "pending_changes": len(pending_changes),
                "changes_by_status": {}
            },
            "compliance_status": {
                "overall_status": "compliant" if controls_dashboard["summary"]["implementation_percentage"] >= 90 else "non_compliant",
                "key_findings": [],
                "recommendations": []
            }
        }
        
        # Add key findings and recommendations
        if controls_dashboard["summary"]["remediation_required"] > 0:
            report["compliance_status"]["key_findings"].append(f"{controls_dashboard['summary']['remediation_required']} controls require remediation")
        
        if len(controls_dashboard["requiring_review"]) > 0:
            report["compliance_status"]["key_findings"].append(f"{len(controls_dashboard['requiring_review'])} controls require review")
        
        if incident_metrics["total_incidents"] > 0:
            report["compliance_status"]["key_findings"].append(f"{incident_metrics['total_incidents']} incidents occurred in reporting period")
        
        return report

# Factory function
def create_soc2_controls_manager(controls_directory: str = "soc2_controls") -> SOC2ControlsManager:
    """Create SOC 2 controls manager instance"""
    return SOC2ControlsManager(controls_directory)

# Example usage and testing
if __name__ == "__main__":
    # Initialize SOC 2 controls
    soc2_mgr = create_soc2_controls_manager()
    
    # Example: Update some controls to implemented status
    soc2_mgr.update_control_status(
        "CC6.1",
        ControlStatus.IMPLEMENTED,
        "Implemented logical access controls with multi-factor authentication",
        "access_control_policy.pdf",
        "Security Team"
    )
    
    soc2_mgr.update_control_status(
        "CC8.1", 
        ControlStatus.IMPLEMENTED,
        "Change management process documented and implemented",
        "change_management_procedure.pdf",
        "Engineering Team"
    )
    
    # Example: Create a change request
    change_id = soc2_mgr.change_mgmt.create_change_request(
        "Update security logging configuration",
        "Enhance security logging to capture additional events for SOC 2 compliance",
        "security_enhancement",
        "Security Team",
        "Required for SOC 2 Type II compliance",
        "low"
    )
    
    # Example: Create an incident
    incident_id = soc2_mgr.incident_response.create_incident(
        "Unusual login activity detected",
        "Multiple failed login attempts from suspicious IP addresses",
        "medium",
        "security_breach",
        "Security Monitoring System"
    )
    
    # Generate compliance dashboard
    dashboard = soc2_mgr.get_control_dashboard()
    print("🛡️ SOC 2 Controls Dashboard:")
    print(f"   Total Controls: {dashboard['summary']['total_controls']}")
    print(f"   Implemented: {dashboard['summary']['implemented']}")
    print(f"   Implementation %: {dashboard['summary']['implementation_percentage']:.1f}%")
    
    print(f"\n📋 Recent Activity:")
    print(f"   Pending Changes: {dashboard['recent_changes']}")
    print(f"   Open Incidents: {dashboard['open_incidents']}")
    
    print(f"\n✅ SOC 2 Type II controls framework initialized successfully!")