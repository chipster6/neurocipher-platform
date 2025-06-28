#!/usr/bin/env python3
"""
Unified Data Models for AuditHound
Combines compliance auditing with threat hunting and security analytics
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from enum import Enum
import json
import uuid

class RiskLevel(Enum):
    """Risk level enumeration"""
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ComplianceStatus(Enum):
    """Compliance status enumeration"""
    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    NOT_ASSESSED = "not_assessed"

class ThreatStatus(Enum):
    """Threat status enumeration"""
    ACTIVE = "active"
    MITIGATED = "mitigated"
    FALSE_POSITIVE = "false_positive"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"

class AssetType(Enum):
    """Asset type enumeration"""
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    CLOUD_RESOURCE = "cloud_resource"
    CONTAINER = "container"
    DATABASE = "database"
    APPLICATION = "application"

@dataclass
class SecurityAsset:
    """Unified security asset representation with multi-tenant support"""
    asset_id: str
    name: str
    asset_type: AssetType
    client_id: str  # Multi-tenant identifier
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    cloud_provider: Optional[str] = None
    cloud_region: Optional[str] = None
    cloud_account: Optional[str] = None
    operating_system: Optional[str] = None
    criticality: RiskLevel = RiskLevel.MEDIUM
    
    # Compliance related
    compliance_controls: List[str] = field(default_factory=list)
    compliance_status: ComplianceStatus = ComplianceStatus.NOT_ASSESSED
    last_compliance_scan: Optional[datetime] = None
    
    # Threat hunting related
    threat_indicators: List[str] = field(default_factory=list)
    threat_status: ThreatStatus = ThreatStatus.RESOLVED
    last_threat_scan: Optional[datetime] = None
    anomaly_score: float = 0.0
    
    # Multi-tenant metadata
    organization_name: Optional[str] = None
    department: Optional[str] = None
    owner: Optional[str] = None
    cost_center: Optional[str] = None
    
    # Metadata
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def update_compliance_status(self, status: ComplianceStatus, controls: List[str]):
        """Update compliance status and associated controls"""
        self.compliance_status = status
        self.compliance_controls = controls
        self.last_compliance_scan = datetime.now()
        self.updated_at = datetime.now()
    
    def update_threat_status(self, status: ThreatStatus, indicators: List[str], score: float):
        """Update threat status and indicators"""
        self.threat_status = status
        self.threat_indicators = indicators
        self.anomaly_score = score
        self.last_threat_scan = datetime.now()
        self.updated_at = datetime.now()

@dataclass
class UnifiedFinding:
    """Unified finding that covers both compliance and threat hunting with multi-tenant support"""
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    client_id: str = ""  # Multi-tenant identifier
    title: str = ""
    description: str = ""
    finding_type: str = ""  # 'compliance' or 'threat' or 'hybrid'
    severity: RiskLevel = RiskLevel.MEDIUM
    status: str = "open"  # open, investigating, mitigated, resolved, false_positive
    
    # Multi-tenant metadata
    organization_name: Optional[str] = None
    tenant_context: Dict[str, Any] = field(default_factory=dict)
    
    # Asset relationships
    affected_assets: List[str] = field(default_factory=list)
    
    # Compliance specific
    compliance_framework: Optional[str] = None
    control_id: Optional[str] = None
    compliance_score: Optional[float] = None
    remediation_guidance: Optional[str] = None
    
    # Threat hunting specific
    hunting_rule: Optional[str] = None
    mitre_techniques: List[str] = field(default_factory=list)
    iocs: List[Dict] = field(default_factory=list)
    threat_actor: Optional[str] = None
    confidence_score: float = 0.0
    
    # Evidence and context
    evidence: List[Dict] = field(default_factory=list)
    raw_data: Dict = field(default_factory=dict)
    
    # Workflow
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    created_by: str = "audithound"
    
    # External integrations
    misp_event_id: Optional[str] = None
    thehive_case_id: Optional[str] = None
    jira_ticket: Optional[str] = None
    
    def add_evidence(self, evidence_type: str, data: Dict, source: str):
        """Add evidence to the finding"""
        evidence_entry = {
            'type': evidence_type,
            'data': data,
            'source': source,
            'timestamp': datetime.now().isoformat(),
            'hash': self._calculate_evidence_hash(data)
        }
        self.evidence.append(evidence_entry)
        self.updated_at = datetime.now()
    
    def add_ioc(self, ioc_type: str, value: str, description: str = ""):
        """Add IOC to threat-related finding"""
        ioc = {
            'type': ioc_type,
            'value': value,
            'description': description,
            'first_seen': datetime.now().isoformat(),
            'confidence': self.confidence_score
        }
        self.iocs.append(ioc)
        self.updated_at = datetime.now()
    
    def calculate_risk_score(self) -> float:
        """Calculate unified risk score considering both compliance and threat factors"""
        base_score = 0.0
        
        # Severity scoring
        severity_scores = {
            RiskLevel.CRITICAL: 25,
            RiskLevel.HIGH: 20,
            RiskLevel.MEDIUM: 15,
            RiskLevel.LOW: 10,
            RiskLevel.INFO: 5
        }
        base_score += severity_scores.get(self.severity, 10)
        
        # Compliance factor
        if self.compliance_score is not None:
            # Lower compliance score increases risk
            compliance_factor = (100 - self.compliance_score) / 4
            base_score += compliance_factor
        
        # Threat factor
        if self.confidence_score > 0:
            threat_factor = self.confidence_score / 4
            base_score += threat_factor
        
        # Asset criticality factor (if assets are critical)
        asset_factor = len(self.affected_assets) * 2
        base_score += min(asset_factor, 20)  # Cap at 20
        
        # MITRE technique factor
        technique_factor = len(self.mitre_techniques) * 3
        base_score += min(technique_factor, 15)  # Cap at 15
        
        return min(base_score, 100.0)  # Cap at 100
    
    def _calculate_evidence_hash(self, data: Dict) -> str:
        """Calculate hash of evidence data for deduplication"""
        import hashlib
        data_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()[:16]

@dataclass
class ComplianceControl:
    """Enhanced compliance control with threat hunting integration"""
    control_id: str
    description: str
    framework: str
    cloud_providers: List[str] = field(default_factory=list)
    
    # Scoring configuration
    scoring_weights: Dict[str, float] = field(default_factory=dict)
    threshold_compliant: float = 90.0
    threshold_partial: float = 70.0
    
    # Threat hunting integration
    related_hunt_rules: List[str] = field(default_factory=list)
    mitre_mappings: List[str] = field(default_factory=list)
    
    # Assessment configuration
    aws_sources: List[str] = field(default_factory=list)
    gcp_sources: List[str] = field(default_factory=list)
    azure_sources: List[str] = field(default_factory=list)
    
    # Metadata
    category: str = "access_control"
    priority: RiskLevel = RiskLevel.MEDIUM
    automated_assessment: bool = True
    
    def calculate_compliance_score(self, evidence: Dict) -> float:
        """Calculate compliance score from evidence using weighted components"""
        total_score = 0.0
        total_weight = 0.0
        
        for component, weight in self.scoring_weights.items():
            if component in evidence:
                component_score = evidence[component].get('score', 0.0)
                total_score += component_score * weight
                total_weight += weight
        
        if total_weight > 0:
            return total_score / total_weight
        return 0.0
    
    def get_compliance_status(self, score: float) -> ComplianceStatus:
        """Get compliance status based on score thresholds"""
        if score >= self.threshold_compliant:
            return ComplianceStatus.COMPLIANT
        elif score >= self.threshold_partial:
            return ComplianceStatus.PARTIAL
        else:
            return ComplianceStatus.NON_COMPLIANT

@dataclass
class HuntingRule:
    """Enhanced hunting rule with compliance integration"""
    rule_id: str
    name: str
    description: str
    query_logic: Dict
    
    # Classification
    mitre_techniques: List[str] = field(default_factory=list)
    threat_types: List[str] = field(default_factory=list)
    severity: RiskLevel = RiskLevel.MEDIUM
    
    # Compliance integration
    related_controls: List[str] = field(default_factory=list)
    compliance_frameworks: List[str] = field(default_factory=list)
    
    # Execution configuration
    enabled: bool = True
    schedule: str = "0 */6 * * *"  # Every 6 hours
    timeout_seconds: int = 300
    
    # Metadata
    created_by: str = "audithound"
    created_at: datetime = field(default_factory=datetime.now)
    last_execution: Optional[datetime] = None
    execution_count: int = 0
    
    def execute(self, weaviate_client, correlation_window_hours: int = 24) -> List[UnifiedFinding]:
        """Execute hunting rule and return findings"""
        # This will be implemented by the hunting engine
        pass

@dataclass
class ScanResult:
    """Unified scan result for compliance and threat hunting with multi-tenant support"""
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    client_id: str = ""  # Multi-tenant identifier
    scan_type: str = "unified"  # compliance, threat, unified
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    status: str = "running"  # running, completed, failed, cancelled
    
    # Multi-tenant metadata
    organization_name: Optional[str] = None
    initiated_by: Optional[str] = None
    scan_scope: str = "organization"  # organization, department, cost_center
    
    # Scope
    target_assets: List[str] = field(default_factory=list)
    cloud_providers: List[str] = field(default_factory=list)
    compliance_frameworks: List[str] = field(default_factory=list)
    hunting_rules: List[str] = field(default_factory=list)
    
    # Results
    findings: List[UnifiedFinding] = field(default_factory=list)
    compliance_scores: Dict[str, float] = field(default_factory=dict)
    threat_scores: Dict[str, float] = field(default_factory=dict)
    
    # Statistics
    total_assets_scanned: int = 0
    total_controls_assessed: int = 0
    total_hunt_rules_executed: int = 0
    
    # Summary
    overall_compliance_score: float = 0.0
    overall_threat_score: float = 0.0
    critical_findings: int = 0
    high_findings: int = 0
    
    def add_finding(self, finding: UnifiedFinding):
        """Add finding to scan result"""
        self.findings.append(finding)
        
        # Update counters
        if finding.severity == RiskLevel.CRITICAL:
            self.critical_findings += 1
        elif finding.severity == RiskLevel.HIGH:
            self.high_findings += 1
    
    def complete_scan(self):
        """Mark scan as completed and calculate final scores"""
        self.completed_at = datetime.now()
        self.status = "completed"
        
        # Calculate overall scores
        if self.compliance_scores:
            self.overall_compliance_score = sum(self.compliance_scores.values()) / len(self.compliance_scores)
        
        if self.threat_scores:
            self.overall_threat_score = sum(self.threat_scores.values()) / len(self.threat_scores)
    
    def get_summary(self) -> Dict:
        """Get scan summary statistics"""
        return {
            'scan_id': self.scan_id,
            'scan_type': self.scan_type,
            'duration_minutes': self._get_duration_minutes(),
            'status': self.status,
            'total_findings': len(self.findings),
            'critical_findings': self.critical_findings,
            'high_findings': self.high_findings,
            'overall_compliance_score': self.overall_compliance_score,
            'overall_threat_score': self.overall_threat_score,
            'assets_scanned': self.total_assets_scanned,
            'controls_assessed': self.total_controls_assessed,
            'hunt_rules_executed': self.total_hunt_rules_executed
        }
    
    def _get_duration_minutes(self) -> float:
        """Calculate scan duration in minutes"""
        if self.completed_at:
            delta = self.completed_at - self.started_at
            return delta.total_seconds() / 60
        else:
            delta = datetime.now() - self.started_at
            return delta.total_seconds() / 60

# Factory functions for creating unified findings
def create_compliance_finding(control_id: str, framework: str, score: float, 
                            evidence: List[Dict], assets: List[str], client_id: str = "default") -> UnifiedFinding:
    """Create compliance-focused finding"""
    severity = RiskLevel.CRITICAL if score < 50 else RiskLevel.HIGH if score < 70 else RiskLevel.MEDIUM
    
    return UnifiedFinding(
        client_id=client_id,
        title=f"Compliance Issue: {control_id}",
        description=f"Control {control_id} has compliance score of {score:.1f}%",
        finding_type="compliance",
        severity=severity,
        compliance_framework=framework,
        control_id=control_id,
        compliance_score=score,
        affected_assets=assets,
        evidence=evidence
    )

def create_threat_finding(rule_name: str, techniques: List[str], confidence: float,
                         iocs: List[Dict], assets: List[str], client_id: str = "default") -> UnifiedFinding:
    """Create threat hunting focused finding"""
    severity = RiskLevel.CRITICAL if confidence > 90 else RiskLevel.HIGH if confidence > 70 else RiskLevel.MEDIUM
    
    finding = UnifiedFinding(
        client_id=client_id,
        title=f"Threat Detection: {rule_name}",
        description=f"Hunting rule {rule_name} detected suspicious activity",
        finding_type="threat",
        severity=severity,
        hunting_rule=rule_name,
        mitre_techniques=techniques,
        confidence_score=confidence,
        affected_assets=assets
    )
    
    for ioc in iocs:
        finding.add_ioc(ioc['type'], ioc['value'], ioc.get('description', ''))
    
    return finding

def create_hybrid_finding(control_id: str, rule_name: str, compliance_score: float,
                         threat_confidence: float, assets: List[str], client_id: str = "default") -> UnifiedFinding:
    """Create hybrid compliance + threat finding"""
    # Combined risk assessment
    combined_risk = (100 - compliance_score + threat_confidence) / 2
    severity = RiskLevel.CRITICAL if combined_risk > 75 else RiskLevel.HIGH if combined_risk > 50 else RiskLevel.MEDIUM
    
    return UnifiedFinding(
        client_id=client_id,
        title=f"Hybrid Risk: {control_id} + {rule_name}",
        description=f"Compliance control {control_id} failed with concurrent threat activity",
        finding_type="hybrid",
        severity=severity,
        compliance_score=compliance_score,
        control_id=control_id,
        hunting_rule=rule_name,
        confidence_score=threat_confidence,
        affected_assets=assets
    )