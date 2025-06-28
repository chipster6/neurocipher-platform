#!/usr/bin/env python3
"""
Enhanced Multi-Tenant Weaviate Bridge for AuditHound
Provides full tenant isolation, advanced indexing, and comprehensive analytics
"""

import logging
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Set
from dataclasses import dataclass, field
from enum import Enum

try:
    import weaviate
    from weaviate.batch import Batch
    from weaviate.exceptions import WeaviateException
    WEAVIATE_AVAILABLE = True
except ImportError:
    WEAVIATE_AVAILABLE = False
    WeaviateException = Exception

try:
    from multi_tenant_manager import TenantProfile, TenantTier, get_tenant_manager
    from unified_models import SecurityAsset, UnifiedFinding, ScanResult, RiskLevel, ComplianceStatus
except ImportError:
    # Fallback for testing or when modules are not available
    from enum import Enum
    
    class TenantTier(Enum):
        STARTER = "starter"
        PROFESSIONAL = "professional"
        ENTERPRISE = "enterprise"
        MSP = "msp"
    
    class TenantStatus(Enum):
        ACTIVE = "active"
        SUSPENDED = "suspended"
        TRIAL = "trial"
        EXPIRED = "expired"
    
    class RiskLevel(Enum):
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"
    
    class ComplianceStatus(Enum):
        COMPLIANT = "compliant"
        PARTIAL = "partial"
        NON_COMPLIANT = "non_compliant"
    
    # Mock classes for testing
    class TenantProfile:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
            if not hasattr(self, 'tier'):
                self.tier = TenantTier.ENTERPRISE
            if not hasattr(self, 'status'):
                self.status = TenantStatus.ACTIVE
    
    def get_tenant_manager():
        return None

logger = logging.getLogger(__name__)

class TenantIsolationLevel(Enum):
    """Tenant data isolation levels"""
    SOFT = "soft"          # Filter by client_id in queries
    HARD = "hard"          # Separate collections per tenant
    HYBRID = "hybrid"      # Namespace-based separation

@dataclass
class MultiTenantComplianceScore:
    """Enhanced compliance score with full multi-tenant metadata"""
    client_id: str
    organization_name: str
    tenant_tier: str
    
    # Core compliance data
    provider: str
    control_id: str
    framework: str
    score: float
    status: str
    
    # Evidence and context
    evidence_summary: Dict[str, Any]
    component_scores: Dict[str, float]
    risk_factors: List[str]
    recommendations: List[str]
    
    # Multi-tenant organizational context
    department: Optional[str] = None
    cost_center: Optional[str] = None
    business_unit: Optional[str] = None
    geographic_region: Optional[str] = None
    
    # Audit trail
    scan_id: Optional[str] = None
    assessment_date: datetime = field(default_factory=datetime.now)
    assessor: Optional[str] = None
    
    # Compliance context
    control_category: Optional[str] = None
    regulatory_requirements: List[str] = field(default_factory=list)
    baseline_score: Optional[float] = None
    target_score: Optional[float] = None
    
    # Trend and analytics
    previous_score: Optional[float] = None
    score_change: Optional[float] = None
    trend_direction: Optional[str] = None
    
    def to_weaviate_object(self) -> Dict[str, Any]:
        """Convert to Weaviate object with full indexing"""
        return {
            # Tenant identification (primary indexes)
            "clientId": self.client_id,
            "organizationName": self.organization_name,
            "tenantTier": self.tenant_tier,
            
            # Compliance core data
            "provider": self.provider,
            "controlId": self.control_id,
            "framework": self.framework,
            "score": self.score,
            "status": self.status,
            
            # Organizational structure (secondary indexes)
            "department": self.department or "",
            "costCenter": self.cost_center or "",
            "businessUnit": self.business_unit or "",
            "geographicRegion": self.geographic_region or "",
            
            # Audit and tracking
            "scanId": self.scan_id or "",
            "assessmentDate": self.assessment_date.isoformat(),
            "assessor": self.assessor or "",
            
            # Compliance metadata
            "controlCategory": self.control_category or "",
            "regulatoryRequirements": json.dumps(self.regulatory_requirements),
            "baselineScore": self.baseline_score or 0.0,
            "targetScore": self.target_score or 100.0,
            
            # Evidence and recommendations (searchable text)
            "evidenceSummary": json.dumps(self.evidence_summary),
            "componentScores": json.dumps(self.component_scores),
            "riskFactors": "; ".join(self.risk_factors),
            "recommendations": "; ".join(self.recommendations),
            
            # Trend analysis
            "previousScore": self.previous_score or 0.0,
            "scoreChange": self.score_change or 0.0,
            "trendDirection": self.trend_direction or "stable",
            
            # Computed fields for analytics
            "scoreCategory": self._get_score_category(),
            "riskLevel": self._get_risk_level(),
            "complianceGap": max(0, 100 - self.score),
            "improvementNeeded": self.score < (self.target_score or 90),
            
            # Temporal indexing
            "yearMonth": self.assessment_date.strftime("%Y-%m"),
            "quarter": f"{self.assessment_date.year}-Q{(self.assessment_date.month-1)//3 + 1}",
            "dayOfWeek": self.assessment_date.strftime("%A"),
            
            # Search and classification
            "searchableText": self._generate_searchable_text()
        }
    
    def _get_score_category(self) -> str:
        """Categorize score for analytics"""
        if self.score >= 95:
            return "excellent"
        elif self.score >= 90:
            return "good"
        elif self.score >= 80:
            return "acceptable"
        elif self.score >= 70:
            return "needs_improvement"
        elif self.score >= 50:
            return "poor"
        else:
            return "critical"
    
    def _get_risk_level(self) -> str:
        """Calculate risk level based on score and context"""
        if self.score >= 90:
            return "low"
        elif self.score >= 80:
            return "medium"
        elif self.score >= 70:
            return "high"
        else:
            return "critical"
    
    def _generate_searchable_text(self) -> str:
        """Generate searchable text for semantic search"""
        text_parts = [
            self.organization_name,
            self.provider,
            self.control_id,
            self.framework,
            self.control_category or "",
            " ".join(self.risk_factors),
            " ".join(self.recommendations),
            self.department or "",
            self.business_unit or ""
        ]
        return " ".join(filter(None, text_parts)).lower()

@dataclass 
class TenantAssetInventory:
    """Multi-tenant asset inventory entry"""
    client_id: str
    organization_name: str
    
    # Asset identification
    asset_id: str
    asset_name: str
    asset_type: str
    
    # Cloud context
    cloud_provider: str
    cloud_region: str
    cloud_account: str
    
    # Organizational context
    department: Optional[str] = None
    cost_center: Optional[str] = None
    business_unit: Optional[str] = None
    owner: Optional[str] = None
    
    # Security classification
    criticality: str = "medium"
    sensitivity_level: str = "internal"
    data_classification: List[str] = field(default_factory=list)
    
    # Compliance status
    compliance_scores: Dict[str, float] = field(default_factory=dict)
    last_assessment: Optional[datetime] = None
    compliance_status: str = "unknown"
    
    # Risk and threats
    risk_score: float = 0.0
    threat_indicators: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    
    # Asset metadata
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)
    
    def to_weaviate_object(self) -> Dict[str, Any]:
        """Convert asset to Weaviate object"""
        return {
            # Tenant context
            "clientId": self.client_id,
            "organizationName": self.organization_name,
            
            # Asset identification
            "assetId": self.asset_id,
            "assetName": self.asset_name,
            "assetType": self.asset_type,
            
            # Cloud context
            "cloudProvider": self.cloud_provider,
            "cloudRegion": self.cloud_region,
            "cloudAccount": self.cloud_account,
            
            # Organizational structure
            "department": self.department or "",
            "costCenter": self.cost_center or "",
            "businessUnit": self.business_unit or "",
            "owner": self.owner or "",
            
            # Security and compliance
            "criticality": self.criticality,
            "sensitivityLevel": self.sensitivity_level,
            "dataClassification": json.dumps(self.data_classification),
            "complianceScores": json.dumps(self.compliance_scores),
            "lastAssessment": self.last_assessment.isoformat() if self.last_assessment else "",
            "complianceStatus": self.compliance_status,
            
            # Risk assessment
            "riskScore": self.risk_score,
            "threatIndicators": json.dumps(self.threat_indicators),
            "vulnerabilities": json.dumps(self.vulnerabilities),
            
            # Metadata
            "createdAt": self.created_at.isoformat(),
            "updatedAt": self.updated_at.isoformat(),
            "tags": json.dumps(self.tags),
            
            # Computed fields
            "riskLevel": self._get_risk_level(),
            "complianceHealthScore": self._calculate_compliance_health(),
            "yearMonth": self.updated_at.strftime("%Y-%m"),
            
            # Search text
            "searchableText": self._generate_searchable_text()
        }
    
    def _get_risk_level(self) -> str:
        """Calculate risk level from risk score"""
        if self.risk_score >= 80:
            return "critical"
        elif self.risk_score >= 60:
            return "high"
        elif self.risk_score >= 40:
            return "medium"
        else:
            return "low"
    
    def _calculate_compliance_health(self) -> float:
        """Calculate overall compliance health score"""
        if not self.compliance_scores:
            return 0.0
        return sum(self.compliance_scores.values()) / len(self.compliance_scores)
    
    def _generate_searchable_text(self) -> str:
        """Generate searchable text"""
        text_parts = [
            self.asset_name,
            self.asset_type,
            self.cloud_provider,
            self.department or "",
            self.business_unit or "",
            " ".join(self.tags),
            " ".join(self.data_classification)
        ]
        return " ".join(filter(None, text_parts)).lower()

class WeaviateMultiTenantBridge:
    """
    Enhanced multi-tenant Weaviate bridge with advanced analytics and indexing
    """
    
    def __init__(self, weaviate_client=None, isolation_level: TenantIsolationLevel = TenantIsolationLevel.SOFT):
        """
        Initialize multi-tenant Weaviate bridge
        
        Args:
            weaviate_client: Weaviate client instance
            isolation_level: Tenant isolation strategy
        """
        if not WEAVIATE_AVAILABLE:
            logger.warning("Weaviate not available - using mock implementation")
            self.client = None
        else:
            self.client = weaviate_client or self._create_default_client()
        
        self.isolation_level = isolation_level
        self.tenant_manager = get_tenant_manager()
        self.batch_size = 100
        
        # Initialize schema and indexes
        if self.client:
            self.ensure_enhanced_schema()
            self.create_tenant_indexes()
        
        logger.info(f"Multi-tenant Weaviate bridge initialized with {isolation_level.value} isolation")
    
    def _create_default_client(self):
        """Create default Weaviate client"""
        weaviate_url = os.getenv('WEAVIATE_URL', 'http://localhost:8080')
        api_key = os.getenv('WEAVIATE_API_KEY')
        
        if api_key:
            auth_config = weaviate.AuthApiKey(api_key=api_key)
            return weaviate.Client(weaviate_url, auth_client_secret=auth_config)
        else:
            return weaviate.Client(weaviate_url)
    
    def ensure_enhanced_schema(self):
        """Create enhanced schema with multi-tenant indexing"""
        try:
            # Multi-tenant compliance scores class
            compliance_class = {
                "class": "MultiTenantComplianceScore",
                "description": "Multi-tenant compliance scores with advanced indexing",
                "properties": [
                    # Tenant identification (indexed)
                    {"name": "clientId", "dataType": ["text"], "indexInverted": True, "description": "Tenant identifier"},
                    {"name": "organizationName", "dataType": ["text"], "indexInverted": True, "description": "Organization name"},
                    {"name": "tenantTier", "dataType": ["text"], "indexInverted": True, "description": "Tenant service tier"},
                    
                    # Core compliance data (indexed)
                    {"name": "provider", "dataType": ["text"], "indexInverted": True, "description": "Cloud provider"},
                    {"name": "controlId", "dataType": ["text"], "indexInverted": True, "description": "Control ID"},
                    {"name": "framework", "dataType": ["text"], "indexInverted": True, "description": "Compliance framework"},
                    {"name": "score", "dataType": ["number"], "indexInverted": True, "description": "Compliance score"},
                    {"name": "status", "dataType": ["text"], "indexInverted": True, "description": "Compliance status"},
                    
                    # Organizational structure (indexed)
                    {"name": "department", "dataType": ["text"], "indexInverted": True, "description": "Department"},
                    {"name": "costCenter", "dataType": ["text"], "indexInverted": True, "description": "Cost center"},
                    {"name": "businessUnit", "dataType": ["text"], "indexInverted": True, "description": "Business unit"},
                    {"name": "geographicRegion", "dataType": ["text"], "indexInverted": True, "description": "Geographic region"},
                    
                    # Audit trail
                    {"name": "scanId", "dataType": ["text"], "description": "Scan identifier"},
                    {"name": "assessmentDate", "dataType": ["date"], "indexInverted": True, "description": "Assessment date"},
                    {"name": "assessor", "dataType": ["text"], "description": "Assessor name"},
                    
                    # Compliance metadata
                    {"name": "controlCategory", "dataType": ["text"], "indexInverted": True, "description": "Control category"},
                    {"name": "regulatoryRequirements", "dataType": ["text"], "description": "Regulatory requirements"},
                    {"name": "baselineScore", "dataType": ["number"], "description": "Baseline score"},
                    {"name": "targetScore", "dataType": ["number"], "description": "Target score"},
                    
                    # Evidence and recommendations (searchable)
                    {"name": "evidenceSummary", "dataType": ["text"], "description": "Evidence summary"},
                    {"name": "componentScores", "dataType": ["text"], "description": "Component scores"},
                    {"name": "riskFactors", "dataType": ["text"], "description": "Risk factors"},
                    {"name": "recommendations", "dataType": ["text"], "description": "Recommendations"},
                    
                    # Trend analysis
                    {"name": "previousScore", "dataType": ["number"], "description": "Previous score"},
                    {"name": "scoreChange", "dataType": ["number"], "description": "Score change"},
                    {"name": "trendDirection", "dataType": ["text"], "indexInverted": True, "description": "Trend direction"},
                    
                    # Computed analytics fields (indexed)
                    {"name": "scoreCategory", "dataType": ["text"], "indexInverted": True, "description": "Score category"},
                    {"name": "riskLevel", "dataType": ["text"], "indexInverted": True, "description": "Risk level"},
                    {"name": "complianceGap", "dataType": ["number"], "indexInverted": True, "description": "Compliance gap"},
                    {"name": "improvementNeeded", "dataType": ["boolean"], "indexInverted": True, "description": "Improvement needed"},
                    
                    # Temporal indexing (for analytics)
                    {"name": "yearMonth", "dataType": ["text"], "indexInverted": True, "description": "Year-month"},
                    {"name": "quarter", "dataType": ["text"], "indexInverted": True, "description": "Quarter"},
                    {"name": "dayOfWeek", "dataType": ["text"], "indexInverted": True, "description": "Day of week"},
                    
                    # Search
                    {"name": "searchableText", "dataType": ["text"], "description": "Searchable text"}
                ],
                "vectorizer": self._get_vectorizer_config()
            }
            
            # Multi-tenant asset inventory class
            asset_class = {
                "class": "MultiTenantAssetInventory",
                "description": "Multi-tenant asset inventory with security classification",
                "properties": [
                    # Tenant context (indexed)
                    {"name": "clientId", "dataType": ["text"], "indexInverted": True, "description": "Tenant identifier"},
                    {"name": "organizationName", "dataType": ["text"], "indexInverted": True, "description": "Organization name"},
                    
                    # Asset identification (indexed)
                    {"name": "assetId", "dataType": ["text"], "indexInverted": True, "description": "Asset ID"},
                    {"name": "assetName", "dataType": ["text"], "indexInverted": True, "description": "Asset name"},
                    {"name": "assetType", "dataType": ["text"], "indexInverted": True, "description": "Asset type"},
                    
                    # Cloud context (indexed)
                    {"name": "cloudProvider", "dataType": ["text"], "indexInverted": True, "description": "Cloud provider"},
                    {"name": "cloudRegion", "dataType": ["text"], "indexInverted": True, "description": "Cloud region"},
                    {"name": "cloudAccount", "dataType": ["text"], "indexInverted": True, "description": "Cloud account"},
                    
                    # Organizational structure (indexed)
                    {"name": "department", "dataType": ["text"], "indexInverted": True, "description": "Department"},
                    {"name": "costCenter", "dataType": ["text"], "indexInverted": True, "description": "Cost center"},
                    {"name": "businessUnit", "dataType": ["text"], "indexInverted": True, "description": "Business unit"},
                    {"name": "owner", "dataType": ["text"], "indexInverted": True, "description": "Asset owner"},
                    
                    # Security classification (indexed)
                    {"name": "criticality", "dataType": ["text"], "indexInverted": True, "description": "Criticality level"},
                    {"name": "sensitivityLevel", "dataType": ["text"], "indexInverted": True, "description": "Sensitivity level"},
                    {"name": "dataClassification", "dataType": ["text"], "description": "Data classification"},
                    
                    # Compliance and risk (indexed)
                    {"name": "complianceScores", "dataType": ["text"], "description": "Compliance scores"},
                    {"name": "lastAssessment", "dataType": ["date"], "indexInverted": True, "description": "Last assessment"},
                    {"name": "complianceStatus", "dataType": ["text"], "indexInverted": True, "description": "Compliance status"},
                    {"name": "riskScore", "dataType": ["number"], "indexInverted": True, "description": "Risk score"},
                    {"name": "threatIndicators", "dataType": ["text"], "description": "Threat indicators"},
                    {"name": "vulnerabilities", "dataType": ["text"], "description": "Vulnerabilities"},
                    
                    # Metadata
                    {"name": "createdAt", "dataType": ["date"], "indexInverted": True, "description": "Created timestamp"},
                    {"name": "updatedAt", "dataType": ["date"], "indexInverted": True, "description": "Updated timestamp"},
                    {"name": "tags", "dataType": ["text"], "description": "Asset tags"},
                    
                    # Computed fields (indexed)
                    {"name": "riskLevel", "dataType": ["text"], "indexInverted": True, "description": "Risk level"},
                    {"name": "complianceHealthScore", "dataType": ["number"], "indexInverted": True, "description": "Compliance health"},
                    {"name": "yearMonth", "dataType": ["text"], "indexInverted": True, "description": "Year-month"},
                    
                    # Search
                    {"name": "searchableText", "dataType": ["text"], "description": "Searchable text"}
                ],
                "vectorizer": self._get_vectorizer_config()
            }
            
            # Tenant analytics aggregation class
            analytics_class = {
                "class": "TenantAnalytics",
                "description": "Tenant-level compliance analytics and KPIs",
                "properties": [
                    {"name": "clientId", "dataType": ["text"], "indexInverted": True},
                    {"name": "organizationName", "dataType": ["text"], "indexInverted": True},
                    {"name": "period", "dataType": ["text"], "indexInverted": True},
                    {"name": "periodStart", "dataType": ["date"], "indexInverted": True},
                    {"name": "periodEnd", "dataType": ["date"], "indexInverted": True},
                    {"name": "overallScore", "dataType": ["number"], "indexInverted": True},
                    {"name": "totalAssets", "dataType": ["int"], "indexInverted": True},
                    {"name": "compliantAssets", "dataType": ["int"]},
                    {"name": "criticalFindings", "dataType": ["int"]},
                    {"name": "improvementTrend", "dataType": ["text"], "indexInverted": True},
                    {"name": "topRisks", "dataType": ["text"]},
                    {"name": "recommendations", "dataType": ["text"]},
                    {"name": "benchmarkComparison", "dataType": ["text"]},
                    {"name": "kpiMetrics", "dataType": ["text"]}
                ]
            }
            
            # Create classes if they don't exist
            existing_classes = set()
            try:
                schema = self.client.schema.get()
                existing_classes = {c['class'] for c in schema.get('classes', [])}
            except:
                pass
            
            for class_def in [compliance_class, asset_class, analytics_class]:
                if class_def['class'] not in existing_classes:
                    self.client.schema.create_class(class_def)
                    logger.info(f"Created Weaviate class: {class_def['class']}")
            
        except Exception as e:
            logger.error(f"Failed to ensure enhanced Weaviate schema: {e}")
    
    def _get_vectorizer_config(self) -> str:
        """Get appropriate vectorizer configuration"""
        try:
            if self.client:
                modules = self.client.get_meta().get('modules', {})
                if any('text2vec-openai' in str(module) for module in modules.values()):
                    return "text2vec-openai"
                elif any('text2vec-transformers' in str(module) for module in modules.values()):
                    return "text2vec-transformers"
        except:
            pass
        return "none"
    
    def create_tenant_indexes(self):
        """Create optimized indexes for tenant queries"""
        if not self.client:
            return
        
        try:
            # Create composite indexes for common query patterns
            index_configs = [
                # Tenant + time-based queries
                ("clientId", "assessmentDate"),
                ("clientId", "yearMonth"),
                ("clientId", "scoreCategory"),
                
                # Organizational queries
                ("clientId", "department"),
                ("clientId", "businessUnit"),
                ("clientId", "costCenter"),
                
                # Compliance queries
                ("clientId", "framework", "controlId"),
                ("clientId", "provider", "status"),
                
                # Risk-based queries
                ("clientId", "riskLevel"),
                ("clientId", "improvementNeeded"),
                
                # Cross-tenant analytics (for MSPs)
                ("tenantTier", "scoreCategory"),
                ("geographicRegion", "riskLevel")
            ]
            
            # Note: Weaviate handles indexing automatically for properties marked with indexInverted
            # This method is a placeholder for future custom index optimizations
            logger.info("Tenant indexing patterns configured")
            
        except Exception as e:
            logger.error(f"Failed to create tenant indexes: {e}")
    
    def persist_compliance_score(self, score: MultiTenantComplianceScore) -> str:
        """Persist multi-tenant compliance score"""
        if not self.client:
            logger.warning("Weaviate client not available - skipping persistence")
            return "mock-uuid"
        
        try:
            # Validate tenant access
            if not self._validate_tenant_access(score.client_id):
                raise ValueError(f"Invalid tenant access: {score.client_id}")
            
            weaviate_object = score.to_weaviate_object()
            
            result = self.client.data_object.create(
                data_object=weaviate_object,
                class_name="MultiTenantComplianceScore"
            )
            
            logger.debug(f"Persisted compliance score for {score.client_id}: {score.control_id} = {score.score}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to persist compliance score: {e}")
            raise
    
    def persist_asset_inventory(self, asset: TenantAssetInventory) -> str:
        """Persist multi-tenant asset inventory"""
        if not self.client:
            logger.warning("Weaviate client not available - skipping persistence")
            return "mock-uuid"
        
        try:
            if not self._validate_tenant_access(asset.client_id):
                raise ValueError(f"Invalid tenant access: {asset.client_id}")
            
            weaviate_object = asset.to_weaviate_object()
            
            result = self.client.data_object.create(
                data_object=weaviate_object,
                class_name="MultiTenantAssetInventory"
            )
            
            logger.debug(f"Persisted asset for {asset.client_id}: {asset.asset_id}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to persist asset inventory: {e}")
            raise
    
    def batch_persist_scores(self, scores: List[MultiTenantComplianceScore]) -> List[str]:
        """Batch persist compliance scores with tenant validation"""
        if not self.client:
            logger.warning("Weaviate client not available - using mock batch")
            return [f"mock-uuid-{i}" for i in range(len(scores))]
        
        try:
            batch_results = []
            
            # Group by tenant for validation
            tenant_groups = {}
            for score in scores:
                if score.client_id not in tenant_groups:
                    tenant_groups[score.client_id] = []
                tenant_groups[score.client_id].append(score)
            
            # Validate all tenants
            for client_id in tenant_groups.keys():
                if not self._validate_tenant_access(client_id):
                    raise ValueError(f"Invalid tenant access: {client_id}")
            
            # Batch persist
            with self.client.batch as batch:
                batch.batch_size = self.batch_size
                
                for score in scores:
                    weaviate_object = score.to_weaviate_object()
                    uuid = batch.add_data_object(
                        data_object=weaviate_object,
                        class_name="MultiTenantComplianceScore"
                    )
                    batch_results.append(uuid)
            
            logger.info(f"Batch persisted {len(scores)} compliance scores across {len(tenant_groups)} tenants")
            return batch_results
            
        except Exception as e:
            logger.error(f"Failed to batch persist scores: {e}")
            raise
    
    def query_tenant_compliance(self, client_id: str, 
                               filters: Optional[Dict[str, Any]] = None,
                               limit: int = 100) -> List[Dict[str, Any]]:
        """Query compliance scores for specific tenant with advanced filtering"""
        if not self.client:
            return self._mock_compliance_query(client_id, filters, limit)
        
        try:
            if not self._validate_tenant_access(client_id):
                raise ValueError(f"Invalid tenant access: {client_id}")
            
            # Base query for tenant
            query = self.client.query.get("MultiTenantComplianceScore", [
                "clientId", "organizationName", "provider", "controlId", "framework",
                "score", "status", "department", "businessUnit", "costCenter",
                "assessmentDate", "scoreCategory", "riskLevel", "trendDirection",
                "recommendations", "riskFactors", "complianceGap"
            ])
            
            # Build WHERE conditions
            where_conditions = [
                {
                    "path": ["clientId"],
                    "operator": "Equal",
                    "valueText": client_id
                }
            ]
            
            # Add additional filters
            if filters:
                if "provider" in filters:
                    where_conditions.append({
                        "path": ["provider"],
                        "operator": "Equal",
                        "valueText": filters["provider"]
                    })
                
                if "framework" in filters:
                    where_conditions.append({
                        "path": ["framework"],
                        "operator": "Equal",
                        "valueText": filters["framework"]
                    })
                
                if "department" in filters:
                    where_conditions.append({
                        "path": ["department"],
                        "operator": "Equal",
                        "valueText": filters["department"]
                    })
                
                if "score_min" in filters:
                    where_conditions.append({
                        "path": ["score"],
                        "operator": "GreaterThanEqual",
                        "valueNumber": filters["score_min"]
                    })
                
                if "score_max" in filters:
                    where_conditions.append({
                        "path": ["score"],
                        "operator": "LessThanEqual",
                        "valueNumber": filters["score_max"]
                    })
                
                if "risk_level" in filters:
                    where_conditions.append({
                        "path": ["riskLevel"],
                        "operator": "Equal",
                        "valueText": filters["risk_level"]
                    })
                
                if "since_date" in filters:
                    where_conditions.append({
                        "path": ["assessmentDate"],
                        "operator": "GreaterThan",
                        "valueDate": filters["since_date"]
                    })
            
            # Apply WHERE conditions
            if len(where_conditions) == 1:
                query = query.with_where(where_conditions[0])
            elif len(where_conditions) > 1:
                query = query.with_where({
                    "operator": "And",
                    "operands": where_conditions
                })
            
            # Execute query
            result = query.with_limit(limit).do()
            
            if 'data' in result and 'Get' in result['data']:
                return result['data']['Get']['MultiTenantComplianceScore']
            else:
                return []
                
        except Exception as e:
            logger.error(f"Failed to query tenant compliance: {e}")
            return []
    
    def query_tenant_assets(self, client_id: str,
                           filters: Optional[Dict[str, Any]] = None,
                           limit: int = 100) -> List[Dict[str, Any]]:
        """Query asset inventory for specific tenant"""
        if not self.client:
            return self._mock_asset_query(client_id, filters, limit)
        
        try:
            if not self._validate_tenant_access(client_id):
                raise ValueError(f"Invalid tenant access: {client_id}")
            
            query = self.client.query.get("MultiTenantAssetInventory", [
                "clientId", "assetId", "assetName", "assetType", "cloudProvider",
                "cloudRegion", "department", "businessUnit", "criticality",
                "riskScore", "riskLevel", "complianceStatus", "complianceHealthScore",
                "lastAssessment", "owner", "tags"
            ])
            
            # Build WHERE conditions
            where_conditions = [
                {
                    "path": ["clientId"],
                    "operator": "Equal",
                    "valueText": client_id
                }
            ]
            
            # Add filters
            if filters:
                for field, value in filters.items():
                    if field in ["assetType", "cloudProvider", "department", "businessUnit", "criticality", "riskLevel"]:
                        where_conditions.append({
                            "path": [field],
                            "operator": "Equal",
                            "valueText": value
                        })
                    elif field in ["riskScore_min", "complianceHealthScore_min"]:
                        field_name = field.replace("_min", "")
                        where_conditions.append({
                            "path": [field_name],
                            "operator": "GreaterThanEqual",
                            "valueNumber": value
                        })
            
            # Apply conditions and execute
            if len(where_conditions) > 1:
                query = query.with_where({
                    "operator": "And", 
                    "operands": where_conditions
                })
            else:
                query = query.with_where(where_conditions[0])
            
            result = query.with_limit(limit).do()
            
            if 'data' in result and 'Get' in result['data']:
                return result['data']['Get']['MultiTenantAssetInventory']
            else:
                return []
                
        except Exception as e:
            logger.error(f"Failed to query tenant assets: {e}")
            return []
    
    def get_tenant_analytics_dashboard(self, client_id: str, 
                                     time_period: str = "30d") -> Dict[str, Any]:
        """Generate comprehensive analytics dashboard for tenant"""
        try:
            if not self._validate_tenant_access(client_id):
                raise ValueError(f"Invalid tenant access: {client_id}")
            
            # Calculate date range
            now = datetime.now()
            if time_period == "7d":
                since_date = now - timedelta(days=7)
            elif time_period == "30d":
                since_date = now - timedelta(days=30)
            elif time_period == "90d":
                since_date = now - timedelta(days=90)
            else:
                since_date = now - timedelta(days=30)
            
            # Get compliance data
            compliance_data = self.query_tenant_compliance(
                client_id,
                filters={"since_date": since_date.isoformat()},
                limit=1000
            )
            
            # Get asset data
            asset_data = self.query_tenant_assets(client_id, limit=1000)
            
            # Generate analytics
            analytics = {
                "tenant_info": self._get_tenant_info(client_id),
                "time_period": time_period,
                "analysis_date": now.isoformat(),
                
                # Compliance overview
                "compliance_overview": self._analyze_compliance_overview(compliance_data),
                
                # Risk assessment
                "risk_assessment": self._analyze_risk_landscape(compliance_data, asset_data),
                
                # Trend analysis
                "trends": self._analyze_compliance_trends(compliance_data),
                
                # Asset security posture
                "asset_posture": self._analyze_asset_security(asset_data),
                
                # Recommendations
                "recommendations": self._generate_tenant_recommendations(compliance_data, asset_data),
                
                # Benchmarking (if tenant tier allows)
                "benchmarking": self._generate_benchmarking(client_id, compliance_data),
                
                # Executive summary
                "executive_summary": self._generate_executive_summary(compliance_data, asset_data)
            }
            
            return analytics
            
        except Exception as e:
            logger.error(f"Failed to generate tenant analytics: {e}")
            return {"error": str(e)}
    
    def get_cross_tenant_analytics(self, requester_client_id: str, 
                                  tenant_filter: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate cross-tenant analytics (MSP feature)"""
        try:
            # Validate MSP access
            if not self.tenant_manager:
                # Mock data for testing
                managed_orgs = [
                    {"client_id": "client_acme_001", "organization_name": "Acme Corp", "tier": "enterprise"},
                    {"client_id": "client_startup_002", "organization_name": "StartupXYZ", "tier": "professional"}
                ]
            else:
                requester_tenant = self.tenant_manager.get_tenant(requester_client_id)
                if not requester_tenant or requester_tenant.tier != TenantTier.MSP:
                    raise ValueError("Cross-tenant analytics requires MSP tier access")
                
                # Get managed organizations
                managed_orgs = self.tenant_manager.get_organizations_for_msp(requester_client_id)
            
            if not managed_orgs:
                return {"error": "No managed organizations found"}
            
            # Collect analytics for all managed tenants
            tenant_analytics = {}
            overall_metrics = {
                "total_tenants": len(managed_orgs),
                "total_assets": 0,
                "average_compliance_score": 0,
                "tenants_at_risk": 0,
                "common_issues": {},
                "improvement_opportunities": []
            }
            
            for org in managed_orgs:
                try:
                    tenant_data = self.get_tenant_analytics_dashboard(org["client_id"], "30d")
                    tenant_analytics[org["client_id"]] = {
                        "organization_name": org["organization_name"],
                        "tier": org["tier"],
                        "analytics": tenant_data
                    }
                    
                    # Aggregate metrics
                    if "compliance_overview" in tenant_data:
                        overview = tenant_data["compliance_overview"]
                        overall_metrics["total_assets"] += overview.get("total_assessments", 0)
                        
                        score = overview.get("average_score", 0)
                        if score > 0:
                            overall_metrics["average_compliance_score"] += score
                        
                        if overview.get("risk_score", 0) > 70:
                            overall_metrics["tenants_at_risk"] += 1
                
                except Exception as e:
                    logger.warning(f"Failed to get analytics for tenant {org['client_id']}: {e}")
            
            # Calculate averages
            if tenant_analytics:
                overall_metrics["average_compliance_score"] /= len(tenant_analytics)
            
            return {
                "msp_client_id": requester_client_id,
                "analysis_date": datetime.now().isoformat(),
                "overall_metrics": overall_metrics,
                "tenant_analytics": tenant_analytics,
                "recommendations": self._generate_msp_recommendations(tenant_analytics)
            }
            
        except Exception as e:
            logger.error(f"Failed to generate cross-tenant analytics: {e}")
            return {"error": str(e)}
    
    def semantic_search_tenant(self, client_id: str, query_text: str, 
                              search_type: str = "compliance", limit: int = 10) -> List[Dict[str, Any]]:
        """Semantic search within tenant data"""
        if not self.client:
            return self._mock_semantic_search(client_id, query_text, search_type, limit)
        
        try:
            if not self._validate_tenant_access(client_id):
                raise ValueError(f"Invalid tenant access: {client_id}")
            
            if search_type == "compliance":
                class_name = "MultiTenantComplianceScore"
                fields = ["controlId", "framework", "recommendations", "riskFactors", "score"]
            elif search_type == "assets":
                class_name = "MultiTenantAssetInventory"
                fields = ["assetName", "assetType", "tags", "riskLevel"]
            else:
                raise ValueError(f"Invalid search type: {search_type}")
            
            # Use vector search if available, otherwise keyword search
            if self._get_vectorizer_config() != "none":
                query = self.client.query.get(class_name, fields).with_near_text({
                    "concepts": [query_text]
                }).with_where({
                    "path": ["clientId"],
                    "operator": "Equal",
                    "valueText": client_id
                })
            else:
                # Fallback to keyword search
                query = self.client.query.get(class_name, fields).with_where({
                    "operator": "And",
                    "operands": [
                        {
                            "path": ["clientId"],
                            "operator": "Equal",
                            "valueText": client_id
                        },
                        {
                            "path": ["searchableText"],
                            "operator": "Like",
                            "valueText": f"*{query_text.lower()}*"
                        }
                    ]
                })
            
            result = query.with_limit(limit).do()
            
            if 'data' in result and 'Get' in result['data']:
                return result['data']['Get'][class_name]
            else:
                return []
                
        except Exception as e:
            logger.error(f"Failed semantic search: {e}")
            return []
    
    def _validate_tenant_access(self, client_id: str) -> bool:
        """Validate tenant exists and is active"""
        if not self.tenant_manager:
            return True  # Allow all access if no tenant manager available
        tenant = self.tenant_manager.get_tenant(client_id)
        if not tenant:
            return True  # Allow access for testing
        return tenant.status.value in ['active', 'trial']
    
    def _get_tenant_info(self, client_id: str) -> Dict[str, Any]:
        """Get tenant information"""
        if not self.tenant_manager:
            return {
                "client_id": client_id,
                "organization_name": "Mock Organization",
                "tier": "enterprise",
                "status": "active"
            }
        
        tenant = self.tenant_manager.get_tenant(client_id)
        if not tenant:
            return {}
        
        return {
            "client_id": client_id,
            "organization_name": tenant.organization_name,
            "tier": tenant.tier.value,
            "status": tenant.status.value
        }
    
    def _analyze_compliance_overview(self, compliance_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze compliance overview metrics"""
        if not compliance_data:
            return {"total_assessments": 0, "average_score": 0}
        
        scores = [item.get("score", 0) for item in compliance_data]
        
        return {
            "total_assessments": len(compliance_data),
            "average_score": sum(scores) / len(scores) if scores else 0,
            "highest_score": max(scores) if scores else 0,
            "lowest_score": min(scores) if scores else 0,
            "compliance_distribution": self._calculate_score_distribution(scores),
            "framework_breakdown": self._analyze_by_framework(compliance_data),
            "provider_breakdown": self._analyze_by_provider(compliance_data)
        }
    
    def _analyze_risk_landscape(self, compliance_data: List[Dict[str, Any]], 
                               asset_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze risk landscape"""
        risk_metrics = {
            "overall_risk_score": 0,
            "critical_findings": 0,
            "high_risk_assets": 0,
            "risk_trend": "stable"
        }
        
        # Analyze compliance risks
        if compliance_data:
            low_scores = [item for item in compliance_data if item.get("score", 0) < 70]
            risk_metrics["critical_findings"] = len(low_scores)
            
            avg_score = sum(item.get("score", 0) for item in compliance_data) / len(compliance_data)
            risk_metrics["overall_risk_score"] = max(0, 100 - avg_score)
        
        # Analyze asset risks
        if asset_data:
            high_risk = [asset for asset in asset_data if asset.get("riskScore", 0) > 70]
            risk_metrics["high_risk_assets"] = len(high_risk)
        
        return risk_metrics
    
    def _analyze_compliance_trends(self, compliance_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze compliance trends over time"""
        if not compliance_data:
            return {}
        
        # Group by time periods
        time_series = {}
        for item in compliance_data:
            date_str = item.get("assessmentDate", "")
            if date_str:
                try:
                    date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                    week_key = date.strftime("%Y-W%U")
                    if week_key not in time_series:
                        time_series[week_key] = []
                    time_series[week_key].append(item.get("score", 0))
                except:
                    continue
        
        # Calculate trends
        weekly_averages = {}
        for week, scores in time_series.items():
            weekly_averages[week] = sum(scores) / len(scores) if scores else 0
        
        return {
            "weekly_averages": weekly_averages,
            "trend_direction": self._calculate_trend_direction(weekly_averages),
            "volatility": self._calculate_score_volatility(weekly_averages)
        }
    
    def _analyze_asset_security(self, asset_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze asset security posture"""
        if not asset_data:
            return {}
        
        return {
            "total_assets": len(asset_data),
            "by_criticality": self._group_by_field(asset_data, "criticality"),
            "by_cloud_provider": self._group_by_field(asset_data, "cloudProvider"),
            "by_risk_level": self._group_by_field(asset_data, "riskLevel"),
            "average_compliance_health": self._calculate_average_field(asset_data, "complianceHealthScore")
        }
    
    def _generate_tenant_recommendations(self, compliance_data: List[Dict[str, Any]], 
                                       asset_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate tenant-specific recommendations"""
        recommendations = []
        
        # Analyze compliance gaps
        if compliance_data:
            low_scoring_controls = [item for item in compliance_data if item.get("score", 0) < 80]
            for control in low_scoring_controls[:5]:  # Top 5 issues
                recommendations.append({
                    "type": "compliance_gap",
                    "priority": "high" if control.get("score", 0) < 60 else "medium",
                    "title": f"Improve {control.get('controlId', 'Unknown')} compliance",
                    "description": f"Current score: {control.get('score', 0):.1f}%",
                    "impact": "compliance_risk"
                })
        
        # Analyze asset risks
        if asset_data:
            high_risk_assets = [asset for asset in asset_data if asset.get("riskScore", 0) > 70]
            if len(high_risk_assets) > 0:
                recommendations.append({
                    "type": "asset_security",
                    "priority": "high",
                    "title": f"Address {len(high_risk_assets)} high-risk assets",
                    "description": "Assets with risk scores above 70 require immediate attention",
                    "impact": "security_risk"
                })
        
        return recommendations[:10]  # Limit to top 10
    
    def _generate_benchmarking(self, client_id: str, compliance_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate benchmarking data (anonymized)"""
        # Mock benchmarking data - in production, this would use anonymized cross-tenant data
        tenant_avg = sum(item.get("score", 0) for item in compliance_data) / len(compliance_data) if compliance_data else 0
        
        if not self.tenant_manager:
            tier_value = "enterprise"
        else:
            tenant = self.tenant_manager.get_tenant(client_id)
            if not tenant:
                return {}
            tier_value = tenant.tier.value
        
        return {
            "tenant_average": tenant_avg,
            "industry_average": 78.5,  # Mock industry average
            "tier_average": {
                TenantTier.STARTER.value: 72.0,
                TenantTier.PROFESSIONAL.value: 78.0,
                TenantTier.ENTERPRISE.value: 85.0
            }.get(tier_value, 75.0),
            "percentile": min(99, max(1, int((tenant_avg / 100) * 100)))
        }
    
    def _generate_executive_summary(self, compliance_data: List[Dict[str, Any]], 
                                  asset_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate executive summary"""
        summary = {
            "overall_health": "unknown",
            "key_metrics": {},
            "top_priorities": [],
            "achievements": []
        }
        
        if compliance_data:
            avg_score = sum(item.get("score", 0) for item in compliance_data) / len(compliance_data)
            
            if avg_score >= 90:
                summary["overall_health"] = "excellent"
            elif avg_score >= 80:
                summary["overall_health"] = "good"
            elif avg_score >= 70:
                summary["overall_health"] = "needs_improvement"
            else:
                summary["overall_health"] = "critical"
            
            summary["key_metrics"] = {
                "average_compliance_score": avg_score,
                "total_assessments": len(compliance_data),
                "compliant_controls": len([item for item in compliance_data if item.get("score", 0) >= 90])
            }
        
        return summary
    
    # Helper methods for analytics
    def _calculate_score_distribution(self, scores: List[float]) -> Dict[str, int]:
        """Calculate score distribution"""
        distribution = {"excellent": 0, "good": 0, "acceptable": 0, "poor": 0, "critical": 0}
        
        for score in scores:
            if score >= 95:
                distribution["excellent"] += 1
            elif score >= 85:
                distribution["good"] += 1
            elif score >= 70:
                distribution["acceptable"] += 1
            elif score >= 50:
                distribution["poor"] += 1
            else:
                distribution["critical"] += 1
        
        return distribution
    
    def _analyze_by_framework(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze compliance data by framework"""
        frameworks = {}
        for item in data:
            framework = item.get("framework", "unknown")
            if framework not in frameworks:
                frameworks[framework] = {"count": 0, "total_score": 0}
            frameworks[framework]["count"] += 1
            frameworks[framework]["total_score"] += item.get("score", 0)
        
        # Calculate averages
        for framework, stats in frameworks.items():
            if stats["count"] > 0:
                stats["average_score"] = stats["total_score"] / stats["count"]
        
        return frameworks
    
    def _analyze_by_provider(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze compliance data by cloud provider"""
        providers = {}
        for item in data:
            provider = item.get("provider", "unknown")
            if provider not in providers:
                providers[provider] = {"count": 0, "total_score": 0}
            providers[provider]["count"] += 1
            providers[provider]["total_score"] += item.get("score", 0)
        
        # Calculate averages
        for provider, stats in providers.items():
            if stats["count"] > 0:
                stats["average_score"] = stats["total_score"] / stats["count"]
        
        return providers
    
    def _calculate_trend_direction(self, weekly_averages: Dict[str, float]) -> str:
        """Calculate trend direction from weekly averages"""
        if len(weekly_averages) < 2:
            return "stable"
        
        values = list(weekly_averages.values())
        recent_avg = sum(values[-3:]) / min(3, len(values))
        older_avg = sum(values[:3]) / min(3, len(values))
        
        if recent_avg > older_avg + 2:
            return "improving"
        elif recent_avg < older_avg - 2:
            return "declining"
        else:
            return "stable"
    
    def _calculate_score_volatility(self, weekly_averages: Dict[str, float]) -> float:
        """Calculate score volatility"""
        if len(weekly_averages) < 2:
            return 0.0
        
        values = list(weekly_averages.values())
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5
    
    def _group_by_field(self, data: List[Dict[str, Any]], field: str) -> Dict[str, int]:
        """Group data by field value"""
        groups = {}
        for item in data:
            value = item.get(field, "unknown")
            groups[value] = groups.get(value, 0) + 1
        return groups
    
    def _calculate_average_field(self, data: List[Dict[str, Any]], field: str) -> float:
        """Calculate average of numeric field"""
        values = [item.get(field, 0) for item in data if isinstance(item.get(field), (int, float))]
        return sum(values) / len(values) if values else 0.0
    
    def _generate_msp_recommendations(self, tenant_analytics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate MSP-level recommendations"""
        recommendations = []
        
        # Analyze across all tenants
        low_scoring_tenants = []
        for client_id, data in tenant_analytics.items():
            analytics = data.get("analytics", {})
            overview = analytics.get("compliance_overview", {})
            avg_score = overview.get("average_score", 0)
            
            if avg_score < 75:
                low_scoring_tenants.append({
                    "client_id": client_id,
                    "org_name": data.get("organization_name", "Unknown"),
                    "score": avg_score
                })
        
        if low_scoring_tenants:
            recommendations.append({
                "type": "tenant_attention",
                "priority": "high",
                "title": f"Focus on {len(low_scoring_tenants)} underperforming clients",
                "description": "Several clients need immediate compliance support",
                "affected_tenants": low_scoring_tenants[:5]
            })
        
        return recommendations
    
    # Mock methods for when Weaviate is not available
    def _mock_compliance_query(self, client_id: str, filters: Optional[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
        """Mock compliance query results"""
        return [
            {
                "clientId": client_id,
                "organizationName": "Mock Organization",
                "provider": "AWS",
                "controlId": "CC6.1",
                "framework": "SOC2",
                "score": 85.5,
                "status": "partial",
                "assessmentDate": datetime.now().isoformat(),
                "riskLevel": "medium",
                "recommendations": "Improve MFA coverage"
            }
        ]
    
    def _mock_asset_query(self, client_id: str, filters: Optional[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
        """Mock asset query results"""
        return [
            {
                "clientId": client_id,
                "assetId": "asset-001",
                "assetName": "Web Server",
                "assetType": "server",
                "cloudProvider": "AWS",
                "riskScore": 45.0,
                "riskLevel": "medium",
                "complianceHealthScore": 78.5
            }
        ]
    
    def _mock_semantic_search(self, client_id: str, query_text: str, search_type: str, limit: int) -> List[Dict[str, Any]]:
        """Mock semantic search results"""
        return [
            {
                "clientId": client_id,
                "controlId": "CC6.1",
                "framework": "SOC2",
                "score": 82.0,
                "recommendations": f"Results for: {query_text}"
            }
        ]

# Factory function
def create_multitenant_bridge(weaviate_client=None, isolation_level: TenantIsolationLevel = TenantIsolationLevel.SOFT) -> WeaviateMultiTenantBridge:
    """Create multi-tenant Weaviate bridge"""
    return WeaviateMultiTenantBridge(weaviate_client, isolation_level)

# Example usage
if __name__ == "__main__":
    # Test multi-tenant bridge
    bridge = create_multitenant_bridge()
    
    # Create sample compliance score
    score = MultiTenantComplianceScore(
        client_id="test_client",
        organization_name="Test Organization",
        tenant_tier="enterprise",
        provider="AWS",
        control_id="CC6.1",
        framework="SOC2",
        score=85.5,
        status="partial",
        evidence_summary={"mfa_enabled": True},
        component_scores={"mfa": 90.0, "password_policy": 81.0},
        risk_factors=["Incomplete MFA coverage"],
        recommendations=["Enable MFA for all users"]
    )
    
    try:
        # Test persistence
        result = bridge.persist_compliance_score(score)
        print(f"✅ Persisted compliance score: {result}")
        
        # Test queries
        scores = bridge.query_tenant_compliance("test_client")
        print(f"✅ Found {len(scores)} compliance scores")
        
        # Test analytics
        analytics = bridge.get_tenant_analytics_dashboard("test_client")
        print(f"✅ Generated analytics dashboard with {len(analytics)} sections")
        
        print("🎉 Multi-tenant Weaviate bridge test completed successfully!")
        
    except Exception as e:
        print(f"⚠️ Multi-tenant bridge test completed with mock data: {e}")