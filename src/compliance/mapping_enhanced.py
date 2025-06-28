#!/usr/bin/env python3
"""
Enhanced Multi-cloud compliance control mapping and normalization
Supports comprehensive SOC 2 evidence collection across AWS, GCP, and Azure
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

class CloudProvider(Enum):
    """Supported cloud providers"""
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"

class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    CIS = "cis"
    NIST = "nist"

@dataclass
class ControlEvidence:
    """Evidence source mapping for a control across cloud providers"""
    aws_sources: List[str] = field(default_factory=list)
    gcp_sources: List[str] = field(default_factory=list)
    azure_sources: List[str] = field(default_factory=list)
    collection_methods: Dict[str, str] = field(default_factory=dict)

@dataclass
class ComplianceControl:
    """Enhanced compliance control with detailed mappings"""
    control_id: str
    title: str
    description: str
    framework: ComplianceFramework
    category: str
    risk_level: str
    evidence: ControlEvidence
    scoring_weights: Dict[str, float]
    threshold_compliant: float = 90.0
    threshold_partial: float = 70.0
    
class EnhancedComplianceMappingMatrix:
    """Enhanced multi-cloud compliance normalization layer"""
    
    def __init__(self):
        self.controls = self._initialize_enhanced_mappings()
        self.provider_methods = self._initialize_provider_methods()
    
    def _initialize_enhanced_mappings(self) -> Dict[str, ComplianceControl]:
        """Initialize comprehensive control mappings with enhanced evidence sources"""
        return {
            "CC6.1": ComplianceControl(
                control_id="CC6.1",
                title="Logical Access Controls",
                description="The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity's objectives.",
                framework=ComplianceFramework.SOC2,
                category="Access Control",
                risk_level="High",
                evidence=ControlEvidence(
                    aws_sources=[
                        "password_policy", "mfa_devices", "iam_policies", "access_keys",
                        "account_summary", "security_hub_findings", "permissions_boundaries"
                    ],
                    gcp_sources=[
                        "organization_policies", "iam_policies", "workspace_security",
                        "service_accounts", "identity_management", "domain_restrictions"
                    ],
                    azure_sources=[
                        "azure_ad_policies", "conditional_access", "rbac_assignments",
                        "privileged_identity_management", "authentication_methods", "user_management"
                    ],
                    collection_methods={
                        "aws": "collect_soc2_cc6_1_evidence",
                        "gcp": "collect_soc2_cc6_1_evidence", 
                        "azure": "collect_soc2_cc6_1_evidence"
                    }
                ),
                scoring_weights={
                    "password_policy_strength": 0.20,
                    "mfa_enforcement": 0.25,
                    "access_control_policies": 0.25,
                    "privileged_access_management": 0.20,
                    "account_lifecycle_management": 0.10
                }
            ),
            
            "CC6.2": ComplianceControl(
                control_id="CC6.2",
                title="Authentication",
                description="Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users whose access is administered by the entity.",
                framework=ComplianceFramework.SOC2,
                category="Authentication",
                risk_level="High",
                evidence=ControlEvidence(
                    aws_sources=[
                        "mfa_devices", "password_policy", "access_keys", "iam_user_management",
                        "cognito_user_pools", "federation_providers", "root_account_security"
                    ],
                    gcp_sources=[
                        "workspace_security", "identity_providers", "authentication_methods",
                        "service_account_keys", "oauth_configurations", "session_management"
                    ],
                    azure_sources=[
                        "azure_ad_policies", "authentication_methods", "conditional_access",
                        "identity_protection", "self_service_password_reset", "guest_access"
                    ],
                    collection_methods={
                        "aws": "collect_soc2_cc6_2_evidence",
                        "gcp": "collect_soc2_cc6_2_evidence",
                        "azure": "collect_soc2_cc6_2_evidence"
                    }
                ),
                scoring_weights={
                    "multi_factor_authentication": 0.30,
                    "authentication_policies": 0.25,
                    "credential_management": 0.25,
                    "session_management": 0.20
                }
            ),
            
            "CC6.3": ComplianceControl(
                control_id="CC6.3",
                title="Authorization",
                description="The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles, responsibilities, or the system use case for which access is required.",
                framework=ComplianceFramework.SOC2,
                category="Authorization",
                risk_level="High",
                evidence=ControlEvidence(
                    aws_sources=[
                        "iam_policies", "role_trust_policies", "permissions_boundaries",
                        "access_analyzer", "policy_simulator", "least_privilege_analysis"
                    ],
                    gcp_sources=[
                        "iam_policies", "organization_policies", "conditional_iam",
                        "resource_hierarchy", "policy_intelligence", "custom_roles"
                    ],
                    azure_sources=[
                        "rbac_assignments", "conditional_access", "privileged_identity_management",
                        "custom_roles", "application_permissions", "entitlement_management"
                    ],
                    collection_methods={
                        "aws": "collect_soc2_cc6_3_evidence",
                        "gcp": "collect_soc2_cc6_3_evidence",
                        "azure": "collect_soc2_cc6_3_evidence"
                    }
                ),
                scoring_weights={
                    "least_privilege_implementation": 0.30,
                    "role_based_access_control": 0.25,
                    "regular_access_reviews": 0.25,
                    "privilege_escalation_controls": 0.20
                }
            ),
            
            "CC7.1": ComplianceControl(
                control_id="CC7.1",
                title="System Monitoring",
                description="To meet its objectives, the entity uses detection and monitoring procedures to identify (1) changes to configurations that result in the introduction of new vulnerabilities, and (2) susceptibilities to newly discovered vulnerabilities.",
                framework=ComplianceFramework.SOC2,
                category="System Operations",
                risk_level="Medium",
                evidence=ControlEvidence(
                    aws_sources=[
                        "cloudtrail_config", "config_rules", "security_hub_findings",
                        "guardduty_findings", "inspector_assessments", "systems_manager_compliance"
                    ],
                    gcp_sources=[
                        "cloud_logging", "security_center_findings", "asset_inventory",
                        "policy_analyzer", "security_insights", "audit_logs"
                    ],
                    azure_sources=[
                        "activity_logs", "security_center_data", "policy_compliance",
                        "azure_monitor", "log_analytics", "security_insights"
                    ],
                    collection_methods={
                        "aws": "collect_soc2_cc7_1_evidence",
                        "gcp": "collect_soc2_cc7_1_evidence",
                        "azure": "collect_soc2_cc7_1_evidence"
                    }
                ),
                scoring_weights={
                    "comprehensive_logging": 0.30,
                    "security_monitoring": 0.25,
                    "vulnerability_management": 0.25,
                    "incident_detection": 0.20
                }
            ),
            
            "CC8.1": ComplianceControl(
                control_id="CC8.1", 
                title="Change Management",
                description="The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures to meet its objectives.",
                framework=ComplianceFramework.SOC2,
                category="Change Management",
                risk_level="Medium",
                evidence=ControlEvidence(
                    aws_sources=[
                        "cloudtrail_config", "config_rules", "systems_manager_patch",
                        "cloudformation_drift", "code_pipeline", "change_calendar"
                    ],
                    gcp_sources=[
                        "cloud_logging", "deployment_manager", "config_connector",
                        "cloud_build", "release_manager", "binary_authorization"
                    ],
                    azure_sources=[
                        "activity_logs", "policy_compliance", "automation_accounts",
                        "devops_pipelines", "update_management", "change_tracking"
                    ],
                    collection_methods={
                        "aws": "collect_soc2_cc8_1_evidence",
                        "gcp": "collect_soc2_cc8_1_evidence",
                        "azure": "collect_soc2_cc8_1_evidence"
                    }
                ),
                scoring_weights={
                    "change_tracking": 0.30,
                    "approval_workflows": 0.25,
                    "testing_procedures": 0.25,
                    "rollback_capabilities": 0.20
                }
            )
        }
    
    def _initialize_provider_methods(self) -> Dict[str, Dict[str, str]]:
        """Initialize provider-specific collection methods"""
        return {
            "aws": {
                "account_summary": "collect_account_summary",
                "password_policy": "collect_password_policy",
                "mfa_devices": "collect_mfa_devices",
                "iam_policies": "collect_iam_policies",
                "access_keys": "collect_access_keys",
                "cloudtrail_config": "collect_cloudtrail_config",
                "s3_security": "collect_s3_security",
                "config_rules": "collect_config_rules",
                "security_hub_findings": "collect_security_hub_findings"
            },
            "gcp": {
                "organization_policies": "collect_organization_policies",
                "iam_policies": "collect_iam_policies",
                "workspace_security": "collect_workspace_security",
                "security_center_findings": "collect_security_center_findings",
                "cloud_logging": "collect_cloud_logging_config",
                "storage_security": "collect_storage_security",
                "compute_security": "collect_compute_security"
            },
            "azure": {
                "azure_ad_policies": "collect_azure_ad_policies",
                "azure_ad_users": "collect_azure_ad_users",
                "rbac_assignments": "collect_rbac_assignments",
                "security_center_data": "collect_security_center_data",
                "storage_security": "collect_storage_security",
                "network_security": "collect_network_security",
                "key_vault_security": "collect_key_vault_security",
                "activity_logs": "collect_activity_logs"
            }
        }
    
    def get_control_mapping(self, control_id: str) -> Optional[ComplianceControl]:
        """Get the mapping for a specific control"""
        return self.controls.get(control_id)
    
    def get_framework_controls(self, framework: ComplianceFramework) -> List[ComplianceControl]:
        """Get all controls for a specific framework"""
        return [control for control in self.controls.values() 
                if control.framework == framework]
    
    def get_soc2_controls(self) -> List[ComplianceControl]:
        """Get all SOC 2 controls"""
        return self.get_framework_controls(ComplianceFramework.SOC2)
    
    def get_provider_evidence_sources(self, control_id: str, provider: CloudProvider) -> List[str]:
        """Get evidence sources for a specific control and provider"""
        control = self.get_control_mapping(control_id)
        if not control:
            return []
        
        if provider == CloudProvider.AWS:
            return control.evidence.aws_sources
        elif provider == CloudProvider.GCP:
            return control.evidence.gcp_sources
        elif provider == CloudProvider.AZURE:
            return control.evidence.azure_sources
        
        return []
    
    def get_collection_method(self, control_id: str, provider: CloudProvider) -> Optional[str]:
        """Get the collection method for a specific control and provider"""
        control = self.get_control_mapping(control_id)
        if not control:
            return None
        
        return control.evidence.collection_methods.get(provider.value)
    
    def calculate_control_score(self, control_id: str, component_scores: Dict[str, float]) -> Dict[str, Any]:
        """Calculate weighted compliance score for a control"""
        control = self.get_control_mapping(control_id)
        if not control:
            return {"error": "Control not found"}
        
        total_score = 0.0
        total_weight = 0.0
        component_details = {}
        
        for component, weight in control.scoring_weights.items():
            if component in component_scores:
                score = component_scores[component]
                weighted_score = score * weight
                total_score += weighted_score
                total_weight += weight
                
                component_details[component] = {
                    "score": score,
                    "weight": weight,
                    "weighted_score": weighted_score
                }
        
        # Normalize score if we don't have all components
        if total_weight > 0:
            final_score = total_score / total_weight
        else:
            final_score = 0.0
        
        # Determine compliance status
        if final_score >= control.threshold_compliant:
            status = "compliant"
        elif final_score >= control.threshold_partial:
            status = "partial"
        else:
            status = "non_compliant"
        
        return {
            "control_id": control_id,
            "score": final_score,
            "status": status,
            "component_scores": component_details,
            "total_weight_used": total_weight,
            "max_possible_weight": sum(control.scoring_weights.values()),
            "coverage_percentage": (total_weight / sum(control.scoring_weights.values())) * 100
        }
    
    def normalize_evidence_across_providers(self, control_id: str, evidence_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize evidence data across different cloud providers"""
        control = self.get_control_mapping(control_id)
        if not control:
            return {}
        
        normalized = {
            "control_id": control_id,
            "title": control.title,
            "description": control.description,
            "framework": control.framework.value,
            "category": control.category,
            "risk_level": control.risk_level,
            "providers": {},
            "unified_score": 0.0,
            "compliance_status": "not_assessed"
        }
        
        provider_scores = {}
        total_providers = 0
        
        # Process each provider's evidence
        for provider_key, provider_evidence in evidence_data.items():
            if provider_key in ["aws", "gcp", "azure"]:
                provider = CloudProvider(provider_key)
                
                # Extract component scores from provider evidence
                component_scores = self._extract_component_scores(
                    control_id, provider, provider_evidence
                )
                
                # Calculate provider-specific score
                provider_result = self.calculate_control_score(control_id, component_scores)
                
                normalized["providers"][provider_key] = {
                    "evidence": provider_evidence,
                    "score": provider_result["score"],
                    "status": provider_result["status"],
                    "component_scores": provider_result["component_scores"]
                }
                
                provider_scores[provider_key] = provider_result["score"]
                total_providers += 1
        
        # Calculate unified score across providers
        if provider_scores:
            normalized["unified_score"] = sum(provider_scores.values()) / len(provider_scores)
            
            # Determine unified compliance status
            if normalized["unified_score"] >= control.threshold_compliant:
                normalized["compliance_status"] = "compliant"
            elif normalized["unified_score"] >= control.threshold_partial:
                normalized["compliance_status"] = "partial"
            else:
                normalized["compliance_status"] = "non_compliant"
        
        return normalized
    
    def _extract_component_scores(self, control_id: str, provider: CloudProvider, evidence: Dict[str, Any]) -> Dict[str, float]:
        """Extract component scores from provider-specific evidence"""
        # This method maps provider-specific evidence to standard scoring components
        # Implementation would depend on the specific evidence structure from each provider
        
        component_scores = {}
        
        if control_id == "CC6.1":
            # Map evidence to scoring components for CC6.1
            if provider == CloudProvider.AWS:
                if "password_policy" in evidence:
                    component_scores["password_policy_strength"] = self._score_aws_password_policy(evidence["password_policy"])
                if "mfa_configuration" in evidence:
                    component_scores["mfa_enforcement"] = self._score_aws_mfa(evidence["mfa_configuration"])
                # Add more component mappings...
                
        elif control_id == "CC6.2":
            # Map evidence for CC6.2
            if provider == CloudProvider.GCP:
                if "workspace_security" in evidence:
                    component_scores["multi_factor_authentication"] = self._score_gcp_mfa(evidence["workspace_security"])
                # Add more component mappings...
        
        # Add more control mappings...
        
        return component_scores
    
    def _score_aws_password_policy(self, policy_data: Dict[str, Any]) -> float:
        """Score AWS password policy strength"""
        score = 0.0
        policy = policy_data.get("password_policy", {})
        
        # Check minimum length
        if policy.get("minimum_length", 0) >= 14:
            score += 25
        elif policy.get("minimum_length", 0) >= 12:
            score += 20
        
        # Check complexity requirements
        if all([
            policy.get("require_symbols"),
            policy.get("require_numbers"),
            policy.get("require_uppercase"),
            policy.get("require_lowercase")
        ]):
            score += 25
        
        # Check password history
        if policy.get("password_reuse_prevention", 0) >= 24:
            score += 25
        elif policy.get("password_reuse_prevention", 0) >= 12:
            score += 20
        
        # Check max age
        if policy.get("max_password_age", 365) <= 90:
            score += 25
        
        return score
    
    def _score_aws_mfa(self, mfa_data: Dict[str, Any]) -> float:
        """Score AWS MFA enforcement"""
        score = 0.0
        
        # Root account MFA
        if mfa_data.get("root_account_mfa"):
            score += 30
        
        # User MFA coverage
        mfa_stats = mfa_data.get("mfa_statistics", {})
        coverage = mfa_stats.get("mfa_coverage_percentage", 0)
        if coverage >= 95:
            score += 40
        elif coverage >= 90:
            score += 35
        elif coverage >= 80:
            score += 25
        
        # MFA policy enforcement
        mfa_policy = mfa_data.get("mfa_policy", {})
        if mfa_policy.get("enforce_mfa"):
            score += 30
        
        return score
    
    def _score_gcp_mfa(self, workspace_data: Dict[str, Any]) -> float:
        """Score GCP MFA enforcement"""
        score = 0.0
        
        domain_settings = workspace_data.get("domain_settings", {})
        two_step = domain_settings.get("two_step_verification", {})
        
        # Enforcement level
        if two_step.get("enforcement") == "MANDATORY":
            score += 40
        elif two_step.get("enforcement") == "OPTIONAL":
            score += 20
        
        # User coverage
        users = workspace_data.get("users", [])
        if users:
            users_with_2fa = sum(1 for user in users if user.get("two_step_verification"))
            coverage = (users_with_2fa / len(users)) * 100
            if coverage >= 95:
                score += 35
            elif coverage >= 90:
                score += 30
            elif coverage >= 80:
                score += 20
        
        # Grace period
        grace_period = two_step.get("grace_period_days", 30)
        if grace_period <= 7:
            score += 25
        elif grace_period <= 14:
            score += 15
        
        return score

# Factory function
def get_enhanced_mapping_matrix() -> EnhancedComplianceMappingMatrix:
    """Get an instance of the enhanced mapping matrix"""
    return EnhancedComplianceMappingMatrix()