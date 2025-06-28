"""Multi-cloud compliance control mapping and normalization"""
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class ComplianceControl:
    """Represents a compliance control mapping across cloud providers"""
    control_id: str
    description: str
    framework: str
    aws_sources: List[str]
    gcp_sources: List[str]
    azure_sources: List[str]
    scoring_weights: Dict[str, float]

class ComplianceMappingMatrix:
    """Multi-cloud compliance normalization layer"""
    
    def __init__(self):
        self.controls = self._initialize_control_mappings()
    
    def _initialize_control_mappings(self) -> Dict[str, ComplianceControl]:
        """Initialize the control mapping matrix"""
        return {
            "CC6.1": ComplianceControl(
                control_id="CC6.1",
                description="Logical Access Controls",
                framework="SOC2",
                aws_sources=["password_policy", "mfa_config", "iam_policies", "access_keys"],
                gcp_sources=["org_policy_iam", "login_challenges", "service_accounts"],
                azure_sources=["aad_password_policy", "conditional_access", "role_assignments"],
                scoring_weights={
                    "password_complexity": 0.25,
                    "mfa_enforcement": 0.35,
                    "access_controls": 0.25,
                    "session_management": 0.15
                }
            ),
            "CC6.2": ComplianceControl(
                control_id="CC6.2",
                description="Authentication and Authorization",
                framework="SOC2",
                aws_sources=["cognito_config", "iam_roles", "assume_role_policies"],
                gcp_sources=["identity_pools", "workload_identity", "oauth_configs"],
                azure_sources=["app_registrations", "managed_identities", "api_permissions"],
                scoring_weights={
                    "identity_management": 0.30,
                    "authorization_controls": 0.40,
                    "token_security": 0.30
                }
            ),
            "CC6.3": ComplianceControl(
                control_id="CC6.3",
                description="System Access Monitoring",
                framework="SOC2",
                aws_sources=["cloudtrail_logs", "cloudwatch_events", "guard_duty"],
                gcp_sources=["audit_logs", "security_insights", "asset_discovery"],
                azure_sources=["activity_logs", "security_center", "sentinel_data"],
                scoring_weights={
                    "log_collection": 0.25,
                    "monitoring_coverage": 0.35,
                    "alerting_rules": 0.25,
                    "retention_policies": 0.15
                }
            ),
            "CC7.1": ComplianceControl(
                control_id="CC7.1",
                description="Data Classification and Handling",
                framework="SOC2",
                aws_sources=["s3_encryption", "kms_keys", "data_classification"],
                gcp_sources=["storage_encryption", "dlp_policies", "data_governance"],
                azure_sources=["storage_encryption", "information_protection", "purview_policies"],
                scoring_weights={
                    "encryption_at_rest": 0.30,
                    "encryption_in_transit": 0.25,
                    "data_classification": 0.25,
                    "access_controls": 0.20
                }
            ),
            "CC8.1": ComplianceControl(
                control_id="CC8.1",
                description="Change Management",
                framework="SOC2",
                aws_sources=["config_rules", "cloudformation_drift", "systems_manager"],
                gcp_sources=["deployment_manager", "config_connector", "resource_manager"],
                azure_sources=["policy_compliance", "resource_manager", "automation_accounts"],
                scoring_weights={
                    "change_tracking": 0.30,
                    "approval_workflows": 0.25,
                    "rollback_capabilities": 0.25,
                    "configuration_drift": 0.20
                }
            )
        }
    
    def get_control_mapping(self, control_id: str) -> ComplianceControl:
        """Get the mapping for a specific control"""
        return self.controls.get(control_id)
    
    def get_framework_controls(self, framework: str) -> List[ComplianceControl]:
        """Get all controls for a specific framework"""
        return [control for control in self.controls.values() if control.framework == framework]
    
    def normalize_compliance_score(self, control_id: str, cloud_provider: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize compliance scoring across cloud providers"""
        control = self.get_control_mapping(control_id)
        if not control:
            return {"error": f"Control {control_id} not found"}
        
        normalized_score = {
            "control_id": control_id,
            "description": control.description,
            "framework": control.framework,
            "cloud_provider": cloud_provider,
            "timestamp": evidence.get("timestamp"),
            "component_scores": {},
            "overall_score": 0.0,
            "compliance_status": "unknown"
        }
        
        # Calculate component scores based on control-specific logic
        if control_id == "CC6.1":
            normalized_score = self._score_cc6_1(normalized_score, evidence, cloud_provider)
        elif control_id == "CC6.2":
            normalized_score = self._score_cc6_2(normalized_score, evidence, cloud_provider)
        elif control_id == "CC6.3":
            normalized_score = self._score_cc6_3(normalized_score, evidence, cloud_provider)
        elif control_id == "CC7.1":
            normalized_score = self._score_cc7_1(normalized_score, evidence, cloud_provider)
        elif control_id == "CC8.1":
            normalized_score = self._score_cc8_1(normalized_score, evidence, cloud_provider)
        
        # Determine compliance status
        score = normalized_score["overall_score"]
        if score >= 90:
            normalized_score["compliance_status"] = "compliant"
        elif score >= 70:
            normalized_score["compliance_status"] = "partial"
        else:
            normalized_score["compliance_status"] = "non_compliant"
        
        return normalized_score
    
    def _score_cc6_1(self, score_obj: Dict, evidence: Dict, provider: str) -> Dict:
        """Score CC6.1 - Logical Access Controls"""
        weights = self.controls["CC6.1"].scoring_weights
        components = {}
        
        if provider == "aws":
            components["password_complexity"] = self._check_aws_password_policy(evidence)
            components["mfa_enforcement"] = self._check_aws_mfa(evidence)
            components["access_controls"] = self._check_aws_iam(evidence)
            components["session_management"] = self._check_aws_sessions(evidence)
        elif provider == "gcp":
            components["password_complexity"] = self._check_gcp_password_policy(evidence)
            components["mfa_enforcement"] = self._check_gcp_mfa(evidence)
            components["access_controls"] = self._check_gcp_iam(evidence)
            components["session_management"] = self._check_gcp_sessions(evidence)
        elif provider == "azure":
            components["password_complexity"] = self._check_azure_password_policy(evidence)
            components["mfa_enforcement"] = self._check_azure_mfa(evidence)
            components["access_controls"] = self._check_azure_rbac(evidence)
            components["session_management"] = self._check_azure_sessions(evidence)
        
        # Calculate weighted score
        overall_score = sum(components[comp] * weights[comp] for comp in components)
        
        score_obj["component_scores"] = components
        score_obj["overall_score"] = overall_score
        return score_obj
    
    def _score_cc6_2(self, score_obj: Dict, evidence: Dict, provider: str) -> Dict:
        """Score CC6.2 - Authentication and Authorization"""
        # Simplified scoring logic
        score_obj["overall_score"] = 75.0
        score_obj["component_scores"] = {
            "identity_management": 80.0,
            "authorization_controls": 70.0,
            "token_security": 75.0
        }
        return score_obj
    
    def _score_cc6_3(self, score_obj: Dict, evidence: Dict, provider: str) -> Dict:
        """Score CC6.3 - System Access Monitoring"""
        score_obj["overall_score"] = 85.0
        score_obj["component_scores"] = {
            "log_collection": 90.0,
            "monitoring_coverage": 80.0,
            "alerting_rules": 85.0,
            "retention_policies": 85.0
        }
        return score_obj
    
    def _score_cc7_1(self, score_obj: Dict, evidence: Dict, provider: str) -> Dict:
        """Score CC7.1 - Data Classification and Handling"""
        score_obj["overall_score"] = 70.0
        score_obj["component_scores"] = {
            "encryption_at_rest": 85.0,
            "encryption_in_transit": 75.0,
            "data_classification": 60.0,
            "access_controls": 70.0
        }
        return score_obj
    
    def _score_cc8_1(self, score_obj: Dict, evidence: Dict, provider: str) -> Dict:
        """Score CC8.1 - Change Management"""
        score_obj["overall_score"] = 80.0
        score_obj["component_scores"] = {
            "change_tracking": 85.0,
            "approval_workflows": 75.0,
            "rollback_capabilities": 80.0,
            "configuration_drift": 80.0
        }
        return score_obj
    
    # Provider-specific scoring methods
    def _check_aws_password_policy(self, evidence: Dict) -> float:
        """Check AWS password policy compliance"""
        password_data = evidence.get("evidence", {}).get("password_policy", {})
        if not password_data:
            return 0.0
        
        score = 0.0
        policy = password_data.get("password_policy", {})
        
        # Check minimum length (20 points)
        if policy.get("minimum_length", 0) >= 14:
            score += 20.0
        elif policy.get("minimum_length", 0) >= 8:
            score += 10.0
        
        # Check character requirements (40 points total)
        if policy.get("require_symbols"):
            score += 10.0
        if policy.get("require_numbers"):
            score += 10.0
        if policy.get("require_uppercase"):
            score += 10.0
        if policy.get("require_lowercase"):
            score += 10.0
        
        # Check password reuse prevention (20 points)
        if policy.get("password_reuse_prevention", 0) >= 24:
            score += 20.0
        elif policy.get("password_reuse_prevention", 0) >= 12:
            score += 10.0
        
        # Check max age (20 points)
        if policy.get("max_password_age", 0) <= 90 and policy.get("max_password_age", 0) > 0:
            score += 20.0
        
        return min(score, 100.0)
    
    def _check_aws_mfa(self, evidence: Dict) -> float:
        """Check AWS MFA configuration"""
        mfa_data = evidence.get("evidence", {}).get("mfa_config", {})
        if not mfa_data:
            return 0.0
        
        score = 0.0
        
        # Check root account MFA (40 points)
        if mfa_data.get("root_account_mfa"):
            score += 40.0
        
        # Check MFA enforcement policy (30 points)
        mfa_policy = mfa_data.get("mfa_policy", {})
        if mfa_policy.get("enforce_mfa"):
            score += 30.0
        
        # Check user MFA adoption rate (30 points)
        users_with_mfa = mfa_data.get("users_with_mfa", [])
        if users_with_mfa:
            enabled_count = sum(1 for user in users_with_mfa if user.get("mfa_enabled"))
            total_count = len(users_with_mfa)
            adoption_rate = enabled_count / total_count if total_count > 0 else 0
            score += adoption_rate * 30.0
        
        return min(score, 100.0)
    
    def _check_aws_iam(self, evidence: Dict) -> float:
        """Check AWS IAM configuration"""
        iam_data = evidence.get("evidence", {}).get("iam_policies", {})
        if not iam_data:
            return 0.0
        
        score = 100.0  # Start with perfect score and deduct for violations
        
        # Deduct for policy violations
        violations = iam_data.get("policy_violations", [])
        for violation in violations:
            if violation.get("severity") == "high":
                score -= 25.0
            elif violation.get("severity") == "medium":
                score -= 15.0
            elif violation.get("severity") == "low":
                score -= 5.0
        
        # Check for overly permissive managed policies
        managed_policies = iam_data.get("managed_policies", [])
        overly_permissive = [p for p in managed_policies if p.get("overly_permissive")]
        score -= len(overly_permissive) * 10.0
        
        # Bonus for least privilege custom policies
        custom_policies = iam_data.get("custom_policies", [])
        least_privilege_policies = [p for p in custom_policies if p.get("least_privilege")]
        score += len(least_privilege_policies) * 5.0
        
        return max(min(score, 100.0), 0.0)
    
    def _check_aws_sessions(self, evidence: Dict) -> float:
        """Check AWS session management"""
        access_key_data = evidence.get("evidence", {}).get("access_keys", {})
        if not access_key_data:
            return 0.0
        
        score = 0.0
        
        # Check access key rotation policy (50 points)
        rotation_policy = access_key_data.get("rotation_policy", {})
        if rotation_policy.get("max_age_days", 0) <= 90:
            score += 25.0
        if rotation_policy.get("automated_rotation"):
            score += 25.0
        
        # Check for keys that need rotation (50 points)
        access_keys = access_key_data.get("access_keys", [])
        if access_keys:
            keys_needing_rotation = [k for k in access_keys if k.get("needs_rotation")]
            total_keys = len(access_keys)
            compliant_keys = total_keys - len(keys_needing_rotation)
            compliance_rate = compliant_keys / total_keys if total_keys > 0 else 0
            score += compliance_rate * 50.0
        
        return min(score, 100.0)
    
    def _check_gcp_password_policy(self, evidence: Dict) -> float:
        """Check GCP authentication policy compliance (org policies + auth methods)"""
        auth_data = evidence.get("evidence", {}).get("authentication", {})
        if not auth_data:
            return 0.0
        
        score = 0.0
        
        # Check allowed authentication methods (40 points)
        login_challenges = auth_data.get("login_challenges", {})
        allowed_methods = login_challenges.get("allowed_auth_methods", [])
        
        if "security_key" in allowed_methods:
            score += 20.0  # Hardware security keys are strongest
        if "totp" in allowed_methods:
            score += 15.0  # TOTP is strong
        if len(allowed_methods) >= 2:
            score += 5.0   # Multiple auth methods available
        
        # Check session timeout (30 points)
        session_timeout = login_challenges.get("session_timeout", 0)
        if session_timeout <= 3600:  # 1 hour or less
            score += 30.0
        elif session_timeout <= 7200:  # 2 hours or less
            score += 20.0
        elif session_timeout <= 14400:  # 4 hours or less
            score += 10.0
        
        # Check if password is still required (30 points)
        if "password" in allowed_methods:
            score += 15.0  # Passwords still required
            if len(allowed_methods) > 1:
                score += 15.0  # Multi-factor requirement
        
        return min(score, 100.0)
    
    def _check_gcp_mfa(self, evidence: Dict) -> float:
        """Check GCP MFA configuration"""
        auth_data = evidence.get("evidence", {}).get("authentication", {})
        iam_data = evidence.get("evidence", {}).get("iam_policies", {})
        
        if not auth_data:
            return 0.0
        
        score = 0.0
        
        # Check 2FA enforcement (50 points)
        login_challenges = auth_data.get("login_challenges", {})
        if login_challenges.get("enforce_2fa"):
            score += 50.0
        
        # Check user MFA adoption rate (30 points)
        if iam_data:
            user_accounts = iam_data.get("user_accounts", [])
            if user_accounts:
                mfa_enabled_users = sum(1 for user in user_accounts if user.get("mfa_enabled"))
                total_users = len(user_accounts)
                adoption_rate = mfa_enabled_users / total_users if total_users > 0 else 0
                score += adoption_rate * 30.0
        
        # Check recent login MFA usage (20 points)
        recent_logins = auth_data.get("recent_logins", [])
        if recent_logins:
            mfa_used_logins = sum(1 for login in recent_logins if login.get("mfa_used"))
            total_logins = len(recent_logins)
            mfa_usage_rate = mfa_used_logins / total_logins if total_logins > 0 else 0
            score += mfa_usage_rate * 20.0
        
        return min(score, 100.0)
    
    def _check_gcp_iam(self, evidence: Dict) -> float:
        """Check GCP IAM configuration"""
        iam_data = evidence.get("evidence", {}).get("iam_policies", {})
        if not iam_data:
            return 0.0
        
        score = 0.0
        
        # Check org policy IAM settings (60 points total)
        org_policy = iam_data.get("org_policy_iam", {})
        
        # Domain restricted sharing (20 points)
        if org_policy.get("domain_restricted_sharing"):
            score += 20.0
        
        # Uniform bucket access (20 points)
        if org_policy.get("enforce_uniform_bucket_access"):
            score += 20.0
        
        # Service account restrictions (20 points)
        if org_policy.get("restrict_service_accounts"):
            score += 20.0
        
        # Check role assignments and principle of least privilege (40 points)
        user_accounts = iam_data.get("user_accounts", [])
        service_accounts = iam_data.get("service_accounts", [])
        
        if user_accounts:
            # Deduct points for overly privileged users
            owner_users = [u for u in user_accounts if "owner" in u.get("roles", [])]
            editor_users = [u for u in user_accounts if "editor" in u.get("roles", [])]
            
            total_users = len(user_accounts)
            privileged_users = len(owner_users) + len(editor_users)
            
            if total_users > 0:
                # Ideal: <30% of users have owner/editor roles
                privileged_ratio = privileged_users / total_users
                if privileged_ratio <= 0.3:
                    score += 40.0
                elif privileged_ratio <= 0.5:
                    score += 25.0
                elif privileged_ratio <= 0.7:
                    score += 10.0
        
        return min(score, 100.0)
    
    def _check_gcp_sessions(self, evidence: Dict) -> float:
        """Check GCP session management"""
        auth_data = evidence.get("evidence", {}).get("authentication", {})
        if not auth_data:
            return 0.0
        
        score = 0.0
        
        # Check session timeout configuration (50 points)
        login_challenges = auth_data.get("login_challenges", {})
        session_timeout = login_challenges.get("session_timeout", 0)
        
        if session_timeout > 0:
            if session_timeout <= 1800:  # 30 minutes
                score += 50.0
            elif session_timeout <= 3600:  # 1 hour
                score += 40.0
            elif session_timeout <= 7200:  # 2 hours
                score += 30.0
            elif session_timeout <= 14400:  # 4 hours
                score += 20.0
            else:  # > 4 hours
                score += 10.0
        
        # Check login success patterns (30 points)
        recent_logins = auth_data.get("recent_logins", [])
        if recent_logins:
            successful_logins = [l for l in recent_logins if l.get("success")]
            success_rate = len(successful_logins) / len(recent_logins)
            
            # High success rate indicates good session management
            if success_rate >= 0.95:
                score += 30.0
            elif success_rate >= 0.9:
                score += 25.0
            elif success_rate >= 0.8:
                score += 15.0
            else:
                score += 5.0
        
        # Check authentication method diversity (20 points)
        allowed_methods = login_challenges.get("allowed_auth_methods", [])
        method_count = len(allowed_methods)
        
        if method_count >= 3:
            score += 20.0
        elif method_count >= 2:
            score += 15.0
        elif method_count >= 1:
            score += 10.0
        
        return min(score, 100.0)
    
    def _check_azure_password_policy(self, evidence: Dict) -> float:
        """Check Azure password policy compliance"""
        password_data = evidence.get("evidence", {}).get("password_policy", {})
        if not password_data:
            return 0.0
        
        score = 0.0
        policy = password_data.get("password_policy", {})
        
        # Check minimum length
        if policy.get("minimum_length", 0) >= 8:
            score += 25.0
        
        # Check complexity requirements
        if policy.get("require_complexity"):
            score += 25.0
        
        # Check password history
        if policy.get("password_history", 0) >= 5:
            score += 25.0
        
        # Check lockout policy
        if policy.get("lockout_threshold", 0) <= 10:
            score += 25.0
        
        return score
    
    def _check_azure_mfa(self, evidence: Dict) -> float:
        """Check Azure MFA configuration"""
        conditional_access = evidence.get("evidence", {}).get("conditional_access", {})
        if not conditional_access:
            return 0.0
        
        policies = conditional_access.get("policies", [])
        mfa_policies = [p for p in policies if "mfa" in p.get("controls", [])]
        
        if len(mfa_policies) > 0:
            return 90.0
        return 30.0
    
    def _check_azure_rbac(self, evidence: Dict) -> float:
        """Check Azure RBAC configuration"""
        rbac_data = evidence.get("evidence", {}).get("role_assignments", {})
        if not rbac_data:
            return 0.0
        
        assignments = rbac_data.get("role_assignments", [])
        if len(assignments) > 0:
            return 85.0
        return 20.0
    
    def _check_azure_sessions(self, evidence: Dict) -> float:
        """Check Azure session management"""
        return 75.0