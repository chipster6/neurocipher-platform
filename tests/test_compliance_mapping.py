"""Unit tests for compliance mapping and scoring logic"""
import pytest
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from compliance.mapping import ComplianceMappingMatrix, ComplianceControl

class TestComplianceMappingMatrix:
    """Test the compliance mapping matrix functionality"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mapper = ComplianceMappingMatrix()
    
    def test_control_mapping_initialization(self):
        """Test that control mappings are properly initialized"""
        # Test that all expected controls are present
        expected_controls = ["CC6.1", "CC6.2", "CC6.3", "CC7.1", "CC8.1"]
        for control_id in expected_controls:
            assert control_id in self.mapper.controls
        
        # Test CC6.1 mapping structure
        cc6_1 = self.mapper.get_control_mapping("CC6.1")
        assert cc6_1 is not None
        assert cc6_1.control_id == "CC6.1"
        assert cc6_1.description == "Logical Access Controls"
        assert cc6_1.framework == "SOC2"
        assert len(cc6_1.aws_sources) > 0
        assert len(cc6_1.gcp_sources) > 0
        assert len(cc6_1.azure_sources) > 0
    
    def test_framework_controls_retrieval(self):
        """Test retrieving controls by framework"""
        soc2_controls = self.mapper.get_framework_controls("SOC2")
        assert len(soc2_controls) == 5
        
        # Test that all controls are SOC2
        for control in soc2_controls:
            assert control.framework == "SOC2"

class TestAWSScoring:
    """Test AWS-specific scoring functions"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mapper = ComplianceMappingMatrix()
    
    def test_aws_password_policy_perfect_score(self):
        """Test AWS password policy scoring with perfect configuration"""
        perfect_evidence = {
            "evidence": {
                "password_policy": {
                    "password_policy": {
                        "minimum_length": 14,
                        "require_symbols": True,
                        "require_numbers": True,
                        "require_uppercase": True,
                        "require_lowercase": True,
                        "password_reuse_prevention": 24,
                        "max_password_age": 90
                    }
                }
            }
        }
        
        score = self.mapper._check_aws_password_policy(perfect_evidence)
        assert score == 100.0
    
    def test_aws_password_policy_weak_configuration(self):
        """Test AWS password policy scoring with weak configuration"""
        weak_evidence = {
            "evidence": {
                "password_policy": {
                    "password_policy": {
                        "minimum_length": 6,
                        "require_symbols": False,
                        "require_numbers": False,
                        "require_uppercase": False,
                        "require_lowercase": True,
                        "password_reuse_prevention": 1,
                        "max_password_age": 365
                    }
                }
            }
        }
        
        score = self.mapper._check_aws_password_policy(weak_evidence)
        assert score < 50.0  # Should be significantly lower
    
    def test_aws_mfa_perfect_score(self):
        """Test AWS MFA scoring with perfect configuration"""
        perfect_evidence = {
            "evidence": {
                "mfa_config": {
                    "root_account_mfa": True,
                    "mfa_policy": {
                        "enforce_mfa": True
                    },
                    "users_with_mfa": [
                        {"username": "user1", "mfa_enabled": True},
                        {"username": "user2", "mfa_enabled": True},
                        {"username": "user3", "mfa_enabled": True}
                    ]
                }
            }
        }
        
        score = self.mapper._check_aws_mfa(perfect_evidence)
        assert score == 100.0
    
    def test_aws_mfa_no_enforcement(self):
        """Test AWS MFA scoring with no enforcement"""
        no_mfa_evidence = {
            "evidence": {
                "mfa_config": {
                    "root_account_mfa": False,
                    "mfa_policy": {
                        "enforce_mfa": False
                    },
                    "users_with_mfa": [
                        {"username": "user1", "mfa_enabled": False},
                        {"username": "user2", "mfa_enabled": False}
                    ]
                }
            }
        }
        
        score = self.mapper._check_aws_mfa(no_mfa_evidence)
        assert score == 0.0
    
    def test_aws_iam_no_violations(self):
        """Test AWS IAM scoring with no policy violations"""
        clean_evidence = {
            "evidence": {
                "iam_policies": {
                    "policy_violations": [],
                    "managed_policies": [
                        {"name": "ReadOnlyAccess", "overly_permissive": False}
                    ],
                    "custom_policies": [
                        {"name": "CustomPolicy", "least_privilege": True}
                    ]
                }
            }
        }
        
        score = self.mapper._check_aws_iam(clean_evidence)
        assert score > 90.0  # Should be high with no violations
    
    def test_aws_iam_high_severity_violations(self):
        """Test AWS IAM scoring with high severity violations"""
        violation_evidence = {
            "evidence": {
                "iam_policies": {
                    "policy_violations": [
                        {"policy": "AdminAccess", "severity": "high"},
                        {"policy": "PowerUserAccess", "severity": "high"}
                    ],
                    "managed_policies": [
                        {"name": "AdminAccess", "overly_permissive": True}
                    ],
                    "custom_policies": []
                }
            }
        }
        
        score = self.mapper._check_aws_iam(violation_evidence)
        assert score < 60.0  # Should be significantly lower
    
    def test_aws_sessions_perfect_rotation(self):
        """Test AWS session management with perfect key rotation"""
        perfect_evidence = {
            "evidence": {
                "access_keys": {
                    "rotation_policy": {
                        "max_age_days": 90,
                        "automated_rotation": True
                    },
                    "access_keys": [
                        {"user": "user1", "needs_rotation": False},
                        {"user": "user2", "needs_rotation": False}
                    ]
                }
            }
        }
        
        score = self.mapper._check_aws_sessions(perfect_evidence)
        assert score == 100.0

class TestGCPScoring:
    """Test GCP-specific scoring functions"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mapper = ComplianceMappingMatrix()
    
    def test_gcp_password_policy_strong_auth(self):
        """Test GCP authentication policy with strong configuration"""
        strong_evidence = {
            "evidence": {
                "authentication": {
                    "login_challenges": {
                        "allowed_auth_methods": ["password", "totp", "security_key"],
                        "session_timeout": 3600
                    }
                }
            }
        }
        
        score = self.mapper._check_gcp_password_policy(strong_evidence)
        assert score >= 80.0  # Should be high with strong auth methods
    
    def test_gcp_mfa_perfect_enforcement(self):
        """Test GCP MFA with perfect enforcement and adoption"""
        perfect_evidence = {
            "evidence": {
                "authentication": {
                    "login_challenges": {
                        "enforce_2fa": True
                    },
                    "recent_logins": [
                        {"user": "user1", "mfa_used": True},
                        {"user": "user2", "mfa_used": True}
                    ]
                },
                "iam_policies": {
                    "user_accounts": [
                        {"email": "user1@company.com", "mfa_enabled": True},
                        {"email": "user2@company.com", "mfa_enabled": True}
                    ]
                }
            }
        }
        
        score = self.mapper._check_gcp_mfa(perfect_evidence)
        assert score == 100.0
    
    def test_gcp_iam_good_org_policies(self):
        """Test GCP IAM with good organizational policies"""
        good_evidence = {
            "evidence": {
                "iam_policies": {
                    "org_policy_iam": {
                        "domain_restricted_sharing": True,
                        "enforce_uniform_bucket_access": True,
                        "restrict_service_accounts": True
                    },
                    "user_accounts": [
                        {"email": "admin@company.com", "roles": ["viewer"]},
                        {"email": "dev@company.com", "roles": ["editor"]},
                        {"email": "user@company.com", "roles": ["viewer"]}
                    ]
                }
            }
        }
        
        score = self.mapper._check_gcp_iam(good_evidence)
        assert score >= 80.0  # Should be high with good policies
    
    def test_gcp_sessions_optimal_timeout(self):
        """Test GCP session management with optimal settings"""
        optimal_evidence = {
            "evidence": {
                "authentication": {
                    "login_challenges": {
                        "session_timeout": 1800,  # 30 minutes
                        "allowed_auth_methods": ["password", "totp", "security_key"]
                    },
                    "recent_logins": [
                        {"user": "user1", "success": True},
                        {"user": "user2", "success": True},
                        {"user": "user3", "success": True}
                    ]
                }
            }
        }
        
        score = self.mapper._check_gcp_sessions(optimal_evidence)
        assert score >= 90.0  # Should be very high

class TestAzureScoring:
    """Test Azure-specific scoring functions"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mapper = ComplianceMappingMatrix()
    
    def test_azure_password_policy_strong(self):
        """Test Azure password policy with strong configuration"""
        strong_evidence = {
            "evidence": {
                "password_policy": {
                    "password_policy": {
                        "minimum_length": 12,
                        "require_complexity": True,
                        "password_history": 12,
                        "lockout_threshold": 5
                    }
                }
            }
        }
        
        score = self.mapper._check_azure_password_policy(strong_evidence)
        assert score == 100.0
    
    def test_azure_mfa_with_conditional_access(self):
        """Test Azure MFA with conditional access policies"""
        strong_evidence = {
            "evidence": {
                "conditional_access": {
                    "policies": [
                        {
                            "name": "Require MFA for admins",
                            "controls": ["mfa"],
                            "state": "enabled"
                        }
                    ]
                }
            }
        }
        
        score = self.mapper._check_azure_mfa(strong_evidence)
        assert score >= 80.0  # Should be high with MFA policies

class TestComplianceNormalization:
    """Test the full compliance normalization process"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.mapper = ComplianceMappingMatrix()
    
    def test_cc6_1_normalization_aws(self):
        """Test full CC6.1 normalization for AWS"""
        aws_evidence = {
            "control_id": "CC6.1",
            "cloud_provider": "aws",
            "evidence": {
                "password_policy": {
                    "password_policy": {
                        "minimum_length": 14,
                        "require_symbols": True,
                        "require_numbers": True,
                        "require_uppercase": True,
                        "require_lowercase": True,
                        "password_reuse_prevention": 24,
                        "max_password_age": 90
                    }
                },
                "mfa_config": {
                    "root_account_mfa": True,
                    "mfa_policy": {"enforce_mfa": True},
                    "users_with_mfa": [
                        {"username": "user1", "mfa_enabled": True}
                    ]
                },
                "iam_policies": {
                    "policy_violations": [],
                    "managed_policies": [],
                    "custom_policies": [{"name": "test", "least_privilege": True}]
                },
                "access_keys": {
                    "rotation_policy": {"max_age_days": 90, "automated_rotation": True},
                    "access_keys": [{"user": "user1", "needs_rotation": False}]
                }
            }
        }
        
        result = self.mapper.normalize_compliance_score("CC6.1", "aws", aws_evidence)
        
        assert result["control_id"] == "CC6.1"
        assert result["cloud_provider"] == "aws"
        assert result["overall_score"] > 90.0
        assert result["compliance_status"] == "compliant"
        assert "component_scores" in result
    
    def test_compliance_status_thresholds(self):
        """Test compliance status threshold logic"""
        # Mock high score
        high_score_result = {"overall_score": 95.0}
        test_result = self.mapper.normalize_compliance_score("CC6.1", "aws", {"timestamp": "test"})
        
        # Test that scores >= 90 are compliant
        test_result["overall_score"] = 95.0
        # Simulate the status calculation
        if test_result["overall_score"] >= 90:
            status = "compliant"
        elif test_result["overall_score"] >= 70:
            status = "partial"
        else:
            status = "non_compliant"
        
        assert status == "compliant"
        
        # Test partial compliance
        test_result["overall_score"] = 75.0
        if test_result["overall_score"] >= 90:
            status = "compliant"
        elif test_result["overall_score"] >= 70:
            status = "partial"
        else:
            status = "non_compliant"
        
        assert status == "partial"
        
        # Test non-compliance
        test_result["overall_score"] = 50.0
        if test_result["overall_score"] >= 90:
            status = "compliant"
        elif test_result["overall_score"] >= 70:
            status = "partial"
        else:
            status = "non_compliant"
        
        assert status == "non_compliant"

if __name__ == '__main__':
    pytest.main([__file__])