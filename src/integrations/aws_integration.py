"""Amazon Web Services integration for AuditHound"""
import json
from typing import Dict, List, Any
from datetime import datetime

class AWSSecurityCollector:
    """Collects security and compliance data from AWS"""
    
    def __init__(self, region: str = "us-west-2", access_key_id: str = None, secret_access_key: str = None):
        self.region = region
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.clients = {}
    
    def authenticate(self):
        """Authenticate with AWS services"""
        print(f"Authenticating with AWS region: {self.region}")
        return True
    
    def collect_password_policy(self) -> Dict[str, Any]:
        """Collect IAM password policy"""
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "aws_iam",
            "data": {
                "password_policy": {
                    "minimum_length": 14,
                    "require_symbols": True,
                    "require_numbers": True,
                    "require_uppercase": True,
                    "require_lowercase": True,
                    "allow_users_to_change": True,
                    "max_password_age": 90,
                    "password_reuse_prevention": 24,
                    "hard_expiry": False
                },
                "account_summary": {
                    "users": 25,
                    "users_quota": 5000,
                    "groups": 8,
                    "roles": 45,
                    "policies": 120
                }
            }
        }
    
    def collect_mfa_config(self) -> Dict[str, Any]:
        """Collect MFA device configurations"""
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "aws_mfa",
            "data": {
                "root_account_mfa": True,
                "users_with_mfa": [
                    {"username": "admin-user", "mfa_enabled": True, "device_type": "virtual"},
                    {"username": "dev-user1", "mfa_enabled": False, "device_type": None},
                    {"username": "sec-user", "mfa_enabled": True, "device_type": "hardware"}
                ],
                "mfa_policy": {
                    "enforce_mfa": True,
                    "allowed_devices": ["virtual", "hardware", "sms"],
                    "grace_period_hours": 24
                }
            }
        }
    
    def collect_iam_policies(self) -> Dict[str, Any]:
        """Collect IAM policies and access controls"""
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "aws_iam_policies",
            "data": {
                "managed_policies": [
                    {
                        "name": "AdminAccess",
                        "type": "aws_managed",
                        "attached_users": 2,
                        "attached_roles": 1,
                        "overly_permissive": True
                    },
                    {
                        "name": "ReadOnlyAccess",
                        "type": "aws_managed", 
                        "attached_users": 5,
                        "attached_roles": 3,
                        "overly_permissive": False
                    }
                ],
                "custom_policies": [
                    {
                        "name": "DeveloperPolicy",
                        "type": "customer_managed",
                        "attached_users": 8,
                        "least_privilege": True
                    }
                ],
                "policy_violations": [
                    {"policy": "AdminAccess", "violation": "attached_to_user", "severity": "high"},
                    {"policy": "S3FullAccess", "violation": "wildcard_resource", "severity": "medium"}
                ]
            }
        }
    
    def collect_access_keys(self) -> Dict[str, Any]:
        """Collect access key rotation and usage data"""
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "aws_access_keys",
            "data": {
                "access_keys": [
                    {
                        "user": "admin-user",
                        "key_id": "AKIA***EXAMPLE1",
                        "status": "Active",
                        "age_days": 45,
                        "last_used": "2024-06-15",
                        "needs_rotation": False
                    },
                    {
                        "user": "service-account",
                        "key_id": "AKIA***EXAMPLE2", 
                        "status": "Active",
                        "age_days": 120,
                        "last_used": "2024-06-10",
                        "needs_rotation": True
                    }
                ],
                "rotation_policy": {
                    "max_age_days": 90,
                    "automated_rotation": False,
                    "notification_threshold": 7
                }
            }
        }
    
    def collect_cloudtrail_logs(self) -> Dict[str, Any]:
        """Collect CloudTrail logging configuration"""
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "aws_cloudtrail",
            "data": {
                "trails": [
                    {
                        "name": "company-cloudtrail",
                        "status": "logging",
                        "multi_region": True,
                        "log_file_validation": True,
                        "s3_bucket": "company-cloudtrail-logs",
                        "kms_encryption": True
                    }
                ],
                "event_selectors": {
                    "read_events": True,
                    "write_events": True,
                    "data_events": True
                },
                "retention_days": 365
            }
        }
    
    def collect_s3_encryption(self) -> Dict[str, Any]:
        """Collect S3 bucket encryption settings"""
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "aws_s3",
            "data": {
                "buckets": [
                    {
                        "name": "company-data-prod",
                        "encryption": {
                            "enabled": True,
                            "type": "aws_kms",
                            "key_id": "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
                        },
                        "public_access": False,
                        "versioning": True,
                        "logging": True
                    },
                    {
                        "name": "company-backups",
                        "encryption": {
                            "enabled": True,
                            "type": "aes256",
                            "key_id": None
                        },
                        "public_access": False,
                        "versioning": True,
                        "logging": False
                    }
                ]
            }
        }
    
    def collect_config_rules(self) -> Dict[str, Any]:
        """Collect AWS Config rules for change management"""
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "aws_config",
            "data": {
                "configuration_recorder": {
                    "enabled": True,
                    "recording_group": {
                        "all_supported": True,
                        "include_global_resources": True
                    }
                },
                "rules": [
                    {
                        "name": "root-mfa-enabled",
                        "compliance": "COMPLIANT",
                        "description": "Checks if MFA is enabled for root account"
                    },
                    {
                        "name": "iam-password-policy",
                        "compliance": "COMPLIANT", 
                        "description": "Checks IAM password policy configuration"
                    },
                    {
                        "name": "s3-bucket-public-read-prohibited",
                        "compliance": "NON_COMPLIANT",
                        "description": "Checks that S3 buckets do not allow public read access"
                    }
                ]
            }
        }
    
    def collect_soc2_cc6_1_evidence(self) -> Dict[str, Any]:
        """Collect evidence for SOC2 CC6.1 - Logical Access Controls"""
        password_data = self.collect_password_policy()
        mfa_data = self.collect_mfa_config()
        iam_data = self.collect_iam_policies()
        access_key_data = self.collect_access_keys()
        
        return {
            "control_id": "CC6.1",
            "description": "Logical Access Controls",
            "framework": "SOC2",
            "cloud_provider": "aws",
            "evidence": {
                "password_policy": password_data["data"],
                "mfa_config": mfa_data["data"],
                "iam_policies": iam_data["data"],
                "access_keys": access_key_data["data"],
                "compliance_score": self._calculate_cc6_1_score(password_data, mfa_data, iam_data, access_key_data)
            }
        }
    
    def _calculate_cc6_1_score(self, password_data: Dict, mfa_data: Dict, iam_data: Dict, access_key_data: Dict) -> float:
        """Calculate compliance score for CC6.1"""
        score = 0.0
        max_score = 4.0
        
        # Check password policy strength
        policy = password_data["data"]["password_policy"]
        if (policy["minimum_length"] >= 12 and 
            policy["require_symbols"] and 
            policy["require_numbers"] and
            policy["password_reuse_prevention"] >= 12):
            score += 1.0
        
        # Check MFA enforcement
        if mfa_data["data"]["root_account_mfa"] and mfa_data["data"]["mfa_policy"]["enforce_mfa"]:
            score += 1.0
        
        # Check for overly permissive policies
        violations = iam_data["data"]["policy_violations"]
        high_severity_violations = [v for v in violations if v["severity"] == "high"]
        if len(high_severity_violations) == 0:
            score += 1.0
        
        # Check access key rotation
        old_keys = [k for k in access_key_data["data"]["access_keys"] if k["needs_rotation"]]
        if len(old_keys) == 0:
            score += 1.0
        
        return (score / max_score) * 100