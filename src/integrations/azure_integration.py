"""Microsoft Azure integration for AuditHound"""
import json
from typing import Dict, List, Any
from datetime import datetime

class AzureSecurityCollector:
    """Collects security and compliance data from Azure"""
    
    def __init__(self, tenant_id: str, subscription_id: str, client_id: str = None):
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        self.client_id = client_id
        self.client = None
    
    def authenticate(self):
        """Authenticate with Azure Security Center"""
        print(f"Authenticating with Azure tenant: {self.tenant_id}")
        return True
    
    def collect_aad_password_policy(self) -> Dict[str, Any]:
        """Collect Azure AD password policies"""
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "azure_aad",
            "data": {
                "password_policy": {
                    "minimum_length": 8,
                    "require_complexity": True,
                    "password_history": 5,
                    "max_age_days": 90,
                    "lockout_threshold": 5,
                    "lockout_duration_minutes": 30
                },
                "users": [
                    {"upn": "admin@company.onmicrosoft.com", "mfa_enabled": True, "last_login": "2024-06-15"},
                    {"upn": "user@company.onmicrosoft.com", "mfa_enabled": False, "last_login": "2024-06-14"}
                ]
            }
        }
    
    def collect_conditional_access(self) -> Dict[str, Any]:
        """Collect conditional access policies"""
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "azure_conditional_access",
            "data": {
                "policies": [
                    {
                        "name": "Require MFA for admins",
                        "state": "enabled",
                        "users": ["admin_group"],
                        "conditions": ["any_location"],
                        "controls": ["mfa"]
                    },
                    {
                        "name": "Block legacy authentication",
                        "state": "enabled",
                        "users": ["all_users"],
                        "conditions": ["legacy_auth"],
                        "controls": ["block"]
                    }
                ]
            }
        }
    
    def collect_storage_accounts(self) -> Dict[str, Any]:
        """Collect Azure Storage account configurations"""
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "azure_storage",
            "data": {
                "storage_accounts": [
                    {
                        "name": "companystorage001",
                        "public_access": False,
                        "encryption_at_rest": True,
                        "encryption_in_transit": True,
                        "access_tier": "hot",
                        "backup_enabled": True
                    },
                    {
                        "name": "publicassets002",
                        "public_access": True,
                        "encryption_at_rest": True,
                        "encryption_in_transit": False,
                        "access_tier": "cool",
                        "backup_enabled": False
                    }
                ]
            }
        }
    
    def collect_network_security_groups(self) -> Dict[str, Any]:
        """Collect Network Security Group configurations"""
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "azure_network",
            "data": {
                "network_security_groups": [
                    {
                        "name": "web-nsg",
                        "rules": [
                            {"name": "allow-http", "direction": "inbound", "port": "80", "source": "internet"},
                            {"name": "allow-https", "direction": "inbound", "port": "443", "source": "internet"},
                            {"name": "deny-all", "direction": "inbound", "port": "*", "source": "*", "priority": 4096}
                        ]
                    }
                ],
                "virtual_networks": [
                    {
                        "name": "company-vnet",
                        "address_space": "10.0.0.0/16",
                        "subnets": ["web-subnet", "db-subnet"]
                    }
                ]
            }
        }
    
    def collect_role_assignments(self) -> Dict[str, Any]:
        """Collect Azure RBAC role assignments"""
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "azure_rbac",
            "data": {
                "role_assignments": [
                    {"principal": "admin@company.com", "role": "Owner", "scope": "subscription"},
                    {"principal": "dev@company.com", "role": "Contributor", "scope": "resource_group"},
                    {"principal": "viewer@company.com", "role": "Reader", "scope": "resource"}
                ]
            }
        }
    
    def collect_soc2_cc6_1_evidence(self) -> Dict[str, Any]:
        """Collect evidence for SOC2 CC6.1 - Logical Access Controls"""
        password_data = self.collect_aad_password_policy()
        conditional_access_data = self.collect_conditional_access()
        rbac_data = self.collect_role_assignments()
        
        return {
            "control_id": "CC6.1",
            "description": "Logical Access Controls",
            "framework": "SOC2",
            "cloud_provider": "azure",
            "evidence": {
                "password_policy": password_data["data"],
                "conditional_access": conditional_access_data["data"],
                "role_assignments": rbac_data["data"],
                "compliance_score": self._calculate_cc6_1_score(password_data, conditional_access_data, rbac_data)
            }
        }
    
    def _calculate_cc6_1_score(self, password_data: Dict, conditional_access_data: Dict, rbac_data: Dict) -> float:
        """Calculate compliance score for CC6.1"""
        score = 0.0
        max_score = 4.0
        
        # Check password complexity
        if password_data["data"]["password_policy"]["require_complexity"]:
            score += 1.0
        
        # Check MFA policies
        mfa_policies = [p for p in conditional_access_data["data"]["policies"] 
                      if "mfa" in p.get("controls", [])]
        if len(mfa_policies) > 0:
            score += 1.0
        
        # Check legacy auth blocking
        legacy_block_policies = [p for p in conditional_access_data["data"]["policies"] 
                               if "legacy_auth" in p.get("conditions", []) and "block" in p.get("controls", [])]
        if len(legacy_block_policies) > 0:
            score += 1.0
        
        # Check role-based access
        if len(rbac_data["data"]["role_assignments"]) > 0:
            score += 1.0
        
        return (score / max_score) * 100