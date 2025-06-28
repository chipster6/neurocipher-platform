#!/usr/bin/env python3
"""
Multi-Tenant Manager for AuditHound
Handles client separation, organization management, and tenant-specific filtering
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from enum import Enum
import uuid

from .unified_models import SecurityAsset, UnifiedFinding, ScanResult

logger = logging.getLogger(__name__)

class TenantTier(Enum):
    """Tenant service tier levels"""
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    MSP = "msp"  # Managed Service Provider

class TenantStatus(Enum):
    """Tenant account status"""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TRIAL = "trial"
    EXPIRED = "expired"

@dataclass
class TenantProfile:
    """Tenant/Client profile with organizational metadata"""
    client_id: str
    organization_name: str
    tier: TenantTier
    status: TenantStatus
    
    # Contact information
    primary_contact: str
    email: str
    phone: Optional[str] = None
    
    # Service configuration
    max_assets: int = 100
    max_scans_per_month: int = 50
    enabled_features: List[str] = field(default_factory=list)
    cloud_providers: List[str] = field(default_factory=list)
    compliance_frameworks: List[str] = field(default_factory=list)
    
    # Billing and usage
    created_at: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    trial_expires: Optional[datetime] = None
    monthly_usage: Dict[str, int] = field(default_factory=dict)
    
    # Multi-tenant organization structure
    departments: List[str] = field(default_factory=list)
    cost_centers: List[str] = field(default_factory=list)
    
    # Security settings
    sso_enabled: bool = False
    mfa_required: bool = False
    ip_whitelist: List[str] = field(default_factory=list)
    
    # Data retention and compliance
    data_retention_days: int = 365
    compliance_contact: Optional[str] = None
    
    def is_feature_enabled(self, feature: str) -> bool:
        """Check if a feature is enabled for this tenant"""
        return feature in self.enabled_features
    
    def can_create_scan(self) -> bool:
        """Check if tenant can create new scans based on usage limits"""
        current_scans = self.monthly_usage.get('scans', 0)
        return current_scans < self.max_scans_per_month
    
    def can_add_assets(self, count: int = 1) -> bool:
        """Check if tenant can add more assets"""
        current_assets = self.monthly_usage.get('assets', 0)
        return (current_assets + count) <= self.max_assets
    
    def update_usage(self, metric: str, increment: int = 1):
        """Update tenant usage metrics"""
        if metric not in self.monthly_usage:
            self.monthly_usage[metric] = 0
        self.monthly_usage[metric] += increment

class MultiTenantManager:
    """
    Manages multi-tenant separation and organization filtering
    """
    
    def __init__(self):
        """Initialize multi-tenant manager"""
        self.tenants: Dict[str, TenantProfile] = {}
        self.default_features = {
            TenantTier.STARTER: [
                'compliance_auditing', 'basic_reporting', 'email_notifications'
            ],
            TenantTier.PROFESSIONAL: [
                'compliance_auditing', 'threat_hunting', 'advanced_reporting',
                'email_notifications', 'chat_notifications', 'api_access'
            ],
            TenantTier.ENTERPRISE: [
                'compliance_auditing', 'threat_hunting', 'advanced_reporting',
                'email_notifications', 'chat_notifications', 'api_access',
                'misp_integration', 'thehive_integration', 'custom_rules',
                'sso_integration', 'audit_logs'
            ],
            TenantTier.MSP: [
                'compliance_auditing', 'threat_hunting', 'advanced_reporting',
                'email_notifications', 'chat_notifications', 'api_access',
                'misp_integration', 'thehive_integration', 'custom_rules',
                'sso_integration', 'audit_logs', 'white_label', 'multi_tenant_management'
            ]
        }
        
        logger.info("Multi-tenant manager initialized")
    
    def create_tenant(self, organization_name: str, email: str, tier: TenantTier = TenantTier.STARTER) -> str:
        """
        Create new tenant profile
        
        Args:
            organization_name: Organization name
            email: Primary contact email
            tier: Service tier level
            
        Returns:
            Generated client_id
        """
        client_id = f"client_{uuid.uuid4().hex[:8]}"
        
        # Set limits based on tier
        limits = self._get_tier_limits(tier)
        
        tenant = TenantProfile(
            client_id=client_id,
            organization_name=organization_name,
            tier=tier,
            status=TenantStatus.TRIAL if tier == TenantTier.STARTER else TenantStatus.ACTIVE,
            primary_contact=email,
            email=email,
            max_assets=limits['max_assets'],
            max_scans_per_month=limits['max_scans'],
            enabled_features=self.default_features.get(tier, []),
            trial_expires=datetime.now() + timedelta(days=14) if tier == TenantTier.STARTER else None
        )
        
        self.tenants[client_id] = tenant
        
        logger.info(f"Created tenant: {client_id} ({organization_name})")
        return client_id
    
    def get_tenant(self, client_id: str) -> Optional[TenantProfile]:
        """Get tenant profile by client_id"""
        return self.tenants.get(client_id)
    
    def get_tenant_context(self, client_id: str) -> Dict[str, Any]:
        """Get tenant context for API operations"""
        tenant = self.get_tenant(client_id)
        if not tenant:
            return {}
        
        return {
            'client_id': client_id,
            'organization_name': tenant.organization_name,
            'tier': tenant.tier.value,
            'status': tenant.status.value,
            'enabled_features': tenant.enabled_features,
            'usage_limits': {
                'max_assets': tenant.max_assets,
                'max_scans_per_month': tenant.max_scans_per_month,
                'current_usage': tenant.monthly_usage
            }
        }
    
    def filter_assets_by_tenant(self, assets: List[SecurityAsset], client_id: str, 
                               department: Optional[str] = None, 
                               cost_center: Optional[str] = None) -> List[SecurityAsset]:
        """
        Filter assets by tenant and optional organizational filters
        
        Args:
            assets: List of assets to filter
            client_id: Tenant identifier
            department: Optional department filter
            cost_center: Optional cost center filter
            
        Returns:
            Filtered list of assets
        """
        filtered_assets = []
        
        for asset in assets:
            # Basic tenant filtering
            if asset.client_id != client_id:
                continue
            
            # Department filtering
            if department and asset.department != department:
                continue
            
            # Cost center filtering
            if cost_center and asset.cost_center != cost_center:
                continue
            
            filtered_assets.append(asset)
        
        return filtered_assets
    
    def filter_findings_by_tenant(self, findings: List[UnifiedFinding], client_id: str,
                                 severity_filter: Optional[str] = None,
                                 finding_type_filter: Optional[str] = None) -> List[UnifiedFinding]:
        """
        Filter findings by tenant with additional filters
        
        Args:
            findings: List of findings to filter
            client_id: Tenant identifier
            severity_filter: Optional severity filter
            finding_type_filter: Optional finding type filter
            
        Returns:
            Filtered list of findings
        """
        filtered_findings = []
        
        for finding in findings:
            # Basic tenant filtering
            if finding.client_id != client_id:
                continue
            
            # Severity filtering
            if severity_filter and finding.severity.value != severity_filter:
                continue
            
            # Finding type filtering
            if finding_type_filter and finding.finding_type != finding_type_filter:
                continue
            
            filtered_findings.append(finding)
        
        return filtered_findings
    
    def filter_scans_by_tenant(self, scans: List[ScanResult], client_id: str) -> List[ScanResult]:
        """Filter scan results by tenant"""
        return [scan for scan in scans if scan.client_id == client_id]
    
    def get_tenant_usage_summary(self, client_id: str) -> Dict[str, Any]:
        """Get comprehensive usage summary for tenant"""
        tenant = self.get_tenant(client_id)
        if not tenant:
            return {}
        
        current_month = datetime.now().strftime('%Y-%m')
        usage = tenant.monthly_usage
        
        return {
            'client_id': client_id,
            'organization_name': tenant.organization_name,
            'tier': tenant.tier.value,
            'status': tenant.status.value,
            'current_month': current_month,
            'usage': {
                'assets': {
                    'current': usage.get('assets', 0),
                    'limit': tenant.max_assets,
                    'percentage': (usage.get('assets', 0) / tenant.max_assets) * 100
                },
                'scans': {
                    'current': usage.get('scans', 0),
                    'limit': tenant.max_scans_per_month,
                    'percentage': (usage.get('scans', 0) / tenant.max_scans_per_month) * 100
                },
                'findings': usage.get('findings', 0),
                'api_calls': usage.get('api_calls', 0)
            },
            'trial_info': {
                'is_trial': tenant.status == TenantStatus.TRIAL,
                'expires': tenant.trial_expires.isoformat() if tenant.trial_expires else None,
                'days_remaining': (tenant.trial_expires - datetime.now()).days if tenant.trial_expires else None
            }
        }
    
    def validate_tenant_access(self, client_id: str, feature: str) -> bool:
        """
        Validate if tenant has access to specific feature
        
        Args:
            client_id: Tenant identifier
            feature: Feature to check access for
            
        Returns:
            True if tenant has access, False otherwise
        """
        tenant = self.get_tenant(client_id)
        if not tenant:
            return False
        
        # Check tenant status
        if tenant.status not in [TenantStatus.ACTIVE, TenantStatus.TRIAL]:
            return False
        
        # Check trial expiration
        if tenant.status == TenantStatus.TRIAL and tenant.trial_expires:
            if datetime.now() > tenant.trial_expires:
                return False
        
        # Check feature access
        return tenant.is_feature_enabled(feature)
    
    def get_organizations_for_msp(self, msp_client_id: str) -> List[Dict[str, Any]]:
        """Get all organizations managed by an MSP tenant"""
        msp_tenant = self.get_tenant(msp_client_id)
        if not msp_tenant or msp_tenant.tier != TenantTier.MSP:
            return []
        
        # For MSP tenants, return all managed organizations
        managed_orgs = []
        for client_id, tenant in self.tenants.items():
            if client_id != msp_client_id:  # Exclude the MSP itself
                managed_orgs.append({
                    'client_id': client_id,
                    'organization_name': tenant.organization_name,
                    'status': tenant.status.value,
                    'tier': tenant.tier.value,
                    'asset_count': tenant.monthly_usage.get('assets', 0),
                    'last_scan': tenant.monthly_usage.get('last_scan_date'),
                    'compliance_score': tenant.monthly_usage.get('compliance_score', 0)
                })
        
        return managed_orgs
    
    def update_tenant_tier(self, client_id: str, new_tier: TenantTier):
        """Update tenant service tier and adjust limits/features"""
        tenant = self.get_tenant(client_id)
        if not tenant:
            return False
        
        # Update tier and features
        tenant.tier = new_tier
        tenant.enabled_features = self.default_features.get(new_tier, [])
        
        # Update limits
        limits = self._get_tier_limits(new_tier)
        tenant.max_assets = limits['max_assets']
        tenant.max_scans_per_month = limits['max_scans']
        
        # Update status if upgrading from trial
        if tenant.status == TenantStatus.TRIAL and new_tier != TenantTier.STARTER:
            tenant.status = TenantStatus.ACTIVE
            tenant.trial_expires = None
        
        logger.info(f"Updated tenant {client_id} to tier {new_tier.value}")
        return True
    
    def _get_tier_limits(self, tier: TenantTier) -> Dict[str, int]:
        """Get resource limits for tier"""
        limits = {
            TenantTier.STARTER: {'max_assets': 25, 'max_scans': 10},
            TenantTier.PROFESSIONAL: {'max_assets': 100, 'max_scans': 50},
            TenantTier.ENTERPRISE: {'max_assets': 500, 'max_scans': 200},
            TenantTier.MSP: {'max_assets': 10000, 'max_scans': 1000}
        }
        return limits.get(tier, {'max_assets': 25, 'max_scans': 10})
    
    def export_tenant_data(self, client_id: str, include_findings: bool = True) -> Dict[str, Any]:
        """Export all tenant data for compliance/backup purposes"""
        tenant = self.get_tenant(client_id)
        if not tenant:
            return {}
        
        export_data = {
            'tenant_profile': {
                'client_id': tenant.client_id,
                'organization_name': tenant.organization_name,
                'tier': tenant.tier.value,
                'status': tenant.status.value,
                'created_at': tenant.created_at.isoformat(),
                'contact_info': {
                    'primary_contact': tenant.primary_contact,
                    'email': tenant.email,
                    'phone': tenant.phone
                }
            },
            'configuration': {
                'enabled_features': tenant.enabled_features,
                'cloud_providers': tenant.cloud_providers,
                'compliance_frameworks': tenant.compliance_frameworks,
                'departments': tenant.departments,
                'cost_centers': tenant.cost_centers
            },
            'usage_summary': self.get_tenant_usage_summary(client_id),
            'export_timestamp': datetime.now().isoformat()
        }
        
        return export_data

# Global tenant manager instance
tenant_manager = MultiTenantManager()

def get_tenant_manager() -> MultiTenantManager:
    """Get global tenant manager instance"""
    return tenant_manager

# Utility functions for tenant operations
def get_client_id_from_request(request) -> str:
    """Extract client_id from request headers or session"""
    # Check headers first
    client_id = request.headers.get('X-Client-ID')
    if client_id:
        return client_id
    
    # Check session
    client_id = request.session.get('client_id')
    if client_id:
        return client_id
    
    # Check URL parameters
    client_id = request.args.get('client_id')
    if client_id:
        return client_id
    
    # Default fallback
    return "default"

def require_feature(feature: str):
    """Decorator to require specific feature access"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # This would be implemented with proper Flask request context
            # For now, return the function as-is
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Example usage and testing
if __name__ == "__main__":
    # Test multi-tenant manager
    manager = MultiTenantManager()
    
    # Create test tenants
    client1 = manager.create_tenant("Acme Corp", "admin@acme.com", TenantTier.ENTERPRISE)
    client2 = manager.create_tenant("StartupXYZ", "cto@startup.com", TenantTier.PROFESSIONAL)
    client3 = manager.create_tenant("MSP Solutions", "ops@msp.com", TenantTier.MSP)
    
    print(f"Created tenants: {client1}, {client2}, {client3}")
    
    # Test usage tracking
    tenant1 = manager.get_tenant(client1)
    tenant1.update_usage('assets', 10)
    tenant1.update_usage('scans', 3)
    
    # Test usage summary
    usage = manager.get_tenant_usage_summary(client1)
    print(f"Tenant 1 usage: {json.dumps(usage, indent=2)}")
    
    # Test feature validation
    has_misp = manager.validate_tenant_access(client1, 'misp_integration')
    print(f"Tenant 1 has MISP access: {has_misp}")
    
    print("✅ Multi-tenant manager test completed successfully")