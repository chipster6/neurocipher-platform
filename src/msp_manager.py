#!/usr/bin/env python3
"""
MSP (Managed Service Provider) Management System
Handles multi-tenant client management, white-label branding, and MSP operations
"""

import logging
import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
# import yaml  # Not needed for core functionality
import secrets

logger = logging.getLogger(__name__)

class MSPTier(Enum):
    """MSP service tier levels"""
    BASIC = "basic"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    WHITE_LABEL = "white_label"

class ClientStatus(Enum):
    """Client account status"""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TRIAL = "trial"
    EXPIRED = "expired"
    PENDING = "pending"

@dataclass
class WhiteLabelConfig:
    """White-label branding configuration"""
    enabled: bool = False
    company_name: str = ""
    logo_primary: str = ""
    logo_secondary: str = ""
    favicon: str = ""
    
    # Color scheme
    primary_color: str = "#1f77b4"
    secondary_color: str = "#ff7f0e"
    accent_color: str = "#2ca02c"
    background_color: str = "#ffffff"
    text_color: str = "#212529"
    
    # Contact information
    support_email: str = ""
    support_phone: str = ""
    website_url: str = ""
    
    # Custom styling
    custom_css: str = ""
    footer_text: str = ""
    
    # Feature visibility
    hide_audithound_branding: bool = False
    custom_domain: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "enabled": self.enabled,
            "company_name": self.company_name,
            "logo_primary": self.logo_primary,
            "logo_secondary": self.logo_secondary,
            "favicon": self.favicon,
            "primary_color": self.primary_color,
            "secondary_color": self.secondary_color,
            "accent_color": self.accent_color,
            "background_color": self.background_color,
            "text_color": self.text_color,
            "support_email": self.support_email,
            "support_phone": self.support_phone,
            "website_url": self.website_url,
            "custom_css": self.custom_css,
            "footer_text": self.footer_text,
            "hide_audithound_branding": self.hide_audithound_branding,
            "custom_domain": self.custom_domain
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WhiteLabelConfig':
        """Create from dictionary"""
        return cls(**data)

@dataclass
class MSPClient:
    """MSP client configuration"""
    client_id: str
    organization_name: str
    tier: MSPTier
    status: ClientStatus
    
    # Contact information
    primary_contact: str
    email: str
    phone: Optional[str] = None
    
    # Billing and subscription
    billing_contact: Optional[str] = None
    subscription_start: datetime = field(default_factory=datetime.now)
    subscription_end: Optional[datetime] = None
    trial_expires: Optional[datetime] = None
    
    # Service configuration
    enabled_frameworks: List[str] = field(default_factory=list)
    cloud_providers: List[str] = field(default_factory=list)
    max_assets: int = 100
    max_scans_per_month: int = 50
    max_users: int = 5
    
    # Features and permissions
    enabled_features: List[str] = field(default_factory=list)
    api_access: bool = False
    custom_reports: bool = False
    priority_support: bool = False
    
    # White-label configuration
    white_label: Optional[WhiteLabelConfig] = None
    
    # Usage tracking
    current_assets: int = 0
    current_scans: int = 0
    current_users: int = 1
    last_scan_date: Optional[datetime] = None
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    created_by: str = ""
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    
    # Client-specific settings
    custom_settings: Dict[str, Any] = field(default_factory=dict)
    
    def is_trial(self) -> bool:
        """Check if client is on trial"""
        return self.status == ClientStatus.TRIAL
    
    def is_active(self) -> bool:
        """Check if client is active"""
        return self.status in [ClientStatus.ACTIVE, ClientStatus.TRIAL]
    
    def is_expired(self) -> bool:
        """Check if client subscription is expired"""
        if self.subscription_end:
            return datetime.now() > self.subscription_end
        if self.trial_expires and self.is_trial():
            return datetime.now() > self.trial_expires
        return False
    
    def can_perform_scan(self) -> bool:
        """Check if client can perform new scan"""
        return (self.is_active() and 
                not self.is_expired() and 
                self.current_scans < self.max_scans_per_month)
    
    def can_add_assets(self, count: int = 1) -> bool:
        """Check if client can add more assets"""
        return (self.is_active() and 
                not self.is_expired() and 
                (self.current_assets + count) <= self.max_assets)
    
    def update_usage(self, scans: int = 0, assets: int = 0, users: int = 0):
        """Update usage counters"""
        self.current_scans += scans
        self.current_assets += assets
        self.current_users += users
        
        if scans > 0:
            self.last_scan_date = datetime.now()
        
        self.updated_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "client_id": self.client_id,
            "organization_name": self.organization_name,
            "tier": self.tier.value,
            "status": self.status.value,
            "primary_contact": self.primary_contact,
            "email": self.email,
            "phone": self.phone,
            "billing_contact": self.billing_contact,
            "subscription_start": self.subscription_start.isoformat(),
            "subscription_end": self.subscription_end.isoformat() if self.subscription_end else None,
            "trial_expires": self.trial_expires.isoformat() if self.trial_expires else None,
            "enabled_frameworks": self.enabled_frameworks,
            "cloud_providers": self.cloud_providers,
            "max_assets": self.max_assets,
            "max_scans_per_month": self.max_scans_per_month,
            "max_users": self.max_users,
            "enabled_features": self.enabled_features,
            "api_access": self.api_access,
            "custom_reports": self.custom_reports,
            "priority_support": self.priority_support,
            "white_label": self.white_label.to_dict() if self.white_label else None,
            "current_assets": self.current_assets,
            "current_scans": self.current_scans,
            "current_users": self.current_users,
            "last_scan_date": self.last_scan_date.isoformat() if self.last_scan_date else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "created_by": self.created_by,
            "tags": self.tags,
            "notes": self.notes,
            "custom_settings": self.custom_settings
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MSPClient':
        """Create from dictionary"""
        # Handle datetime fields
        if isinstance(data.get('subscription_start'), str):
            data['subscription_start'] = datetime.fromisoformat(data['subscription_start'])
        if data.get('subscription_end'):
            data['subscription_end'] = datetime.fromisoformat(data['subscription_end'])
        if data.get('trial_expires'):
            data['trial_expires'] = datetime.fromisoformat(data['trial_expires'])
        if data.get('last_scan_date'):
            data['last_scan_date'] = datetime.fromisoformat(data['last_scan_date'])
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if isinstance(data.get('updated_at'), str):
            data['updated_at'] = datetime.fromisoformat(data['updated_at'])
        
        # Handle enum fields
        if isinstance(data.get('tier'), str):
            data['tier'] = MSPTier(data['tier'])
        if isinstance(data.get('status'), str):
            data['status'] = ClientStatus(data['status'])
        
        # Handle white label config
        if data.get('white_label'):
            data['white_label'] = WhiteLabelConfig.from_dict(data['white_label'])
        
        return cls(**data)

class MSPManager:
    """
    MSP Manager handles multi-tenant client management, billing, and white-label branding
    """
    
    def __init__(self, install_dir: str = None):
        """Initialize MSP Manager"""
        self.install_dir = Path(install_dir) if install_dir else Path.cwd()
        self.clients: Dict[str, MSPClient] = {}
        self.msp_config: Dict[str, Any] = {}
        
        # Paths
        self.clients_dir = self.install_dir / "tenants"
        self.msp_config_dir = self.install_dir / "msp-configs"
        self.white_label_dir = self.install_dir / "white-label"
        
        # Create directories if they don't exist
        self.clients_dir.mkdir(parents=True, exist_ok=True)
        self.msp_config_dir.mkdir(parents=True, exist_ok=True)
        self.white_label_dir.mkdir(parents=True, exist_ok=True)
        
        # Load existing data
        self.load_msp_config()
        self.load_clients()
        
        logger.info(f"MSP Manager initialized with {len(self.clients)} clients")
    
    def load_msp_config(self):
        """Load MSP configuration"""
        config_path = self.msp_config_dir / "msp_config.json"
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    self.msp_config = json.load(f)
                logger.info("MSP configuration loaded")
            except Exception as e:
                logger.error(f"Failed to load MSP config: {e}")
        else:
            # Create default MSP configuration
            self.msp_config = {
                "company_name": "Your MSP Company",
                "contact_email": "support@yourmsp.com",
                "website": "https://yourmsp.com",
                "default_tier": MSPTier.PROFESSIONAL.value,
                "trial_period_days": 14,
                "features": {
                    MSPTier.BASIC.value: [
                        "compliance_auditing", "basic_reporting", "email_notifications"
                    ],
                    MSPTier.PROFESSIONAL.value: [
                        "compliance_auditing", "threat_hunting", "advanced_reporting",
                        "email_notifications", "chat_notifications", "api_access"
                    ],
                    MSPTier.ENTERPRISE.value: [
                        "compliance_auditing", "threat_hunting", "advanced_reporting",
                        "email_notifications", "chat_notifications", "api_access",
                        "custom_rules", "priority_support", "audit_logs"
                    ],
                    MSPTier.WHITE_LABEL.value: [
                        "compliance_auditing", "threat_hunting", "advanced_reporting",
                        "email_notifications", "chat_notifications", "api_access",
                        "custom_rules", "priority_support", "audit_logs",
                        "white_label_branding", "custom_domain", "api_whitelabeling"
                    ]
                },
                "limits": {
                    MSPTier.BASIC.value: {
                        "max_assets": 50,
                        "max_scans": 25,
                        "max_users": 3
                    },
                    MSPTier.PROFESSIONAL.value: {
                        "max_assets": 200,
                        "max_scans": 100,
                        "max_users": 10
                    },
                    MSPTier.ENTERPRISE.value: {
                        "max_assets": 1000,
                        "max_scans": 500,
                        "max_users": 50
                    },
                    MSPTier.WHITE_LABEL.value: {
                        "max_assets": 5000,
                        "max_scans": 2000,
                        "max_users": 100
                    }
                }
            }
            self.save_msp_config()
    
    def save_msp_config(self):
        """Save MSP configuration"""
        config_path = self.msp_config_dir / "msp_config.json"
        try:
            with open(config_path, 'w') as f:
                json.dump(self.msp_config, f, indent=2)
            logger.info("MSP configuration saved")
        except Exception as e:
            logger.error(f"Failed to save MSP config: {e}")
    
    def load_clients(self):
        """Load all client configurations"""
        if not self.clients_dir.exists():
            return
        
        for client_dir in self.clients_dir.iterdir():
            if client_dir.is_dir():
                config_file = client_dir / "config" / "client_config.json"
                if config_file.exists():
                    try:
                        with open(config_file, 'r') as f:
                            client_data = json.load(f)
                        
                        client = MSPClient.from_dict(client_data)
                        self.clients[client.client_id] = client
                        
                    except Exception as e:
                        logger.error(f"Failed to load client {client_dir.name}: {e}")
        
        logger.info(f"Loaded {len(self.clients)} clients")
    
    def create_client(self, organization_name: str, email: str, 
                     tier: MSPTier = None, trial: bool = True,
                     white_label_config: WhiteLabelConfig = None) -> str:
        """
        Create new MSP client
        
        Args:
            organization_name: Client organization name
            email: Primary contact email
            tier: Service tier (defaults to MSP config default)
            trial: Whether to start as trial
            white_label_config: White-label branding configuration
            
        Returns:
            Generated client_id
        """
        client_id = f"client_{uuid.uuid4().hex[:8]}"
        
        if tier is None:
            tier = MSPTier(self.msp_config.get("default_tier", MSPTier.PROFESSIONAL.value))
        
        # Get tier limits
        limits = self.msp_config["limits"].get(tier.value, {})
        features = self.msp_config["features"].get(tier.value, [])
        
        # Create client configuration
        client = MSPClient(
            client_id=client_id,
            organization_name=organization_name,
            tier=tier,
            status=ClientStatus.TRIAL if trial else ClientStatus.ACTIVE,
            primary_contact=email.split('@')[0].replace('.', ' ').title(),
            email=email,
            enabled_frameworks=["SOC2"],  # Default framework
            cloud_providers=["aws", "gcp", "azure"],  # All providers enabled
            max_assets=limits.get("max_assets", 100),
            max_scans_per_month=limits.get("max_scans", 50),
            max_users=limits.get("max_users", 5),
            enabled_features=features,
            api_access=tier in [MSPTier.PROFESSIONAL, MSPTier.ENTERPRISE, MSPTier.WHITE_LABEL],
            custom_reports=tier in [MSPTier.ENTERPRISE, MSPTier.WHITE_LABEL],
            priority_support=tier in [MSPTier.ENTERPRISE, MSPTier.WHITE_LABEL],
            white_label=white_label_config,
            trial_expires=datetime.now() + timedelta(days=self.msp_config.get("trial_period_days", 14)) if trial else None,
            created_by="msp_manager"
        )
        
        # Create client directory structure
        client_dir = self.clients_dir / client_id
        self._create_client_directories(client_dir)
        
        # Generate client credentials
        credentials = self._generate_client_credentials(client_dir)
        
        # Save client configuration
        self._save_client_config(client_dir, client)
        
        # Add to memory
        self.clients[client_id] = client
        
        logger.info(f"Created client: {client_id} ({organization_name})")
        
        return client_id
    
    def _create_client_directories(self, client_dir: Path):
        """Create client directory structure"""
        directories = [
            "config",
            "data",
            "reports",
            "logs",
            "assets",
            "white-label"
        ]
        
        for directory in directories:
            (client_dir / directory).mkdir(parents=True, exist_ok=True)
    
    def _generate_client_credentials(self, client_dir: Path) -> Dict[str, str]:
        """Generate client-specific credentials"""
        credentials = {
            "api_key": secrets.token_urlsafe(32),
            "client_secret": secrets.token_urlsafe(64),
            "encryption_key": secrets.token_urlsafe(32),
            "webhook_secret": secrets.token_urlsafe(32)
        }
        
        # Save credentials securely
        credentials_file = client_dir / "config" / "credentials.json"
        with open(credentials_file, 'w') as f:
            json.dump(credentials, f, indent=2)
        
        # Set restrictive permissions
        credentials_file.chmod(0o600)
        
        return credentials
    
    def _save_client_config(self, client_dir: Path, client: MSPClient):
        """Save client configuration"""
        config_file = client_dir / "config" / "client_config.json"
        with open(config_file, 'w') as f:
            json.dump(client.to_dict(), f, indent=2)
    
    def get_client(self, client_id: str) -> Optional[MSPClient]:
        """Get client by ID"""
        return self.clients.get(client_id)
    
    def update_client(self, client_id: str, updates: Dict[str, Any]) -> bool:
        """Update client configuration"""
        client = self.get_client(client_id)
        if not client:
            return False
        
        # Update client object
        for key, value in updates.items():
            if hasattr(client, key):
                setattr(client, key, value)
        
        client.updated_at = datetime.now()
        
        # Save to disk
        client_dir = self.clients_dir / client_id
        self._save_client_config(client_dir, client)
        
        logger.info(f"Updated client: {client_id}")
        return True
    
    def suspend_client(self, client_id: str, reason: str = "") -> bool:
        """Suspend client account"""
        return self.update_client(client_id, {
            "status": ClientStatus.SUSPENDED,
            "notes": f"Suspended: {reason}"
        })
    
    def activate_client(self, client_id: str) -> bool:
        """Activate client account"""
        return self.update_client(client_id, {
            "status": ClientStatus.ACTIVE
        })
    
    def delete_client(self, client_id: str) -> bool:
        """Delete client (move to archive)"""
        client = self.get_client(client_id)
        if not client:
            return False
        
        # Move client directory to archive
        client_dir = self.clients_dir / client_id
        archive_dir = self.clients_dir / "archived" / f"{client_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        archive_dir.parent.mkdir(exist_ok=True)
        
        try:
            client_dir.rename(archive_dir)
            del self.clients[client_id]
            logger.info(f"Archived client: {client_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to archive client {client_id}: {e}")
            return False
    
    def setup_white_label_branding(self, client_id: str, branding_config: Dict[str, Any]) -> bool:
        """Setup white-label branding for client"""
        client = self.get_client(client_id)
        if not client:
            return False
        
        # Create white-label configuration
        white_label = WhiteLabelConfig.from_dict(branding_config)
        white_label.enabled = True
        
        # Update client
        client.white_label = white_label
        client.updated_at = datetime.now()
        
        # Create client-specific white-label assets
        client_white_label_dir = self.clients_dir / client_id / "white-label"
        client_white_label_dir.mkdir(exist_ok=True)
        
        # Save white-label configuration
        white_label_config_file = client_white_label_dir / "branding_config.json"
        with open(white_label_config_file, 'w') as f:
            json.dump(white_label.to_dict(), f, indent=2)
        
        # Generate CSS theme
        self._generate_client_css_theme(client_white_label_dir, white_label)
        
        # Save client configuration
        client_dir = self.clients_dir / client_id
        self._save_client_config(client_dir, client)
        
        logger.info(f"Setup white-label branding for client: {client_id}")
        return True
    
    def _generate_client_css_theme(self, white_label_dir: Path, white_label: WhiteLabelConfig):
        """Generate CSS theme for client"""
        css_content = f"""
/* White-Label Theme for {white_label.company_name} */
:root {{
    --brand-primary: {white_label.primary_color};
    --brand-secondary: {white_label.secondary_color};
    --brand-accent: {white_label.accent_color};
    --brand-background: {white_label.background_color};
    --brand-text: {white_label.text_color};
}}

/* Header branding */
.main-header {{
    background: linear-gradient(135deg, var(--brand-primary), var(--brand-secondary));
    color: white;
}}

.logo-container {{
    display: flex;
    align-items: center;
    padding: 1rem;
}}

.logo-container h1 {{
    color: white;
    margin: 0;
    font-size: 1.5rem;
}}

/* Sidebar styling */
.stSidebar {{
    background-color: var(--brand-background);
    border-right: 2px solid var(--brand-primary);
}}

/* Button styling */
.stButton > button {{
    background-color: var(--brand-primary);
    color: white;
    border: none;
    border-radius: 6px;
}}

.stButton > button:hover {{
    background-color: var(--brand-secondary);
}}

/* Metric styling */
.metric-container {{
    background: linear-gradient(135deg, var(--brand-primary), var(--brand-accent));
    color: white;
    padding: 1rem;
    border-radius: 8px;
    margin: 0.5rem 0;
}}

/* Footer styling */
.footer {{
    background-color: var(--brand-primary);
    color: white;
    text-align: center;
    padding: 1rem;
    margin-top: 2rem;
}}

{white_label.custom_css}
"""
        
        css_file = white_label_dir / "theme.css"
        with open(css_file, 'w') as f:
            f.write(css_content)
    
    def get_client_dashboard_config(self, client_id: str) -> Dict[str, Any]:
        """Get client-specific dashboard configuration"""
        client = self.get_client(client_id)
        if not client:
            return {}
        
        config = {
            "client_id": client_id,
            "organization_name": client.organization_name,
            "tier": client.tier.value,
            "status": client.status.value,
            "enabled_features": client.enabled_features,
            "white_label": client.white_label.to_dict() if client.white_label else None,
            "usage": {
                "assets": {
                    "current": client.current_assets,
                    "limit": client.max_assets,
                    "percentage": (client.current_assets / client.max_assets) * 100 if client.max_assets > 0 else 0
                },
                "scans": {
                    "current": client.current_scans,
                    "limit": client.max_scans_per_month,
                    "percentage": (client.current_scans / client.max_scans_per_month) * 100 if client.max_scans_per_month > 0 else 0
                },
                "users": {
                    "current": client.current_users,
                    "limit": client.max_users,
                    "percentage": (client.current_users / client.max_users) * 100 if client.max_users > 0 else 0
                }
            },
            "trial_info": {
                "is_trial": client.is_trial(),
                "expires": client.trial_expires.isoformat() if client.trial_expires else None,
                "days_remaining": (client.trial_expires - datetime.now()).days if client.trial_expires else None
            }
        }
        
        return config
    
    def get_msp_analytics(self) -> Dict[str, Any]:
        """Get MSP-level analytics across all clients"""
        total_clients = len(self.clients)
        active_clients = len([c for c in self.clients.values() if c.is_active()])
        trial_clients = len([c for c in self.clients.values() if c.is_trial()])
        expired_clients = len([c for c in self.clients.values() if c.is_expired()])
        
        # Tier distribution
        tier_distribution = {}
        for tier in MSPTier:
            tier_distribution[tier.value] = len([c for c in self.clients.values() if c.tier == tier])
        
        # Usage statistics
        total_assets = sum(c.current_assets for c in self.clients.values())
        total_scans = sum(c.current_scans for c in self.clients.values())
        total_users = sum(c.current_users for c in self.clients.values())
        
        # Revenue potential (if billing enabled)
        revenue_data = self._calculate_revenue_metrics()
        
        return {
            "client_metrics": {
                "total": total_clients,
                "active": active_clients,
                "trial": trial_clients,
                "expired": expired_clients,
                "tier_distribution": tier_distribution
            },
            "usage_metrics": {
                "total_assets": total_assets,
                "total_scans": total_scans,
                "total_users": total_users,
                "average_assets_per_client": total_assets / total_clients if total_clients > 0 else 0
            },
            "revenue_metrics": revenue_data,
            "white_label_clients": len([c for c in self.clients.values() if c.white_label and c.white_label.enabled]),
            "analysis_date": datetime.now().isoformat()
        }
    
    def _calculate_revenue_metrics(self) -> Dict[str, Any]:
        """Calculate revenue metrics (placeholder for billing integration)"""
        # This would integrate with billing system in production
        tier_pricing = {
            MSPTier.BASIC.value: 99,
            MSPTier.PROFESSIONAL.value: 299,
            MSPTier.ENTERPRISE.value: 599,
            MSPTier.WHITE_LABEL.value: 999
        }
        
        monthly_revenue = 0
        for client in self.clients.values():
            if client.is_active() and not client.is_trial():
                monthly_revenue += tier_pricing.get(client.tier.value, 0)
        
        return {
            "monthly_recurring_revenue": monthly_revenue,
            "annual_recurring_revenue": monthly_revenue * 12,
            "average_revenue_per_client": monthly_revenue / len([c for c in self.clients.values() if c.is_active() and not c.is_trial()]) if len([c for c in self.clients.values() if c.is_active() and not c.is_trial()]) > 0 else 0
        }
    
    def export_client_data(self, client_id: str) -> Dict[str, Any]:
        """Export client data for backup/migration"""
        client = self.get_client(client_id)
        if not client:
            return {}
        
        client_dir = self.clients_dir / client_id
        
        export_data = {
            "client_config": client.to_dict(),
            "export_timestamp": datetime.now().isoformat(),
            "export_version": "1.0"
        }
        
        # Include credentials if available
        credentials_file = client_dir / "config" / "credentials.json"
        if credentials_file.exists():
            try:
                with open(credentials_file, 'r') as f:
                    export_data["credentials"] = json.load(f)
            except Exception as e:
                logger.warning(f"Could not export credentials for {client_id}: {e}")
        
        return export_data
    
    def import_client_data(self, export_data: Dict[str, Any]) -> bool:
        """Import client data from export"""
        try:
            client_data = export_data["client_config"]
            client = MSPClient.from_dict(client_data)
            
            # Create client directory
            client_dir = self.clients_dir / client.client_id
            self._create_client_directories(client_dir)
            
            # Save client configuration
            self._save_client_config(client_dir, client)
            
            # Restore credentials if available
            if "credentials" in export_data:
                credentials_file = client_dir / "config" / "credentials.json"
                with open(credentials_file, 'w') as f:
                    json.dump(export_data["credentials"], f, indent=2)
                credentials_file.chmod(0o600)
            
            # Add to memory
            self.clients[client.client_id] = client
            
            logger.info(f"Imported client: {client.client_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import client data: {e}")
            return False

# Factory function
def create_msp_manager(install_dir: str = None) -> MSPManager:
    """Create MSP Manager instance"""
    return MSPManager(install_dir)

# Example usage
if __name__ == "__main__":
    # Test MSP Manager
    msp = create_msp_manager()
    
    # Create sample client
    white_label = WhiteLabelConfig(
        enabled=True,
        company_name="SecureCloud MSP",
        primary_color="#2c5aa0",
        secondary_color="#f39c12",
        support_email="support@securecloud.com"
    )
    
    client_id = msp.create_client(
        organization_name="Acme Corporation",
        email="admin@acme.com",
        tier=MSPTier.ENTERPRISE,
        white_label_config=white_label
    )
    
    print(f"✅ Created client: {client_id}")
    
    # Get analytics
    analytics = msp.get_msp_analytics()
    print(f"📊 MSP Analytics: {analytics['client_metrics']['total']} clients")
    
    print("🎉 MSP Manager test completed successfully!")