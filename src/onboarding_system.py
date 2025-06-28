#!/usr/bin/env python3
"""
AuditHound Client Onboarding System
Automated client setup, configuration, and provisioning workflow
"""

import logging
import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
# import yaml  # Not needed for core functionality
import secrets
import subprocess
# from jinja2 import Template  # Not needed for core functionality

from msp_manager import MSPManager, MSPClient, WhiteLabelConfig, MSPTier, ClientStatus

logger = logging.getLogger(__name__)

class OnboardingStage(Enum):
    """Onboarding workflow stages"""
    INITIATED = "initiated"
    INFO_COLLECTED = "info_collected"
    INFRASTRUCTURE_CONFIGURED = "infrastructure_configured"
    CREDENTIALS_GENERATED = "credentials_generated"
    TESTING_COMPLETED = "testing_completed"
    COMPLETED = "completed"
    FAILED = "failed"

class OnboardingMethod(Enum):
    """Onboarding methods"""
    MANUAL = "manual"
    AUTOMATED = "automated"
    GUIDED = "guided"
    BULK_IMPORT = "bulk_import"

@dataclass
class OnboardingRequest:
    """Client onboarding request"""
    request_id: str
    organization_name: str
    primary_contact_email: str
    
    # Organization details
    industry: str = ""
    company_size: str = "medium"
    primary_contact_name: str = ""
    phone: str = ""
    
    # Address information
    address: Dict[str, str] = field(default_factory=dict)
    
    # Service requirements
    requested_tier: MSPTier = MSPTier.PROFESSIONAL
    compliance_frameworks: List[str] = field(default_factory=lambda: ["SOC2"])
    cloud_providers: List[str] = field(default_factory=lambda: ["aws"])
    
    # Infrastructure details
    infrastructure_info: Dict[str, Any] = field(default_factory=dict)
    security_requirements: Dict[str, Any] = field(default_factory=dict)
    
    # White-label preferences
    white_label_requested: bool = False
    branding_requirements: Dict[str, Any] = field(default_factory=dict)
    
    # Workflow tracking
    stage: OnboardingStage = OnboardingStage.INITIATED
    method: OnboardingMethod = OnboardingMethod.AUTOMATED
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    
    # Results
    client_id: Optional[str] = None
    credentials: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "request_id": self.request_id,
            "organization_name": self.organization_name,
            "primary_contact_email": self.primary_contact_email,
            "industry": self.industry,
            "company_size": self.company_size,
            "primary_contact_name": self.primary_contact_name,
            "phone": self.phone,
            "address": self.address,
            "requested_tier": self.requested_tier.value,
            "compliance_frameworks": self.compliance_frameworks,
            "cloud_providers": self.cloud_providers,
            "infrastructure_info": self.infrastructure_info,
            "security_requirements": self.security_requirements,
            "white_label_requested": self.white_label_requested,
            "branding_requirements": self.branding_requirements,
            "stage": self.stage.value,
            "method": self.method.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "client_id": self.client_id,
            "credentials": self.credentials,
            "errors": self.errors,
            "notes": self.notes
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'OnboardingRequest':
        """Create from dictionary"""
        # Handle datetime fields
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if isinstance(data.get('updated_at'), str):
            data['updated_at'] = datetime.fromisoformat(data['updated_at'])
        if data.get('completed_at'):
            data['completed_at'] = datetime.fromisoformat(data['completed_at'])
        
        # Handle enum fields
        if isinstance(data.get('requested_tier'), str):
            data['requested_tier'] = MSPTier(data['requested_tier'])
        if isinstance(data.get('stage'), str):
            data['stage'] = OnboardingStage(data['stage'])
        if isinstance(data.get('method'), str):
            data['method'] = OnboardingMethod(data['method'])
        
        return cls(**data)

class OnboardingWorkflow:
    """Handles the complete client onboarding workflow"""
    
    def __init__(self, install_dir: str = None):
        """Initialize onboarding workflow"""
        self.install_dir = Path(install_dir) if install_dir else Path.cwd()
        self.msp_manager = MSPManager(install_dir)
        
        # Onboarding paths
        self.onboarding_dir = self.install_dir / "onboarding"
        self.templates_dir = self.onboarding_dir / "templates"
        self.requests_dir = self.onboarding_dir / "requests"
        self.completed_dir = self.onboarding_dir / "completed"
        
        # Create directories
        for directory in [self.onboarding_dir, self.templates_dir, self.requests_dir, self.completed_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Active onboarding requests
        self.active_requests: Dict[str, OnboardingRequest] = {}
        
        # Load existing requests
        self.load_active_requests()
        
        logger.info(f"Onboarding workflow initialized with {len(self.active_requests)} active requests")
    
    def load_active_requests(self):
        """Load active onboarding requests"""
        for request_file in self.requests_dir.glob("*.json"):
            try:
                with open(request_file, 'r') as f:
                    request_data = json.load(f)
                
                request = OnboardingRequest.from_dict(request_data)
                self.active_requests[request.request_id] = request
                
            except Exception as e:
                logger.error(f"Failed to load onboarding request {request_file}: {e}")
    
    def create_onboarding_request(self, organization_name: str, email: str, 
                                 onboarding_data: Dict[str, Any] = None) -> str:
        """
        Create new onboarding request
        
        Args:
            organization_name: Client organization name
            email: Primary contact email
            onboarding_data: Additional onboarding information
            
        Returns:
            Generated request_id
        """
        request_id = f"onboard_{uuid.uuid4().hex[:8]}"
        
        # Create onboarding request
        request = OnboardingRequest(
            request_id=request_id,
            organization_name=organization_name,
            primary_contact_email=email
        )
        
        # Apply additional data if provided
        if onboarding_data:
            self._apply_onboarding_data(request, onboarding_data)
        
        # Save request
        self._save_request(request)
        self.active_requests[request_id] = request
        
        logger.info(f"Created onboarding request: {request_id} for {organization_name}")
        
        return request_id
    
    def _apply_onboarding_data(self, request: OnboardingRequest, data: Dict[str, Any]):
        """Apply onboarding data to request"""
        # Organization details
        org_data = data.get("organization", {})
        request.industry = org_data.get("industry", "")
        request.company_size = org_data.get("size", "medium")
        
        # Contact information
        contact_data = org_data.get("contact", {})
        request.primary_contact_name = contact_data.get("name", "")
        request.phone = contact_data.get("phone", "")
        request.address = org_data.get("address", {})
        
        # Service requirements
        compliance_data = data.get("compliance", {})
        request.compliance_frameworks = compliance_data.get("frameworks", ["SOC2"])
        
        # Infrastructure
        infra_data = data.get("infrastructure", {})
        request.infrastructure_info = infra_data
        
        # Cloud providers
        cloud_data = infra_data.get("cloud_providers", {})
        enabled_providers = []
        for provider, config in cloud_data.items():
            if config.get("enabled", False):
                enabled_providers.append(provider)
        request.cloud_providers = enabled_providers or ["aws"]
        
        # Security requirements
        request.security_requirements = data.get("security", {})
        
        # MSP settings
        msp_data = data.get("msp_settings", {})
        request.white_label_requested = msp_data.get("white_label", {}).get("enabled", False)
        request.branding_requirements = msp_data.get("white_label", {}).get("branding", {})
        
        # Determine tier based on requirements
        request.requested_tier = self._determine_recommended_tier(request)
        
        request.updated_at = datetime.now()
    
    def _determine_recommended_tier(self, request: OnboardingRequest) -> MSPTier:
        """Determine recommended tier based on requirements"""
        score = 0
        
        # Company size scoring
        size_scores = {
            "small": 1,
            "medium": 2,
            "large": 3,
            "enterprise": 4
        }
        score += size_scores.get(request.company_size, 2)
        
        # Framework complexity
        if len(request.compliance_frameworks) > 1:
            score += 1
        if "ISO27001" in request.compliance_frameworks:
            score += 1
        if "NIST" in request.compliance_frameworks:
            score += 1
        
        # Cloud provider complexity
        if len(request.cloud_providers) > 2:
            score += 1
        
        # White label requirement
        if request.white_label_requested:
            score += 2
        
        # Map score to tier
        if score >= 7:
            return MSPTier.WHITE_LABEL
        elif score >= 5:
            return MSPTier.ENTERPRISE
        elif score >= 3:
            return MSPTier.PROFESSIONAL
        else:
            return MSPTier.BASIC
    
    def process_onboarding_request(self, request_id: str, auto_approve: bool = True) -> bool:
        """
        Process onboarding request through complete workflow
        
        Args:
            request_id: Onboarding request ID
            auto_approve: Whether to auto-approve or require manual approval
            
        Returns:
            True if successful, False otherwise
        """
        request = self.active_requests.get(request_id)
        if not request:
            logger.error(f"Onboarding request not found: {request_id}")
            return False
        
        try:
            # Stage 1: Validate information
            if not self._validate_request_info(request):
                request.stage = OnboardingStage.FAILED
                request.errors.append("Information validation failed")
                self._save_request(request)
                return False
            
            request.stage = OnboardingStage.INFO_COLLECTED
            self._save_request(request)
            
            # Stage 2: Configure infrastructure
            if not self._configure_infrastructure(request):
                request.stage = OnboardingStage.FAILED
                request.errors.append("Infrastructure configuration failed")
                self._save_request(request)
                return False
            
            request.stage = OnboardingStage.INFRASTRUCTURE_CONFIGURED
            self._save_request(request)
            
            # Stage 3: Create client and generate credentials
            client_id = self._create_client_account(request)
            if not client_id:
                request.stage = OnboardingStage.FAILED
                request.errors.append("Client account creation failed")
                self._save_request(request)
                return False
            
            request.client_id = client_id
            request.stage = OnboardingStage.CREDENTIALS_GENERATED
            self._save_request(request)
            
            # Stage 4: Setup white-label branding (if requested)
            if request.white_label_requested:
                if not self._setup_white_label_branding(request):
                    logger.warning(f"White-label setup failed for {request_id}, continuing...")
            
            # Stage 5: Perform initial testing
            if not self._perform_initial_testing(request):
                logger.warning(f"Initial testing failed for {request_id}, but continuing...")
            
            request.stage = OnboardingStage.TESTING_COMPLETED
            self._save_request(request)
            
            # Stage 6: Finalize onboarding
            if not self._finalize_onboarding(request):
                request.stage = OnboardingStage.FAILED
                request.errors.append("Onboarding finalization failed")
                self._save_request(request)
                return False
            
            request.stage = OnboardingStage.COMPLETED
            request.completed_at = datetime.now()
            self._save_request(request)
            
            # Move to completed
            self._move_to_completed(request)
            
            logger.info(f"Onboarding completed successfully for {request_id}")
            return True
            
        except Exception as e:
            logger.error(f"Onboarding failed for {request_id}: {e}")
            request.stage = OnboardingStage.FAILED
            request.errors.append(f"Unexpected error: {str(e)}")
            self._save_request(request)
            return False
    
    def _validate_request_info(self, request: OnboardingRequest) -> bool:
        """Validate onboarding request information"""
        # Required fields validation
        if not request.organization_name:
            request.errors.append("Organization name is required")
            return False
        
        if not request.primary_contact_email or "@" not in request.primary_contact_email:
            request.errors.append("Valid email address is required")
            return False
        
        if not request.compliance_frameworks:
            request.errors.append("At least one compliance framework must be selected")
            return False
        
        if not request.cloud_providers:
            request.errors.append("At least one cloud provider must be selected")
            return False
        
        return True
    
    def _configure_infrastructure(self, request: OnboardingRequest) -> bool:
        """Configure infrastructure settings for client"""
        try:
            # Create infrastructure configuration
            infra_config = {
                "cloud_providers": {},
                "compliance_frameworks": request.compliance_frameworks,
                "monitoring": {
                    "enabled": True,
                    "retention_days": 90
                },
                "security": {
                    "encryption_enabled": True,
                    "audit_logging": True
                }
            }
            
            # Configure cloud providers
            for provider in request.cloud_providers:
                infra_config["cloud_providers"][provider] = {
                    "enabled": True,
                    "auto_discovery": True,
                    "compliance_scanning": True
                }
                
                # Provider-specific configuration
                if provider == "aws":
                    infra_config["cloud_providers"][provider].update({
                        "regions": ["us-west-2", "us-east-1"],
                        "services": ["iam", "cloudtrail", "config", "securityhub"]
                    })
                elif provider == "gcp":
                    infra_config["cloud_providers"][provider].update({
                        "organization_policies": True,
                        "security_command_center": True,
                        "cloud_logging": True
                    })
                elif provider == "azure":
                    infra_config["cloud_providers"][provider].update({
                        "azure_ad_integration": True,
                        "security_center": True,
                        "activity_logs": True
                    })
            
            # Store infrastructure configuration
            request.infrastructure_info = infra_config
            
            return True
            
        except Exception as e:
            logger.error(f"Infrastructure configuration failed: {e}")
            request.errors.append(f"Infrastructure configuration error: {str(e)}")
            return False
    
    def _create_client_account(self, request: OnboardingRequest) -> Optional[str]:
        """Create client account in MSP system"""
        try:
            # Prepare white-label configuration if requested
            white_label_config = None
            if request.white_label_requested and request.branding_requirements:
                white_label_config = WhiteLabelConfig(
                    enabled=True,
                    company_name=request.branding_requirements.get("company_name", request.organization_name),
                    primary_color=request.branding_requirements.get("primary_color", "#1f77b4"),
                    secondary_color=request.branding_requirements.get("secondary_color", "#ff7f0e"),
                    support_email=request.branding_requirements.get("support_email", request.primary_contact_email)
                )
            
            # Create client
            client_id = self.msp_manager.create_client(
                organization_name=request.organization_name,
                email=request.primary_contact_email,
                tier=request.requested_tier,
                trial=True,  # Start as trial
                white_label_config=white_label_config
            )
            
            # Get client credentials
            client_dir = self.msp_manager.clients_dir / client_id
            credentials_file = client_dir / "config" / "credentials.json"
            
            if credentials_file.exists():
                with open(credentials_file, 'r') as f:
                    credentials = json.load(f)
                request.credentials = credentials
            
            return client_id
            
        except Exception as e:
            logger.error(f"Client account creation failed: {e}")
            request.errors.append(f"Client creation error: {str(e)}")
            return None
    
    def _setup_white_label_branding(self, request: OnboardingRequest) -> bool:
        """Setup white-label branding for client"""
        if not request.client_id or not request.white_label_requested:
            return True
        
        try:
            return self.msp_manager.setup_white_label_branding(
                request.client_id,
                request.branding_requirements
            )
            
        except Exception as e:
            logger.error(f"White-label branding setup failed: {e}")
            request.errors.append(f"White-label setup error: {str(e)}")
            return False
    
    def _perform_initial_testing(self, request: OnboardingRequest) -> bool:
        """Perform initial testing of client setup"""
        if not request.client_id:
            return False
        
        try:
            # Test client configuration
            client = self.msp_manager.get_client(request.client_id)
            if not client:
                request.errors.append("Client not found after creation")
                return False
            
            # Test credentials
            if not request.credentials.get("api_key"):
                request.errors.append("API key not generated")
                return False
            
            # Test directory structure
            client_dir = self.msp_manager.clients_dir / request.client_id
            required_dirs = ["config", "data", "reports", "logs"]
            
            for req_dir in required_dirs:
                if not (client_dir / req_dir).exists():
                    request.errors.append(f"Required directory missing: {req_dir}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Initial testing failed: {e}")
            request.errors.append(f"Testing error: {str(e)}")
            return False
    
    def _finalize_onboarding(self, request: OnboardingRequest) -> bool:
        """Finalize onboarding process"""
        try:
            # Generate welcome documentation
            self._generate_welcome_documentation(request)
            
            # Create initial configuration files
            self._create_initial_configuration(request)
            
            # Send welcome email (placeholder)
            self._send_welcome_email(request)
            
            return True
            
        except Exception as e:
            logger.error(f"Onboarding finalization failed: {e}")
            request.errors.append(f"Finalization error: {str(e)}")
            return False
    
    def _generate_welcome_documentation(self, request: OnboardingRequest):
        """Generate welcome documentation for client"""
        if not request.client_id:
            return
        
        client_dir = self.msp_manager.clients_dir / request.client_id
        docs_dir = client_dir / "documentation"
        docs_dir.mkdir(exist_ok=True)
        
        # Welcome README
        welcome_content = f"""
# Welcome to AuditHound Security Compliance

Hello {request.organization_name}!

Your security compliance platform has been successfully configured and is ready for use.

## Account Information

- **Organization**: {request.organization_name}
- **Client ID**: {request.client_id}
- **Service Tier**: {request.requested_tier.value.title()}
- **Primary Contact**: {request.primary_contact_email}

## Getting Started

### 1. Access Your Dashboard
Your personalized security dashboard is available at:
- **URL**: https://your-audithound-instance.com
- **Login**: {request.primary_contact_email}
- **API Key**: {request.credentials.get('api_key', 'N/A')[:16]}...

### 2. Cloud Provider Configuration
The following cloud providers have been enabled for your account:
{chr(10).join(f"- {provider.upper()}" for provider in request.cloud_providers)}

### 3. Compliance Frameworks
Your account is configured for the following compliance frameworks:
{chr(10).join(f"- {framework}" for framework in request.compliance_frameworks)}

## Next Steps

1. **Configure Cloud Credentials**: Set up your cloud provider credentials in the dashboard
2. **Run Initial Scan**: Perform your first compliance scan to establish baseline
3. **Review Results**: Analyze compliance findings and recommendations
4. **Set Up Monitoring**: Configure ongoing monitoring and alerting

## Support

For technical support and questions:
- **Email**: support@audithound.com
- **Documentation**: https://docs.audithound.com
- **Phone**: +1-555-AUDIT-1

Welcome to enhanced security compliance with AuditHound!
"""
        
        with open(docs_dir / "README.md", 'w') as f:
            f.write(welcome_content)
    
    def _create_initial_configuration(self, request: OnboardingRequest):
        """Create initial configuration files for client"""
        if not request.client_id:
            return
        
        client_dir = self.msp_manager.clients_dir / request.client_id
        config_dir = client_dir / "config"
        
        # Create client-specific configuration
        client_config = {
            "client": {
                "id": request.client_id,
                "organization": request.organization_name,
                "tier": request.requested_tier.value,
                "created_at": request.created_at.isoformat()
            },
            "compliance": {
                "frameworks": request.compliance_frameworks,
                "auto_scan": True,
                "scan_frequency": "weekly"
            },
            "cloud_providers": request.infrastructure_info.get("cloud_providers", {}),
            "notifications": {
                "email": {
                    "enabled": True,
                    "recipients": [request.primary_contact_email]
                },
                "dashboard": {
                    "enabled": True
                }
            },
            "security": {
                "api_rate_limit": 1000,
                "session_timeout": 3600,
                "require_mfa": False
            }
        }
        
        with open(config_dir / "audithound_config.json", 'w') as f:
            json.dump(client_config, f, indent=2)
    
    def _send_welcome_email(self, request: OnboardingRequest):
        """Send welcome email to client (placeholder)"""
        # This would integrate with email service in production
        logger.info(f"Welcome email would be sent to {request.primary_contact_email}")
    
    def _save_request(self, request: OnboardingRequest):
        """Save onboarding request to disk"""
        request_file = self.requests_dir / f"{request.request_id}.json"
        with open(request_file, 'w') as f:
            json.dump(request.to_dict(), f, indent=2)
    
    def _move_to_completed(self, request: OnboardingRequest):
        """Move completed request to completed directory"""
        # Move from active to completed
        source_file = self.requests_dir / f"{request.request_id}.json"
        dest_file = self.completed_dir / f"{request.request_id}.json"
        
        if source_file.exists():
            source_file.rename(dest_file)
        
        # Remove from active requests
        if request.request_id in self.active_requests:
            del self.active_requests[request.request_id]
    
    def get_onboarding_status(self, request_id: str) -> Dict[str, Any]:
        """Get onboarding status"""
        request = self.active_requests.get(request_id)
        if not request:
            # Check completed requests
            completed_file = self.completed_dir / f"{request_id}.json"
            if completed_file.exists():
                with open(completed_file, 'r') as f:
                    return json.load(f)
            return {"error": "Request not found"}
        
        return request.to_dict()
    
    def list_active_requests(self) -> List[Dict[str, Any]]:
        """List all active onboarding requests"""
        return [request.to_dict() for request in self.active_requests.values()]
    
    def bulk_onboard_clients(self, clients_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Bulk onboard multiple clients"""
        results = {
            "total": len(clients_data),
            "successful": 0,
            "failed": 0,
            "requests": []
        }
        
        for client_data in clients_data:
            try:
                request_id = self.create_onboarding_request(
                    organization_name=client_data["organization_name"],
                    email=client_data["email"],
                    onboarding_data=client_data
                )
                
                success = self.process_onboarding_request(request_id, auto_approve=True)
                
                if success:
                    results["successful"] += 1
                else:
                    results["failed"] += 1
                
                results["requests"].append({
                    "request_id": request_id,
                    "organization_name": client_data["organization_name"],
                    "success": success
                })
                
            except Exception as e:
                logger.error(f"Bulk onboarding failed for {client_data.get('organization_name', 'Unknown')}: {e}")
                results["failed"] += 1
                results["requests"].append({
                    "organization_name": client_data.get("organization_name", "Unknown"),
                    "success": False,
                    "error": str(e)
                })
        
        return results

# Factory function
def create_onboarding_workflow(install_dir: str = None) -> OnboardingWorkflow:
    """Create onboarding workflow instance"""
    return OnboardingWorkflow(install_dir)

# Example usage
if __name__ == "__main__":
    # Test onboarding workflow
    workflow = create_onboarding_workflow()
    
    # Sample onboarding data
    onboarding_data = {
        "organization": {
            "name": "TechCorp Solutions",
            "industry": "Technology",
            "size": "medium",
            "contact": {
                "name": "Sarah Johnson",
                "email": "sarah.johnson@techcorp.com",
                "phone": "+1-555-TECH-123"
            }
        },
        "compliance": {
            "frameworks": ["SOC2", "ISO27001"]
        },
        "infrastructure": {
            "cloud_providers": {
                "aws": {"enabled": True},
                "gcp": {"enabled": True}
            }
        },
        "msp_settings": {
            "white_label": {
                "enabled": True,
                "branding": {
                    "company_name": "TechCorp Security",
                    "primary_color": "#2c5aa0"
                }
            }
        }
    }
    
    # Create and process onboarding request
    request_id = workflow.create_onboarding_request(
        organization_name="TechCorp Solutions",
        email="sarah.johnson@techcorp.com",
        onboarding_data=onboarding_data
    )
    
    print(f"✅ Created onboarding request: {request_id}")
    
    # Process the request
    success = workflow.process_onboarding_request(request_id)
    
    if success:
        print("🎉 Onboarding completed successfully!")
        status = workflow.get_onboarding_status(request_id)
        print(f"   Client ID: {status.get('client_id')}")
    else:
        print("❌ Onboarding failed")
        status = workflow.get_onboarding_status(request_id)
        print(f"   Errors: {status.get('errors', [])}")
    
    print("🎉 Onboarding system test completed!")