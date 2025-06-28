#!/usr/bin/env python3
"""
Unified Flask Dashboard for AuditHound
Combines compliance auditing with threat hunting and security analytics
Enhanced with Post-Quantum Cryptography capabilities
"""

from flask import Flask, render_template, jsonify, request, session
from datetime import datetime, timedelta
import asyncio
import json
import sys
import os
import uuid
from threading import Thread
from typing import Dict, List, Optional

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from unified_models import (
    SecurityAsset, UnifiedFinding, ScanResult, RiskLevel,
    ComplianceStatus, ThreatStatus, AssetType
)
from unified_audit_engine import UnifiedAuditEngine
from soc_integration.misp_connector import MISPConnector
from soc_integration.thehive_connector import TheHiveConnector
from multi_tenant_manager import (
    MultiTenantManager, TenantProfile, TenantTier, TenantStatus,
    get_client_id_from_request, get_tenant_manager
)
from post_quantum_integration import get_pq_integration_manager

app = Flask(__name__)
app.secret_key = 'audithound-unified-dashboard-key'

# Global unified engine instance
unified_engine = None
misp_connector = None
thehive_connector = None
tenant_manager = None
pq_integration_manager = None

def initialize_engine():
    """Initialize the unified audit engine"""
    global unified_engine, misp_connector, thehive_connector, tenant_manager, pq_integration_manager
    
    try:
        config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'config.yaml')
        
        # Initialize Weaviate client if configured
        weaviate_client = None
        try:
            import weaviate
            weaviate_url = os.getenv('WEAVIATE_URL', 'http://localhost:8080')
            weaviate_client = weaviate.Client(weaviate_url)
            # Test connection
            weaviate_client.get_meta()
            print(f"✅ Connected to Weaviate at {weaviate_url}")
        except Exception as e:
            print(f"⚠️  Weaviate not available: {e}")
            weaviate_client = None
        
        # Initialize unified engine with optional Weaviate client
        unified_engine = UnifiedAuditEngine(config_path, weaviate_client=weaviate_client)
        
        # Initialize SOC integrations if configured
        misp_url = os.getenv('MISP_URL')
        misp_key = os.getenv('MISP_API_KEY')
        if misp_url and misp_key:
            misp_connector = MISPConnector(misp_url, misp_key)
        
        thehive_url = os.getenv('THEHIVE_URL')
        thehive_key = os.getenv('THEHIVE_API_KEY')
        if thehive_url and thehive_key:
            thehive_connector = TheHiveConnector(thehive_url, thehive_key)
        
        # Initialize tenant manager
        tenant_manager = get_tenant_manager()
        
        # Create sample tenants for demo
        if not tenant_manager.tenants:
            demo_client = tenant_manager.create_tenant("Demo Organization", "demo@audithound.com", TenantTier.ENTERPRISE)
            acme_client = tenant_manager.create_tenant("Acme Corp", "admin@acme.com", TenantTier.PROFESSIONAL)
            startup_client = tenant_manager.create_tenant("StartupXYZ", "cto@startup.com", TenantTier.STARTER)
        
        # Initialize Post-Quantum Integration
        try:
            database_url = os.getenv('DATABASE_URL', 'postgresql://localhost/audithound_unified')
            secret_key = os.getenv('JWT_SECRET_KEY', 'default-secret-key-change-in-production')
            pq_integration_manager = get_pq_integration_manager(database_url, secret_key)
            print("✅ Post-quantum integration manager initialized")
        except Exception as e:
            print(f"⚠️  Post-quantum integration not available: {e}")
            pq_integration_manager = None
        
        print("✅ Unified AuditHound engine initialized successfully")
        
    except Exception as e:
        print(f"❌ Failed to initialize unified engine: {e}")
        # Create a mock engine for development
        unified_engine = MockUnifiedEngine()

class MockUnifiedEngine:
    """Mock engine for development/testing"""
    
    def __init__(self):
        self.active_scans = {}
        self.assets = {}
        
        # Create sample assets
        self._create_sample_assets()
    
    def _create_sample_assets(self):
        """Create sample assets for demonstration with multi-tenant support"""
        # Get sample client IDs
        client_ids = list(tenant_manager.tenants.keys()) if tenant_manager.tenants else ["demo_client", "acme_client"]
        
        sample_assets = [
            SecurityAsset(
                asset_id="aws-ec2-prod-web-01",
                name="Production Web Server",
                asset_type=AssetType.SERVER,
                client_id=client_ids[0] if client_ids else "demo_client",
                ip_address="10.0.1.100",
                hostname="prod-web-01.company.com",
                cloud_provider="aws",
                cloud_region="us-west-2",
                criticality=RiskLevel.HIGH,
                compliance_status=ComplianceStatus.PARTIAL,
                threat_status=ThreatStatus.INVESTIGATING,
                anomaly_score=75.5,
                organization_name="Demo Organization",
                department="IT",
                owner="admin@demo.com",
                tags=["production", "web-server", "critical"]
            ),
            SecurityAsset(
                asset_id="gcp-gke-app-cluster",
                name="Application Cluster",
                asset_type=AssetType.CONTAINER,
                client_id=client_ids[0] if client_ids else "demo_client",
                cloud_provider="gcp",
                cloud_region="us-central1",
                criticality=RiskLevel.MEDIUM,
                compliance_status=ComplianceStatus.COMPLIANT,
                threat_status=ThreatStatus.RESOLVED,
                anomaly_score=15.2,
                organization_name="Demo Organization",
                department="Engineering",
                owner="dev@demo.com",
                tags=["kubernetes", "application", "development"]
            ),
            SecurityAsset(
                asset_id="azure-sql-primary-db",
                name="Primary Database",
                asset_type=AssetType.DATABASE,
                client_id=client_ids[1] if len(client_ids) > 1 else client_ids[0] if client_ids else "acme_client",
                cloud_provider="azure",
                cloud_region="East US",
                criticality=RiskLevel.CRITICAL,
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                threat_status=ThreatStatus.ACTIVE,
                anomaly_score=88.7,
                organization_name="Acme Corp",
                department="Data",
                owner="dba@acme.com",
                tags=["database", "sql", "sensitive-data"]
            )
        ]
        
        for asset in sample_assets:
            self.assets[asset.asset_id] = asset
    
    async def execute_unified_scan(self, scan_config: Dict) -> ScanResult:
        """Mock unified scan execution"""
        scan = ScanResult(
            scan_type='unified',
            cloud_providers=scan_config.get('providers', []),
            compliance_frameworks=scan_config.get('frameworks', []),
            hunting_rules=scan_config.get('hunting_rules', [])
        )
        
        # Simulate scan execution
        await asyncio.sleep(2)  # Simulate processing time
        
        # Create sample findings
        sample_findings = [
            UnifiedFinding(
                title="Critical Compliance Violation: CC6.1",
                description="Password policy does not meet SOC 2 requirements",
                finding_type="compliance",
                severity=RiskLevel.HIGH,
                compliance_framework="soc2",
                control_id="CC6.1",
                compliance_score=45.5,
                affected_assets=["aws-ec2-prod-web-01"],
                status="open"
            ),
            UnifiedFinding(
                title="Threat Detection: Lateral Movement",
                description="Suspicious network activity indicating lateral movement",
                finding_type="threat",
                severity=RiskLevel.CRITICAL,
                hunting_rule="lateral_movement_detection",
                mitre_techniques=["T1021.001", "T1078"],
                confidence_score=87.3,
                affected_assets=["azure-sql-primary-db"],
                status="investigating"
            ),
            UnifiedFinding(
                title="Hybrid Risk: Access Control + Privilege Escalation",
                description="Failed access controls with concurrent privilege escalation attempts",
                finding_type="hybrid",
                severity=RiskLevel.CRITICAL,
                compliance_score=35.2,
                confidence_score=92.1,
                affected_assets=["aws-ec2-prod-web-01", "azure-sql-primary-db"],
                status="open"
            )
        ]
        
        for finding in sample_findings:
            scan.add_finding(finding)
        
        scan.complete_scan()
        self.active_scans[scan.scan_id] = scan
        
        return scan
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Get scan status"""
        if scan_id in self.active_scans:
            return self.active_scans[scan_id].get_summary()
        return None
    
    def get_asset_risk_profile(self, asset_id: str) -> Dict:
        """Get asset risk profile"""
        if asset_id not in self.assets:
            return {}
        
        asset = self.assets[asset_id]
        return {
            'asset_id': asset_id,
            'overall_risk_score': asset.anomaly_score,
            'compliance_status': asset.compliance_status.value,
            'threat_status': asset.threat_status.value,
            'criticality': asset.criticality.value,
            'recommendations': ["Enable MFA", "Update password policy", "Enhanced monitoring"]
        }

# Initialize engine on startup
initialize_engine()

@app.route('/')
def unified_dashboard():
    """Main unified dashboard view"""
    return render_template('unified_dashboard.html')

@app.route('/api/dashboard-summary')
def dashboard_summary():
    """API endpoint for unified dashboard summary with multi-tenant filtering"""
    try:
        # Get client_id from request
        client_id = get_client_id_from_request(request)
        
        # Filter assets by tenant
        all_assets = list(unified_engine.assets.values())
        tenant_assets = tenant_manager.filter_assets_by_tenant(all_assets, client_id)
        total_assets = len(tenant_assets)
        
        compliance_summary = {
            'compliant': len([a for a in tenant_assets 
                            if a.compliance_status == ComplianceStatus.COMPLIANT]),
            'partial': len([a for a in tenant_assets 
                          if a.compliance_status == ComplianceStatus.PARTIAL]),
            'non_compliant': len([a for a in tenant_assets 
                                if a.compliance_status == ComplianceStatus.NON_COMPLIANT])
        }
        
        threat_summary = {
            'resolved': len([a for a in tenant_assets 
                           if a.threat_status == ThreatStatus.RESOLVED]),
            'investigating': len([a for a in tenant_assets 
                                if a.threat_status == ThreatStatus.INVESTIGATING]),
            'active': len([a for a in tenant_assets 
                         if a.threat_status == ThreatStatus.ACTIVE])
        }
        
        # Get recent scans
        recent_scans = list(unified_engine.active_scans.values())[-5:]
        
        summary = {
            'total_assets': total_assets,
            'compliance_summary': compliance_summary,
            'threat_summary': threat_summary,
            'recent_scans': [scan.get_summary() for scan in recent_scans],
            'overall_compliance_score': sum(a.compliance_status == ComplianceStatus.COMPLIANT 
                                          for a in unified_engine.assets.values()) / total_assets * 100 if total_assets > 0 else 0,
            'average_risk_score': sum(a.anomaly_score for a in unified_engine.assets.values()) / total_assets if total_assets > 0 else 0,
            'last_updated': datetime.now().isoformat()
        }
        
        return jsonify(summary)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/assets')
def get_assets():
    """API endpoint for asset inventory"""
    try:
        assets_list = []
        
        for asset in unified_engine.assets.values():
            asset_data = {
                'asset_id': asset.asset_id,
                'name': asset.name,
                'type': asset.asset_type.value,
                'ip_address': asset.ip_address,
                'hostname': asset.hostname,
                'cloud_provider': asset.cloud_provider,
                'cloud_region': asset.cloud_region,
                'criticality': asset.criticality.value,
                'compliance_status': asset.compliance_status.value,
                'threat_status': asset.threat_status.value,
                'anomaly_score': asset.anomaly_score,
                'tags': asset.tags,
                'last_compliance_scan': asset.last_compliance_scan.isoformat() if asset.last_compliance_scan else None,
                'last_threat_scan': asset.last_threat_scan.isoformat() if asset.last_threat_scan else None
            }
            assets_list.append(asset_data)
        
        # Apply filters
        provider_filter = request.args.get('provider')
        criticality_filter = request.args.get('criticality')
        status_filter = request.args.get('status')
        
        if provider_filter:
            assets_list = [a for a in assets_list if a['cloud_provider'] == provider_filter]
        
        if criticality_filter:
            assets_list = [a for a in assets_list if a['criticality'] == criticality_filter]
        
        if status_filter:
            if status_filter in ['compliant', 'partial', 'non_compliant']:
                assets_list = [a for a in assets_list if a['compliance_status'] == status_filter]
            elif status_filter in ['active', 'investigating', 'resolved']:
                assets_list = [a for a in assets_list if a['threat_status'] == status_filter]
        
        return jsonify({
            'total_assets': len(assets_list),
            'assets': assets_list,
            'filters_applied': {
                'provider': provider_filter,
                'criticality': criticality_filter,
                'status': status_filter
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/unified-scan', methods=['POST'])
def start_unified_scan():
    """API endpoint to start unified compliance and threat hunting scan"""
    try:
        request_data = request.get_json()
        
        # Parse scan configuration
        scan_config = {
            'providers': request_data.get('providers', ['all']),
            'frameworks': request_data.get('frameworks', ['soc2']),
            'hunting_rules': request_data.get('hunting_rules', []),
            'scan_type': request_data.get('scan_type', 'unified')  # unified, compliance, threat
        }
        
        # Start scan asynchronously
        def run_scan():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                scan_result = loop.run_until_complete(
                    unified_engine.execute_unified_scan(scan_config)
                )
                return scan_result
            finally:
                loop.close()
        
        # Execute scan in thread to avoid blocking
        scan_thread = Thread(target=run_scan)
        scan_thread.start()
        
        # Return immediate response with scan ID
        scan_id = f"UNIFIED-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'scan_type': scan_config['scan_type'],
            'started_at': datetime.now().isoformat(),
            'estimated_duration_minutes': 10,
            'message': 'Unified scan started successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': 'Failed to start unified scan',
            'message': str(e)
        }), 500

@app.route('/api/unified-scan/<scan_id>')
def get_unified_scan_status(scan_id):
    """API endpoint to get unified scan status and results"""
    try:
        scan_status = unified_engine.get_scan_status(scan_id)
        
        if not scan_status:
            return jsonify({'error': 'Scan not found'}), 404
        
        return jsonify(scan_status)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings')
def get_findings():
    """API endpoint for unified findings (compliance + threat)"""
    try:
        all_findings = []
        
        # Get findings from recent scans
        for scan in unified_engine.active_scans.values():
            for finding in scan.findings:
                finding_data = {
                    'finding_id': finding.finding_id,
                    'title': finding.title,
                    'description': finding.description,
                    'finding_type': finding.finding_type,
                    'severity': finding.severity.value,
                    'status': finding.status,
                    'affected_assets': finding.affected_assets,
                    'created_at': finding.created_at.isoformat(),
                    'risk_score': finding.calculate_risk_score(),
                    
                    # Compliance specific
                    'compliance_framework': finding.compliance_framework,
                    'control_id': finding.control_id,
                    'compliance_score': finding.compliance_score,
                    
                    # Threat specific
                    'hunting_rule': finding.hunting_rule,
                    'mitre_techniques': finding.mitre_techniques,
                    'confidence_score': finding.confidence_score,
                    'iocs': finding.iocs,
                    
                    # Integrations
                    'misp_event_id': finding.misp_event_id,
                    'thehive_case_id': finding.thehive_case_id
                }
                all_findings.append(finding_data)
        
        # Apply filters
        finding_type = request.args.get('type')  # compliance, threat, hybrid
        severity = request.args.get('severity')
        status = request.args.get('status')
        min_risk_score = float(request.args.get('min_risk_score', 0))
        
        if finding_type:
            all_findings = [f for f in all_findings if f['finding_type'] == finding_type]
        
        if severity:
            all_findings = [f for f in all_findings if f['severity'] == severity]
        
        if status:
            all_findings = [f for f in all_findings if f['status'] == status]
        
        if min_risk_score > 0:
            all_findings = [f for f in all_findings if f['risk_score'] >= min_risk_score]
        
        # Sort by risk score (highest first)
        all_findings.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return jsonify({
            'total_findings': len(all_findings),
            'findings': all_findings,
            'summary': {
                'critical': len([f for f in all_findings if f['severity'] == 'critical']),
                'high': len([f for f in all_findings if f['severity'] == 'high']),
                'medium': len([f for f in all_findings if f['severity'] == 'medium']),
                'low': len([f for f in all_findings if f['severity'] == 'low'])
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/asset-risk/<asset_id>')
def get_asset_risk(asset_id):
    """API endpoint for detailed asset risk profile"""
    try:
        risk_profile = unified_engine.get_asset_risk_profile(asset_id)
        
        if not risk_profile:
            return jsonify({'error': 'Asset not found'}), 404
        
        return jsonify(risk_profile)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/soc-integration/misp/submit', methods=['POST'])
def submit_to_misp():
    """API endpoint to submit threat indicators to MISP"""
    try:
        if not misp_connector:
            return jsonify({'error': 'MISP integration not configured'}), 400
        
        request_data = request.get_json()
        finding_id = request_data.get('finding_id')
        
        # Find the threat finding
        threat_finding = None
        for scan in unified_engine.active_scans.values():
            for finding in scan.findings:
                if finding.finding_id == finding_id and finding.finding_type in ['threat', 'hybrid']:
                    threat_finding = finding
                    break
        
        if not threat_finding:
            return jsonify({'error': 'Threat finding not found'}), 404
        
        # Create MISP event from finding
        hunting_result = {
            'hunting_type': threat_finding.hunting_rule or 'unknown',
            'risk_score': threat_finding.calculate_risk_score(),
            'description': threat_finding.description,
            'mitre_techniques': threat_finding.mitre_techniques,
            'matched_assets': [{'ip_address': '10.0.1.100'}]  # Simplified
        }
        
        event_uuid = misp_connector.create_event(hunting_result)
        
        if event_uuid:
            # Update finding with MISP event ID
            threat_finding.misp_event_id = event_uuid
            
            return jsonify({
                'success': True,
                'misp_event_uuid': event_uuid,
                'message': 'Successfully submitted to MISP'
            })
        else:
            return jsonify({'error': 'Failed to create MISP event'}), 500
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/soc-integration/thehive/create-case', methods=['POST'])
def create_thehive_case():
    """API endpoint to create TheHive case from finding"""
    try:
        if not thehive_connector:
            return jsonify({'error': 'TheHive integration not configured'}), 400
        
        request_data = request.get_json()
        finding_id = request_data.get('finding_id')
        
        # Find the finding
        target_finding = None
        for scan in unified_engine.active_scans.values():
            for finding in scan.findings:
                if finding.finding_id == finding_id:
                    target_finding = finding
                    break
        
        if not target_finding:
            return jsonify({'error': 'Finding not found'}), 404
        
        # Create TheHive case (would use actual connector)
        case_id = f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Update finding with case ID
        target_finding.thehive_case_id = case_id
        
        return jsonify({
            'success': True,
            'case_id': case_id,
            'case_url': f'https://thehive.company.com/cases/{case_id}',
            'message': 'Successfully created TheHive case'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-intelligence/correlate', methods=['POST'])
def correlate_threat_intelligence():
    """API endpoint for threat intelligence correlation"""
    try:
        request_data = request.get_json()
        ioc_value = request_data.get('ioc_value')
        ioc_type = request_data.get('ioc_type', 'ip')
        
        # Correlate with MISP if available
        correlation_results = {
            'ioc_value': ioc_value,
            'ioc_type': ioc_type,
            'sources': [],
            'threat_score': 0.0,
            'recommendations': []
        }
        
        if misp_connector:
            misp_results = misp_connector.enrich_with_misp(ioc_value)
            if misp_results.get('found'):
                correlation_results['sources'].append({
                    'name': 'MISP',
                    'events': misp_results.get('events', []),
                    'confidence': 85.0
                })
                correlation_results['threat_score'] += 30.0
        
        # Add other TI sources as needed
        
        # Generate recommendations
        if correlation_results['threat_score'] > 70:
            correlation_results['recommendations'].extend([
                'Block IOC at network perimeter',
                'Investigate affected assets',
                'Create incident response case'
            ])
        
        return jsonify(correlation_results)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tenant/profile')
def get_tenant_profile():
    """API endpoint to get current tenant profile"""
    try:
        client_id = get_client_id_from_request(request)
        tenant_context = tenant_manager.get_tenant_context(client_id)
        
        if not tenant_context:
            return jsonify({'error': 'Tenant not found'}), 404
        
        return jsonify(tenant_context)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tenant/usage')
def get_tenant_usage():
    """API endpoint to get tenant usage summary"""
    try:
        client_id = get_client_id_from_request(request)
        usage_summary = tenant_manager.get_tenant_usage_summary(client_id)
        
        if not usage_summary:
            return jsonify({'error': 'Tenant not found'}), 404
        
        return jsonify(usage_summary)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tenant/organizations')
def get_managed_organizations():
    """API endpoint for MSP tenants to get managed organizations"""
    try:
        client_id = get_client_id_from_request(request)
        organizations = tenant_manager.get_organizations_for_msp(client_id)
        
        return jsonify({
            'total_organizations': len(organizations),
            'organizations': organizations
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tenant/switch', methods=['POST'])
def switch_tenant_context():
    """API endpoint to switch tenant context (for MSP users)"""
    try:
        request_data = request.get_json()
        target_client_id = request_data.get('target_client_id')
        
        if not target_client_id:
            return jsonify({'error': 'target_client_id required'}), 400
        
        # Validate target tenant exists
        target_tenant = tenant_manager.get_tenant(target_client_id)
        if not target_tenant:
            return jsonify({'error': 'Target tenant not found'}), 404
        
        # In a real implementation, you'd validate MSP permissions here
        
        # Set new tenant context in session
        session['client_id'] = target_client_id
        
        return jsonify({
            'success': True,
            'new_context': tenant_manager.get_tenant_context(target_client_id)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tenant/create', methods=['POST'])
def create_new_tenant():
    """API endpoint to create new tenant (MSP only)"""
    try:
        current_client_id = get_client_id_from_request(request)
        current_tenant = tenant_manager.get_tenant(current_client_id)
        
        # Validate MSP permissions
        if not current_tenant or current_tenant.tier != TenantTier.MSP:
            return jsonify({'error': 'Insufficient permissions'}), 403
        
        request_data = request.get_json()
        organization_name = request_data.get('organization_name')
        email = request_data.get('email')
        tier = TenantTier(request_data.get('tier', 'starter'))
        
        if not organization_name or not email:
            return jsonify({'error': 'organization_name and email required'}), 400
        
        new_client_id = tenant_manager.create_tenant(organization_name, email, tier)
        
        return jsonify({
            'success': True,
            'client_id': new_client_id,
            'tenant_context': tenant_manager.get_tenant_context(new_client_id)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/tenants')
def admin_list_tenants():
    """Admin endpoint to list all tenants"""
    try:
        # In production, add proper admin authentication
        tenants_list = []
        
        for client_id, tenant in tenant_manager.tenants.items():
            tenant_info = {
                'client_id': client_id,
                'organization_name': tenant.organization_name,
                'tier': tenant.tier.value,
                'status': tenant.status.value,
                'created_at': tenant.created_at.isoformat(),
                'asset_count': tenant.monthly_usage.get('assets', 0),
                'scan_count': tenant.monthly_usage.get('scans', 0)
            }
            tenants_list.append(tenant_info)
        
        return jsonify({
            'total_tenants': len(tenants_list),
            'tenants': tenants_list
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/compliance/analytics')
def compliance_analytics():
    """Get compliance analytics and trends"""
    try:
        client_id = get_client_id_from_request()
        
        # Get query parameters
        time_window = request.args.get('time_window', 'weekly')
        lookback_days = int(request.args.get('lookback_days', 30))
        
        analytics = unified_engine.get_compliance_analytics(
            client_id=client_id,
            time_window=time_window,
            lookback_days=lookback_days
        )
        
        return jsonify(analytics)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/compliance/search')
def compliance_search():
    """Semantic search of compliance history"""
    try:
        client_id = get_client_id_from_request()
        query = request.args.get('q', '')
        limit = int(request.args.get('limit', 10))
        
        if not query:
            return jsonify({'error': 'Search query required'}), 400
        
        results = unified_engine.search_compliance_history(
            query=query,
            client_id=client_id,
            limit=limit
        )
        
        return jsonify({
            'query': query,
            'results': results,
            'total': len(results)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/compliance/scores')
def compliance_scores():
    """Query compliance scores with filters"""
    try:
        client_id = get_client_id_from_request()
        
        # Build filters from query parameters
        filters = {'client_id': client_id}
        
        if request.args.get('provider'):
            filters['provider'] = request.args.get('provider')
        if request.args.get('control'):
            filters['control'] = request.args.get('control')
        if request.args.get('framework'):
            filters['framework'] = request.args.get('framework')
        if request.args.get('min_score'):
            filters['min_score'] = float(request.args.get('min_score'))
        if request.args.get('max_score'):
            filters['max_score'] = float(request.args.get('max_score'))
        if request.args.get('limit'):
            filters['limit'] = int(request.args.get('limit'))
        
        # Parse since_date if provided
        if request.args.get('since_date'):
            from datetime import datetime
            filters['since_date'] = datetime.fromisoformat(request.args.get('since_date'))
        
        scores = unified_engine.query_compliance_scores(filters)
        
        return jsonify({
            'filters': {k: str(v) for k, v in filters.items()},
            'scores': scores,
            'total': len(scores)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tpu/status')
def tpu_status():
    """Get TPU acceleration status and performance metrics"""
    try:
        if unified_engine.tpu_acceleration_enabled:
            metrics = unified_engine.get_tpu_performance_metrics()
            health = unified_engine.coral_engine.health_check()
            
            return jsonify({
                'tpu_enabled': True,
                'status': 'healthy' if health['overall_status'] == 'healthy' else 'degraded',
                'metrics': metrics,
                'health_check': health
            })
        else:
            return jsonify({
                'tpu_enabled': False,
                'status': 'unavailable',
                'message': 'Coral TPU acceleration not available'
            })
            
    except Exception as e:
        return jsonify({
            'tpu_enabled': False,
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/api/tpu/batch-analysis', methods=['POST'])
def tpu_batch_analysis():
    """Run batch TPU-accelerated analysis"""
    try:
        if not unified_engine.tpu_acceleration_enabled:
            return jsonify({'error': 'TPU acceleration not available'}), 400
        
        data = request.get_json()
        asset_ids = data.get('asset_ids', [])
        analysis_types = data.get('analysis_types', ['compliance', 'threat', 'anomaly'])
        
        if not asset_ids:
            return jsonify({'error': 'asset_ids required'}), 400
        
        # Run batch analysis
        results = unified_engine.run_tpu_batch_analysis(asset_ids, analysis_types)
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tpu/benchmark')
def tpu_benchmark():
    """Run TPU performance benchmark"""
    try:
        if not unified_engine.tpu_acceleration_enabled:
            return jsonify({'error': 'TPU acceleration not available'}), 400
        
        iterations = int(request.args.get('iterations', 50))
        
        # Run benchmark
        benchmark_results = unified_engine.coral_engine.benchmark_acceleration(iterations)
        
        return jsonify({
            'benchmark_results': benchmark_results,
            'iterations': iterations,
            'summary': {
                'average_acceleration': sum(r.get('acceleration_factor', 1.0) 
                                          for r in benchmark_results.values() 
                                          if isinstance(r, dict)) / len(benchmark_results) if benchmark_results else 1.0,
                'models_tested': len(benchmark_results)
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/accelerated', methods=['POST'])
def accelerated_analytics():
    """Run accelerated analytics on single asset"""
    try:
        client_id = get_client_id_from_request()
        data = request.get_json()
        
        asset_id = data.get('asset_id')
        analysis_type = data.get('analysis_type', 'compliance')
        
        if not asset_id:
            return jsonify({'error': 'asset_id required'}), 400
        
        if not unified_engine.tpu_acceleration_enabled:
            return jsonify({'error': 'TPU acceleration not available'}), 400
        
        # Get asset
        if asset_id not in unified_engine.assets:
            return jsonify({'error': 'Asset not found'}), 404
        
        asset = unified_engine.assets[asset_id]
        
        # Run appropriate accelerated analysis
        if analysis_type == 'compliance':
            evidence = data.get('evidence', {})
            control_id = data.get('control_id', 'CC6.1')
            
            import asyncio
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(
                unified_engine.accelerated_analytics.analyze_compliance_accelerated(
                    asset, evidence, control_id, client_id
                )
            )
            
        elif analysis_type == 'threat':
            behavioral_data = data.get('behavioral_data', {})
            
            import asyncio
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(
                unified_engine.accelerated_analytics.analyze_threat_accelerated(
                    asset, behavioral_data
                )
            )
            
        elif analysis_type == 'anomaly':
            metrics_data = data.get('metrics_data', {})
            
            import asyncio
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(
                unified_engine.accelerated_analytics.analyze_anomaly_accelerated(
                    asset, metrics_data
                )
            )
            
        elif analysis_type == 'risk':
            comprehensive_data = data.get('comprehensive_data', {})
            
            import asyncio
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(
                unified_engine.accelerated_analytics.analyze_risk_accelerated(
                    asset, comprehensive_data
                )
            )
            
        else:
            return jsonify({'error': 'Invalid analysis_type'}), 400
        
        # Convert result to JSON-serializable format
        result_dict = {
            'analysis_type': result.analysis_type,
            'asset_id': result.asset_id,
            'scores': result.scores,
            'predictions': result.predictions,
            'confidence_level': result.confidence_level,
            'processing_time_ms': result.processing_time_ms,
            'tpu_acceleration': result.tpu_acceleration,
            'acceleration_factor': result.acceleration_factor,
            'timestamp': result.timestamp,
            'recommendations': result.recommendations,
            'risk_factors': result.risk_factors
        }
        
        return jsonify(result_dict)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tpu/status')
def tpu_status():
    """Get TPU acceleration status"""
    try:
        status = unified_engine.get_tpu_acceleration_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tpu/health')
def tpu_health():
    """Run TPU health check"""
    try:
        health = unified_engine.run_tpu_health_check()
        return jsonify(health)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tpu/metrics')
def tpu_metrics():
    """Get TPU performance metrics"""
    try:
        if hasattr(unified_engine, 'get_tpu_performance_metrics'):
            metrics = unified_engine.get_tpu_performance_metrics()
        else:
            # Fallback to basic TPU status
            metrics = {
                'tpu_available': unified_engine.tpu_available,
                'message': 'Detailed metrics not available'
            }
        return jsonify(metrics)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tpu/benchmark', methods=['POST'])
def tpu_benchmark():
    """Run TPU acceleration benchmark"""
    try:
        if hasattr(unified_engine, 'run_tpu_benchmark'):
            benchmark_results = unified_engine.run_tpu_benchmark()
        else:
            benchmark_results = {'error': 'TPU benchmarking not available'}
        return jsonify(benchmark_results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ========== Post-Quantum Cryptography Endpoints ==========

@app.route('/api/post-quantum/status')
def post_quantum_status():
    """Get post-quantum cryptography system status"""
    try:
        if pq_integration_manager:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            status = loop.run_until_complete(pq_integration_manager.get_system_status())
            loop.close()
            return jsonify(status)
        else:
            return jsonify({
                'error': 'Post-quantum integration not available',
                'system': {'initialized': False}
            }), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/post-quantum/dashboard-data')
def post_quantum_dashboard_data():
    """Get comprehensive post-quantum dashboard data"""
    try:
        if pq_integration_manager:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            dashboard_data = loop.run_until_complete(pq_integration_manager.get_quantum_dashboard_data())
            loop.close()
            return jsonify(dashboard_data)
        else:
            return jsonify({'error': 'Post-quantum integration not available'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/post-quantum/compliance-assessment', methods=['POST'])
def post_quantum_compliance_assessment():
    """Conduct quantum readiness compliance assessment"""
    try:
        if not pq_integration_manager:
            return jsonify({'error': 'Post-quantum integration not available'}), 503
        
        tenant_id = get_client_id_from_request(request)
        if not tenant_id:
            return jsonify({'error': 'No tenant ID provided'}), 400
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        assessment = loop.run_until_complete(
            pq_integration_manager.conduct_quantum_readiness_assessment(tenant_id)
        )
        loop.close()
        return jsonify(assessment)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/post-quantum/encrypt-data', methods=['POST'])
def post_quantum_encrypt_data():
    """Encrypt data with post-quantum algorithms"""
    try:
        if not pq_integration_manager:
            return jsonify({'error': 'Post-quantum integration not available'}), 503
        
        data = request.json
        if not data or 'data' not in data:
            return jsonify({'error': 'No data provided'}), 400
        
        context = data.get('context', 'api_request')
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        encrypted = loop.run_until_complete(
            pq_integration_manager.encrypt_sensitive_data(data['data'], context)
        )
        loop.close()
        return jsonify({'encrypted_data': encrypted, 'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/post-quantum/integration-summary')
def post_quantum_integration_summary():
    """Get post-quantum integration summary"""
    try:
        if pq_integration_manager:
            summary = pq_integration_manager.get_integration_summary()
            return jsonify(summary)
        else:
            return jsonify({
                'integration_name': 'AuditHound Post-Quantum Cryptography',
                'initialized': False,
                'error': 'Integration not available'
            }), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/post-quantum/cleanup', methods=['POST'])
def post_quantum_cleanup():
    """Clean up expired post-quantum data"""
    try:
        if not pq_integration_manager:
            return jsonify({'error': 'Post-quantum integration not available'}), 503
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        cleanup_results = loop.run_until_complete(pq_integration_manager.cleanup_expired_data())
        loop.close()
        return jsonify(cleanup_results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)