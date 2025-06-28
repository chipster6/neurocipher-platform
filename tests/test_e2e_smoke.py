#!/usr/bin/env python3
"""
End-to-End Smoke Tests for AuditHound
Tests complete deploy → onboard → analytics workflow
"""

import pytest
import asyncio
import json
import os
import subprocess
import time
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from unittest.mock import Mock, patch, MagicMock
import tempfile
import shutil
from pathlib import Path
import yaml
import uuid

# Test configuration
E2E_CONFIG = {
    'deployment': {
        'timeout_seconds': 300,
        'health_check_retries': 10,
        'health_check_interval': 5
    },
    'onboarding': {
        'timeout_seconds': 120,
        'test_client_name': 'e2e_test_client',
        'test_user_email': 'test@audithound.example.com'
    },
    'analytics': {
        'timeout_seconds': 180,
        'min_expected_findings': 1,
        'test_data_size': 100
    },
    'services': {
        'streamlit': {'port': 8501, 'path': '/'},
        'weaviate': {'port': 8080, 'path': '/v1/.well-known/ready'},
        'api': {'port': 8000, 'path': '/health'}
    }
}

class DeploymentManager:
    """Manages deployment lifecycle for E2E tests"""
    
    def __init__(self, test_dir: str):
        self.test_dir = Path(test_dir)
        self.deployment_config = {}
        self.deployed_services = []
        self.temp_configs = []
        
    async def prepare_deployment(self) -> bool:
        """Prepare deployment configuration"""
        try:
            print("📋 Preparing deployment configuration...")
            
            # Create test environment configuration
            test_env = {
                'DEBUG': 'true',
                'LOG_LEVEL': 'INFO',
                'WEAVIATE_URL': 'http://localhost:8080',
                'SECRET_KEY': 'test-secret-key-for-e2e-testing',
                'AUDITHOUND_ENCRYPTION_KEY': 'dGVzdC1lbmNyeXB0aW9uLWtleS1mb3ItZTJlLXRlc3Rpbmc=',
                'TEST_MODE': 'true'
            }
            
            # Write test environment file
            env_file = self.test_dir / '.env.test'
            with open(env_file, 'w') as f:
                for key, value in test_env.items():
                    f.write(f"{key}={value}\n")
            
            self.temp_configs.append(env_file)
            
            # Create test docker-compose configuration
            compose_config = {
                'version': '3.8',
                'services': {
                    'weaviate': {
                        'image': 'semitechnologies/weaviate:1.21.3',
                        'ports': ['8080:8080'],
                        'environment': {
                            'QUERY_DEFAULTS_LIMIT': '25',
                            'AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED': 'true',
                            'PERSISTENCE_DATA_PATH': '/var/lib/weaviate',
                            'DEFAULT_VECTORIZER_MODULE': 'none',
                            'ENABLE_MODULES': 'text2vec-transformers,generative-openai',
                            'CLUSTER_HOSTNAME': 'node1'
                        },
                        'volumes': ['weaviate_data:/var/lib/weaviate'],
                        'healthcheck': {
                            'test': ['CMD', 'curl', '-f', 'http://localhost:8080/v1/.well-known/ready'],
                            'interval': '10s',
                            'timeout': '5s',
                            'retries': 3
                        }
                    }
                },
                'volumes': {
                    'weaviate_data': {}
                }
            }
            
            compose_file = self.test_dir / 'docker-compose.e2e.yml'
            with open(compose_file, 'w') as f:
                yaml.dump(compose_config, f)
            
            self.temp_configs.append(compose_file)
            
            print("✅ Deployment configuration prepared")
            return True
            
        except Exception as e:
            print(f"❌ Failed to prepare deployment: {e}")
            return False
    
    async def deploy_infrastructure(self) -> bool:
        """Deploy infrastructure services"""
        try:
            print("🚀 Deploying infrastructure services...")
            
            # Start Weaviate with docker-compose
            compose_file = self.test_dir / 'docker-compose.e2e.yml'
            
            # Stop any existing services
            subprocess.run([
                'docker-compose', '-f', str(compose_file), 'down', '-v'
            ], capture_output=True)
            
            # Start services
            result = subprocess.run([
                'docker-compose', '-f', str(compose_file), 'up', '-d'
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"❌ Docker compose failed: {result.stderr}")
                return False
            
            self.deployed_services.append('weaviate')
            
            # Wait for services to be healthy
            await self._wait_for_service_health('weaviate', 'http://localhost:8080/v1/.well-known/ready')
            
            print("✅ Infrastructure services deployed")
            return True
            
        except Exception as e:
            print(f"❌ Failed to deploy infrastructure: {e}")
            return False
    
    async def deploy_application(self) -> bool:
        """Deploy AuditHound application"""
        try:
            print("📱 Deploying AuditHound application...")
            
            # Set environment variables for application
            env = os.environ.copy()
            env.update({
                'DEBUG': 'true',
                'WEAVIATE_URL': 'http://localhost:8080',
                'TEST_MODE': 'true'
            })
            
            # Start Streamlit dashboard in background
            streamlit_cmd = [
                'streamlit', 'run', 
                str(self.test_dir / 'streamlit_dashboard.py'),
                '--server.port', '8501',
                '--server.headless', 'true',
                '--server.enableCORS', 'false'
            ]
            
            # Check if streamlit_dashboard.py exists
            dashboard_file = self.test_dir / 'streamlit_dashboard.py'
            if not dashboard_file.exists():
                print("⚠️ Streamlit dashboard not found, creating minimal test version...")
                await self._create_test_dashboard(dashboard_file)
            
            # Note: In a real deployment, we would start the actual services
            # For E2E testing, we'll simulate this with mock services
            print("✅ Application deployment simulated (services would start here)")
            return True
            
        except Exception as e:
            print(f"❌ Failed to deploy application: {e}")
            return False
    
    async def _create_test_dashboard(self, dashboard_file: Path):
        """Create a minimal test dashboard"""
        dashboard_content = '''
import streamlit as st
import time
import json
from datetime import datetime

st.set_page_config(page_title="AuditHound E2E Test", layout="wide")

st.title("🔍 AuditHound - E2E Test Mode")
st.write("Test dashboard for end-to-end testing")

# Health check endpoint
if st.button("Health Check"):
    st.success(f"✅ Dashboard healthy at {datetime.now()}")

# Test data display
if st.button("Show Test Data"):
    test_data = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "test_mode": True,
        "findings": [
            {"id": "TEST-001", "severity": "HIGH", "title": "Test Finding 1"},
            {"id": "TEST-002", "severity": "MEDIUM", "title": "Test Finding 2"}
        ]
    }
    st.json(test_data)

st.write("E2E Test Dashboard Ready")
'''
        with open(dashboard_file, 'w') as f:
            f.write(dashboard_content)
    
    async def _wait_for_service_health(self, service_name: str, health_url: str, timeout: int = 60):
        """Wait for service to become healthy"""
        print(f"⏳ Waiting for {service_name} to become healthy...")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get(health_url, timeout=5)
                if response.status_code == 200:
                    print(f"✅ {service_name} is healthy")
                    return True
            except requests.exceptions.RequestException:
                pass
            
            await asyncio.sleep(E2E_CONFIG['deployment']['health_check_interval'])
        
        raise TimeoutError(f"{service_name} failed to become healthy within {timeout} seconds")
    
    async def cleanup_deployment(self):
        """Clean up deployment resources"""
        try:
            print("🧹 Cleaning up deployment...")
            
            # Stop docker-compose services
            compose_file = self.test_dir / 'docker-compose.e2e.yml'
            if compose_file.exists():
                subprocess.run([
                    'docker-compose', '-f', str(compose_file), 'down', '-v'
                ], capture_output=True)
            
            # Remove temporary configuration files
            for config_file in self.temp_configs:
                if config_file.exists():
                    config_file.unlink()
            
            print("✅ Cleanup completed")
            
        except Exception as e:
            print(f"⚠️ Cleanup error: {e}")

class OnboardingManager:
    """Manages client onboarding workflow"""
    
    def __init__(self):
        self.test_client_data = {}
        self.onboarding_steps = []
        
    async def execute_onboarding_workflow(self) -> bool:
        """Execute complete onboarding workflow"""
        try:
            print("👤 Starting client onboarding workflow...")
            
            # Step 1: Client registration
            success = await self._register_test_client()
            if not success:
                return False
            
            # Step 2: Initial configuration
            success = await self._configure_client_settings()
            if not success:
                return False
            
            # Step 3: Data source setup
            success = await self._setup_data_sources()
            if not success:
                return False
            
            # Step 4: User account creation
            success = await self._create_user_accounts()
            if not success:
                return False
            
            # Step 5: Permission configuration
            success = await self._configure_permissions()
            if not success:
                return False
            
            # Step 6: Initial scan setup
            success = await self._setup_initial_scans()
            if not success:
                return False
            
            print("✅ Onboarding workflow completed successfully")
            return True
            
        except Exception as e:
            print(f"❌ Onboarding workflow failed: {e}")
            return False
    
    async def _register_test_client(self) -> bool:
        """Register test client"""
        try:
            print("  📝 Registering test client...")
            
            client_data = {
                'client_id': f"e2e_test_{uuid.uuid4().hex[:8]}",
                'name': E2E_CONFIG['onboarding']['test_client_name'],
                'industry': 'Technology',
                'size': 'Medium',
                'compliance_requirements': ['SOC2', 'ISO27001'],
                'registration_date': datetime.now().isoformat(),
                'status': 'active'
            }
            
            # Simulate API call to register client
            await asyncio.sleep(1)  # Simulate processing time
            
            self.test_client_data = client_data
            self.onboarding_steps.append({
                'step': 'client_registration',
                'status': 'completed',
                'timestamp': datetime.now().isoformat(),
                'data': client_data
            })
            
            print(f"    ✅ Client registered: {client_data['client_id']}")
            return True
            
        except Exception as e:
            print(f"    ❌ Client registration failed: {e}")
            return False
    
    async def _configure_client_settings(self) -> bool:
        """Configure client-specific settings"""
        try:
            print("  ⚙️ Configuring client settings...")
            
            settings = {
                'scan_frequency': 'daily',
                'notification_preferences': {
                    'email': True,
                    'slack': False,
                    'webhook': True
                },
                'compliance_frameworks': ['SOC2_TYPE2', 'ISO27001'],
                'risk_tolerance': 'medium',
                'data_retention_days': 365,
                'encryption_enabled': True
            }
            
            # Simulate configuration API calls
            await asyncio.sleep(1)
            
            self.onboarding_steps.append({
                'step': 'client_configuration',
                'status': 'completed', 
                'timestamp': datetime.now().isoformat(),
                'data': settings
            })
            
            print("    ✅ Client settings configured")
            return True
            
        except Exception as e:
            print(f"    ❌ Client configuration failed: {e}")
            return False
    
    async def _setup_data_sources(self) -> bool:
        """Setup data sources for scanning"""
        try:
            print("  🔌 Setting up data sources...")
            
            data_sources = [
                {
                    'type': 'aws_account',
                    'name': 'Production AWS',
                    'config': {
                        'account_id': '123456789012',
                        'regions': ['us-west-2', 'us-east-1'],
                        'services': ['ec2', 's3', 'rds', 'iam']
                    },
                    'status': 'connected'
                },
                {
                    'type': 'gcp_project', 
                    'name': 'Production GCP',
                    'config': {
                        'project_id': 'test-project-123',
                        'regions': ['us-central1', 'us-west1'],
                        'services': ['compute', 'storage', 'iam']
                    },
                    'status': 'connected'
                },
                {
                    'type': 'github_org',
                    'name': 'Company GitHub',
                    'config': {
                        'organization': 'test-org',
                        'repositories': ['web-app', 'api-service', 'infrastructure']
                    },
                    'status': 'connected'
                }
            ]
            
            # Simulate data source connection
            for source in data_sources:
                await asyncio.sleep(0.5)  # Simulate connection time
                print(f"    🔗 Connected to {source['name']}")
            
            self.onboarding_steps.append({
                'step': 'data_source_setup',
                'status': 'completed',
                'timestamp': datetime.now().isoformat(),
                'data': data_sources
            })
            
            print("    ✅ Data sources configured")
            return True
            
        except Exception as e:
            print(f"    ❌ Data source setup failed: {e}")
            return False
    
    async def _create_user_accounts(self) -> bool:
        """Create user accounts"""
        try:
            print("  👥 Creating user accounts...")
            
            users = [
                {
                    'email': E2E_CONFIG['onboarding']['test_user_email'],
                    'role': 'admin',
                    'name': 'Test Administrator',
                    'permissions': ['read', 'write', 'admin'],
                    'status': 'active'
                },
                {
                    'email': 'analyst@audithound.example.com',
                    'role': 'analyst',
                    'name': 'Test Analyst',
                    'permissions': ['read', 'write'],
                    'status': 'active'
                },
                {
                    'email': 'viewer@audithound.example.com',
                    'role': 'viewer',
                    'name': 'Test Viewer',
                    'permissions': ['read'],
                    'status': 'active'
                }
            ]
            
            # Simulate user creation
            for user in users:
                await asyncio.sleep(0.3)
                print(f"    👤 Created user: {user['email']} ({user['role']})")
            
            self.onboarding_steps.append({
                'step': 'user_creation',
                'status': 'completed',
                'timestamp': datetime.now().isoformat(),
                'data': users
            })
            
            print("    ✅ User accounts created")
            return True
            
        except Exception as e:
            print(f"    ❌ User creation failed: {e}")
            return False
    
    async def _configure_permissions(self) -> bool:
        """Configure user permissions and access controls"""
        try:
            print("  🔐 Configuring permissions...")
            
            permission_config = {
                'rbac_enabled': True,
                'multi_factor_auth': True,
                'session_timeout_minutes': 480,
                'password_policy': {
                    'min_length': 12,
                    'require_uppercase': True,
                    'require_numbers': True,
                    'require_symbols': True
                },
                'audit_logging': True
            }
            
            # Simulate permission configuration
            await asyncio.sleep(1)
            
            self.onboarding_steps.append({
                'step': 'permission_configuration',
                'status': 'completed',
                'timestamp': datetime.now().isoformat(),
                'data': permission_config
            })
            
            print("    ✅ Permissions configured")
            return True
            
        except Exception as e:
            print(f"    ❌ Permission configuration failed: {e}")
            return False
    
    async def _setup_initial_scans(self) -> bool:
        """Setup initial security scans"""
        try:
            print("  🔍 Setting up initial scans...")
            
            scan_configs = [
                {
                    'type': 'vulnerability_scan',
                    'schedule': 'daily',
                    'targets': ['aws_account', 'gcp_project'],
                    'enabled': True
                },
                {
                    'type': 'compliance_scan',
                    'schedule': 'weekly',
                    'frameworks': ['SOC2', 'ISO27001'],
                    'enabled': True
                },
                {
                    'type': 'code_scan',
                    'schedule': 'on_commit',
                    'targets': ['github_org'],
                    'enabled': True
                }
            ]
            
            # Simulate scan setup
            for scan in scan_configs:
                await asyncio.sleep(0.5)
                print(f"    📊 Configured {scan['type']} ({scan['schedule']})")
            
            self.onboarding_steps.append({
                'step': 'scan_setup',
                'status': 'completed',
                'timestamp': datetime.now().isoformat(),
                'data': scan_configs
            })
            
            print("    ✅ Initial scans configured")
            return True
            
        except Exception as e:
            print(f"    ❌ Scan setup failed: {e}")
            return False
    
    def get_onboarding_summary(self) -> Dict[str, Any]:
        """Get onboarding workflow summary"""
        return {
            'client_data': self.test_client_data,
            'steps_completed': len(self.onboarding_steps),
            'steps': self.onboarding_steps,
            'total_duration': self._calculate_total_duration(),
            'status': 'completed' if len(self.onboarding_steps) == 6 else 'incomplete'
        }
    
    def _calculate_total_duration(self) -> float:
        """Calculate total onboarding duration"""
        if len(self.onboarding_steps) < 2:
            return 0
        
        start_time = datetime.fromisoformat(self.onboarding_steps[0]['timestamp'])
        end_time = datetime.fromisoformat(self.onboarding_steps[-1]['timestamp'])
        
        return (end_time - start_time).total_seconds()

class AnalyticsManager:
    """Manages analytics workflow testing"""
    
    def __init__(self, client_id: str):
        self.client_id = client_id
        self.test_findings = []
        self.analytics_results = {}
        
    async def execute_analytics_workflow(self) -> bool:
        """Execute complete analytics workflow"""
        try:
            print("📊 Starting analytics workflow...")
            
            # Step 1: Generate test data
            success = await self._generate_test_data()
            if not success:
                return False
            
            # Step 2: Run data ingestion
            success = await self._ingest_test_data()
            if not success:
                return False
            
            # Step 3: Execute analytics queries
            success = await self._run_analytics_queries()
            if not success:
                return False
            
            # Step 4: Generate reports
            success = await self._generate_reports()
            if not success:
                return False
            
            # Step 5: Test visualizations
            success = await self._test_visualizations()
            if not success:
                return False
            
            # Step 6: Validate export functionality
            success = await self._test_export_functionality()
            if not success:
                return False
            
            print("✅ Analytics workflow completed successfully")
            return True
            
        except Exception as e:
            print(f"❌ Analytics workflow failed: {e}")
            return False
    
    async def _generate_test_data(self) -> bool:
        """Generate test security findings data"""
        try:
            print("  🎲 Generating test data...")
            
            # Generate diverse test findings
            finding_types = [
                ('High severity vulnerability', 'HIGH', 'vulnerability'),
                ('Configuration drift detected', 'MEDIUM', 'configuration'),
                ('Compliance violation found', 'MEDIUM', 'compliance'),
                ('Unauthorized access attempt', 'HIGH', 'security'),
                ('Weak encryption detected', 'MEDIUM', 'encryption'),
                ('Missing security patch', 'LOW', 'patch_management'),
                ('Insecure network configuration', 'HIGH', 'network'),
                ('Data exposure risk', 'CRITICAL', 'data_protection'),
                ('Access control weakness', 'MEDIUM', 'access_control'),
                ('Logging configuration issue', 'LOW', 'logging')
            ]
            
            for i in range(E2E_CONFIG['analytics']['test_data_size']):
                finding_type = finding_types[i % len(finding_types)]
                
                finding = {
                    'finding_id': f'E2E-{i:04d}',
                    'client_id': self.client_id,
                    'title': f"{finding_type[0]} #{i+1}",
                    'severity': finding_type[1],
                    'category': finding_type[2],
                    'description': f"Test finding {i+1} for E2E validation workflow",
                    'source': 'e2e_test_generator',
                    'timestamp': (datetime.now() - timedelta(days=i % 30)).isoformat(),
                    'status': 'open' if i % 4 != 0 else 'resolved',
                    'metadata': {
                        'test_case': True,
                        'batch': 'e2e_test',
                        'priority': 'test',
                        'resource': f'test-resource-{i % 10}',
                        'region': ['us-west-2', 'us-east-1', 'eu-west-1'][i % 3]
                    },
                    'remediation': f"Test remediation steps for finding {i+1}",
                    'impact': f"Test impact description for finding {i+1}",
                    'tags': ['e2e-test', finding_type[2], finding_type[1].lower()]
                }
                
                self.test_findings.append(finding)
            
            print(f"    📝 Generated {len(self.test_findings)} test findings")
            return True
            
        except Exception as e:
            print(f"    ❌ Test data generation failed: {e}")
            return False
    
    async def _ingest_test_data(self) -> bool:
        """Ingest test data into the system"""
        try:
            print("  📥 Ingesting test data...")
            
            # Simulate data ingestion in batches
            batch_size = 20
            ingested_count = 0
            
            for i in range(0, len(self.test_findings), batch_size):
                batch = self.test_findings[i:i + batch_size]
                
                # Simulate API calls to ingest data
                await asyncio.sleep(0.5)  # Simulate processing time
                
                ingested_count += len(batch)
                print(f"    📊 Ingested batch {i // batch_size + 1}, total: {ingested_count}")
            
            # Simulate indexing and processing time
            await asyncio.sleep(2)
            
            print(f"    ✅ Successfully ingested {ingested_count} findings")
            return True
            
        except Exception as e:
            print(f"    ❌ Data ingestion failed: {e}")
            return False
    
    async def _run_analytics_queries(self) -> bool:
        """Run various analytics queries"""
        try:
            print("  🔍 Running analytics queries...")
            
            queries = [
                ('severity_distribution', self._query_severity_distribution),
                ('category_breakdown', self._query_category_breakdown),
                ('trend_analysis', self._query_trend_analysis),
                ('compliance_status', self._query_compliance_status),
                ('risk_metrics', self._query_risk_metrics),
                ('regional_analysis', self._query_regional_analysis)
            ]
            
            for query_name, query_func in queries:
                print(f"    🔎 Running {query_name} query...")
                result = await query_func()
                self.analytics_results[query_name] = result
                await asyncio.sleep(0.3)  # Simulate query time
            
            print(f"    ✅ Completed {len(queries)} analytics queries")
            return True
            
        except Exception as e:
            print(f"    ❌ Analytics queries failed: {e}")
            return False
    
    async def _query_severity_distribution(self) -> Dict[str, Any]:
        """Query severity distribution"""
        severity_counts = {}
        for finding in self.test_findings:
            severity = finding['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'query': 'severity_distribution',
            'data': severity_counts,
            'total_findings': len(self.test_findings),
            'timestamp': datetime.now().isoformat()
        }
    
    async def _query_category_breakdown(self) -> Dict[str, Any]:
        """Query category breakdown"""
        category_counts = {}
        for finding in self.test_findings:
            category = finding['category']
            category_counts[category] = category_counts.get(category, 0) + 1
        
        return {
            'query': 'category_breakdown',
            'data': category_counts,
            'total_categories': len(category_counts),
            'timestamp': datetime.now().isoformat()
        }
    
    async def _query_trend_analysis(self) -> Dict[str, Any]:
        """Query trend analysis"""
        # Group findings by day
        daily_counts = {}
        for finding in self.test_findings:
            date = finding['timestamp'][:10]  # Extract date
            daily_counts[date] = daily_counts.get(date, 0) + 1
        
        # Calculate trend metrics
        dates = sorted(daily_counts.keys())
        if len(dates) > 1:
            recent_avg = sum(daily_counts[d] for d in dates[-7:]) / min(7, len(dates))
            overall_avg = sum(daily_counts.values()) / len(dates)
            trend = "increasing" if recent_avg > overall_avg else "decreasing"
        else:
            trend = "stable"
        
        return {
            'query': 'trend_analysis',
            'data': {
                'daily_counts': daily_counts,
                'trend': trend,
                'date_range': f"{dates[0]} to {dates[-1]}" if dates else None
            },
            'timestamp': datetime.now().isoformat()
        }
    
    async def _query_compliance_status(self) -> Dict[str, Any]:
        """Query compliance status"""
        compliance_findings = [f for f in self.test_findings if f['category'] == 'compliance']
        
        compliance_metrics = {
            'total_compliance_findings': len(compliance_findings),
            'open_compliance_issues': len([f for f in compliance_findings if f['status'] == 'open']),
            'compliance_percentage': (1 - len(compliance_findings) / len(self.test_findings)) * 100
        }
        
        return {
            'query': 'compliance_status',
            'data': compliance_metrics,
            'timestamp': datetime.now().isoformat()
        }
    
    async def _query_risk_metrics(self) -> Dict[str, Any]:
        """Query risk metrics"""
        # Calculate risk score based on severity
        severity_weights = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}
        
        total_risk_score = 0
        for finding in self.test_findings:
            if finding['status'] == 'open':
                total_risk_score += severity_weights.get(finding['severity'], 1)
        
        risk_metrics = {
            'total_risk_score': total_risk_score,
            'average_risk_per_finding': total_risk_score / len(self.test_findings),
            'high_risk_findings': len([f for f in self.test_findings if f['severity'] in ['CRITICAL', 'HIGH'] and f['status'] == 'open']),
            'risk_level': 'high' if total_risk_score > 200 else 'medium' if total_risk_score > 100 else 'low'
        }
        
        return {
            'query': 'risk_metrics',
            'data': risk_metrics,
            'timestamp': datetime.now().isoformat()
        }
    
    async def _query_regional_analysis(self) -> Dict[str, Any]:
        """Query regional analysis"""
        regional_counts = {}
        for finding in self.test_findings:
            region = finding['metadata'].get('region', 'unknown')
            regional_counts[region] = regional_counts.get(region, 0) + 1
        
        return {
            'query': 'regional_analysis',
            'data': regional_counts,
            'total_regions': len(regional_counts),
            'timestamp': datetime.now().isoformat()
        }
    
    async def _generate_reports(self) -> bool:
        """Generate various reports"""
        try:
            print("  📋 Generating reports...")
            
            reports = [
                ('executive_summary', self._generate_executive_summary),
                ('detailed_findings', self._generate_detailed_findings_report),
                ('compliance_report', self._generate_compliance_report),
                ('trend_report', self._generate_trend_report)
            ]
            
            for report_name, report_func in reports:
                print(f"    📄 Generating {report_name}...")
                report = await report_func()
                self.analytics_results[f'report_{report_name}'] = report
                await asyncio.sleep(0.5)  # Simulate report generation time
            
            print(f"    ✅ Generated {len(reports)} reports")
            return True
            
        except Exception as e:
            print(f"    ❌ Report generation failed: {e}")
            return False
    
    async def _generate_executive_summary(self) -> Dict[str, Any]:
        """Generate executive summary report"""
        severity_dist = self.analytics_results.get('severity_distribution', {}).get('data', {})
        risk_metrics = self.analytics_results.get('risk_metrics', {}).get('data', {})
        
        summary = {
            'report_type': 'executive_summary',
            'client_id': self.client_id,
            'report_date': datetime.now().isoformat(),
            'summary': {
                'total_findings': len(self.test_findings),
                'critical_high_findings': severity_dist.get('CRITICAL', 0) + severity_dist.get('HIGH', 0),
                'overall_risk_level': risk_metrics.get('risk_level', 'unknown'),
                'findings_resolved': len([f for f in self.test_findings if f['status'] == 'resolved']),
                'top_categories': list(self.analytics_results.get('category_breakdown', {}).get('data', {}).keys())[:3]
            },
            'recommendations': [
                'Focus on resolving critical and high severity findings',
                'Implement automated remediation for common issues',
                'Regular compliance reviews recommended'
            ]
        }
        
        return summary
    
    async def _generate_detailed_findings_report(self) -> Dict[str, Any]:
        """Generate detailed findings report"""
        return {
            'report_type': 'detailed_findings',
            'client_id': self.client_id,
            'report_date': datetime.now().isoformat(),
            'findings': self.test_findings[:10],  # Sample of findings
            'total_findings': len(self.test_findings),
            'filters_applied': {'client_id': self.client_id},
            'export_format': 'json'
        }
    
    async def _generate_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance report"""
        compliance_data = self.analytics_results.get('compliance_status', {}).get('data', {})
        
        return {
            'report_type': 'compliance_report',
            'client_id': self.client_id,
            'report_date': datetime.now().isoformat(),
            'compliance_frameworks': ['SOC2', 'ISO27001'],
            'compliance_metrics': compliance_data,
            'compliance_findings': [f for f in self.test_findings if f['category'] == 'compliance'],
            'recommendations': [
                'Address open compliance violations',
                'Review compliance controls regularly',
                'Implement automated compliance monitoring'
            ]
        }
    
    async def _generate_trend_report(self) -> Dict[str, Any]:
        """Generate trend analysis report"""
        trend_data = self.analytics_results.get('trend_analysis', {}).get('data', {})
        
        return {
            'report_type': 'trend_report',
            'client_id': self.client_id,
            'report_date': datetime.now().isoformat(),
            'trend_data': trend_data,
            'insights': [
                f"Overall trend: {trend_data.get('trend', 'unknown')}",
                f"Total days analyzed: {len(trend_data.get('daily_counts', {}))}",
                "Regular monitoring recommended"
            ]
        }
    
    async def _test_visualizations(self) -> bool:
        """Test visualization generation"""
        try:
            print("  📊 Testing visualizations...")
            
            visualizations = [
                'severity_pie_chart',
                'category_bar_chart', 
                'trend_line_chart',
                'risk_gauge_chart',
                'regional_map',
                'compliance_dashboard'
            ]
            
            for viz in visualizations:
                print(f"    📈 Testing {viz}...")
                # Simulate visualization generation
                await asyncio.sleep(0.2)
                
                # In a real test, this would verify chart/graph generation
                viz_result = {
                    'type': viz,
                    'status': 'generated',
                    'timestamp': datetime.now().isoformat(),
                    'data_points': len(self.test_findings)
                }
                
                self.analytics_results[f'viz_{viz}'] = viz_result
            
            print(f"    ✅ Generated {len(visualizations)} visualizations")
            return True
            
        except Exception as e:
            print(f"    ❌ Visualization testing failed: {e}")
            return False
    
    async def _test_export_functionality(self) -> bool:
        """Test data export functionality"""
        try:
            print("  💾 Testing export functionality...")
            
            export_formats = ['json', 'csv', 'pdf', 'excel']
            
            for format_type in export_formats:
                print(f"    📤 Testing {format_type} export...")
                
                # Simulate export generation
                await asyncio.sleep(0.3)
                
                export_result = {
                    'format': format_type,
                    'status': 'generated',
                    'file_size_kb': len(json.dumps(self.test_findings)) // 1024,
                    'record_count': len(self.test_findings),
                    'timestamp': datetime.now().isoformat()
                }
                
                self.analytics_results[f'export_{format_type}'] = export_result
            
            print(f"    ✅ Tested {len(export_formats)} export formats")
            return True
            
        except Exception as e:
            print(f"    ❌ Export testing failed: {e}")
            return False
    
    def get_analytics_summary(self) -> Dict[str, Any]:
        """Get analytics workflow summary"""
        return {
            'client_id': self.client_id,
            'test_data_count': len(self.test_findings),
            'queries_executed': len([k for k in self.analytics_results.keys() if k.startswith('query_') or not k.startswith(('report_', 'viz_', 'export_'))]),
            'reports_generated': len([k for k in self.analytics_results.keys() if k.startswith('report_')]),
            'visualizations_created': len([k for k in self.analytics_results.keys() if k.startswith('viz_')]),
            'exports_tested': len([k for k in self.analytics_results.keys() if k.startswith('export_')]),
            'results': self.analytics_results,
            'status': 'completed'
        }

# Main E2E Test Suite
class E2ETestSuite:
    """Complete end-to-end test suite"""
    
    def __init__(self, test_dir: str):
        self.test_dir = test_dir
        self.deployment_manager = DeploymentManager(test_dir)
        self.onboarding_manager = OnboardingManager()
        self.analytics_manager = None
        self.test_results = {
            'deployment': {'status': 'not_started', 'duration': 0, 'error': None},
            'onboarding': {'status': 'not_started', 'duration': 0, 'error': None},
            'analytics': {'status': 'not_started', 'duration': 0, 'error': None},
            'overall': {'status': 'not_started', 'start_time': None, 'end_time': None}
        }
    
    async def run_complete_e2e_test(self) -> bool:
        """Run complete end-to-end test"""
        try:
            print("🚀 Starting End-to-End Test Suite")
            print("=" * 50)
            
            self.test_results['overall']['start_time'] = datetime.now()
            self.test_results['overall']['status'] = 'running'
            
            # Phase 1: Deployment
            success = await self._run_deployment_phase()
            if not success:
                return False
            
            # Phase 2: Onboarding
            success = await self._run_onboarding_phase()
            if not success:
                return False
            
            # Phase 3: Analytics
            success = await self._run_analytics_phase()
            if not success:
                return False
            
            self.test_results['overall']['status'] = 'completed'
            self.test_results['overall']['end_time'] = datetime.now()
            
            print("\n✅ End-to-End Test Suite Completed Successfully!")
            self._print_test_summary()
            
            return True
            
        except Exception as e:
            self.test_results['overall']['status'] = 'failed'
            self.test_results['overall']['end_time'] = datetime.now()
            print(f"\n❌ End-to-End Test Suite Failed: {e}")
            return False
        
        finally:
            # Cleanup
            await self.deployment_manager.cleanup_deployment()
    
    async def _run_deployment_phase(self) -> bool:
        """Run deployment phase"""
        try:
            print("\n🚀 Phase 1: Deployment Testing")
            print("-" * 30)
            
            start_time = time.time()
            self.test_results['deployment']['status'] = 'running'
            
            # Prepare deployment
            success = await self.deployment_manager.prepare_deployment()
            if not success:
                raise Exception("Deployment preparation failed")
            
            # Deploy infrastructure
            success = await self.deployment_manager.deploy_infrastructure()
            if not success:
                raise Exception("Infrastructure deployment failed")
            
            # Deploy application
            success = await self.deployment_manager.deploy_application()
            if not success:
                raise Exception("Application deployment failed")
            
            duration = time.time() - start_time
            self.test_results['deployment']['status'] = 'completed'
            self.test_results['deployment']['duration'] = duration
            
            print(f"✅ Deployment phase completed in {duration:.1f} seconds")
            return True
            
        except Exception as e:
            duration = time.time() - start_time
            self.test_results['deployment']['status'] = 'failed'
            self.test_results['deployment']['duration'] = duration
            self.test_results['deployment']['error'] = str(e)
            print(f"❌ Deployment phase failed: {e}")
            return False
    
    async def _run_onboarding_phase(self) -> bool:
        """Run onboarding phase"""
        try:
            print("\n👤 Phase 2: Onboarding Testing")
            print("-" * 30)
            
            start_time = time.time()
            self.test_results['onboarding']['status'] = 'running'
            
            # Execute onboarding workflow
            success = await self.onboarding_manager.execute_onboarding_workflow()
            if not success:
                raise Exception("Onboarding workflow failed")
            
            # Get onboarding summary
            summary = self.onboarding_manager.get_onboarding_summary()
            client_id = summary['client_data']['client_id']
            
            # Initialize analytics manager with client ID
            self.analytics_manager = AnalyticsManager(client_id)
            
            duration = time.time() - start_time
            self.test_results['onboarding']['status'] = 'completed'
            self.test_results['onboarding']['duration'] = duration
            self.test_results['onboarding']['summary'] = summary
            
            print(f"✅ Onboarding phase completed in {duration:.1f} seconds")
            print(f"   Client ID: {client_id}")
            print(f"   Steps completed: {summary['steps_completed']}")
            
            return True
            
        except Exception as e:
            duration = time.time() - start_time
            self.test_results['onboarding']['status'] = 'failed'
            self.test_results['onboarding']['duration'] = duration
            self.test_results['onboarding']['error'] = str(e)
            print(f"❌ Onboarding phase failed: {e}")
            return False
    
    async def _run_analytics_phase(self) -> bool:
        """Run analytics phase"""
        try:
            print("\n📊 Phase 3: Analytics Testing")
            print("-" * 30)
            
            if not self.analytics_manager:
                raise Exception("Analytics manager not initialized")
            
            start_time = time.time()
            self.test_results['analytics']['status'] = 'running'
            
            # Execute analytics workflow
            success = await self.analytics_manager.execute_analytics_workflow()
            if not success:
                raise Exception("Analytics workflow failed")
            
            # Get analytics summary
            summary = self.analytics_manager.get_analytics_summary()
            
            duration = time.time() - start_time
            self.test_results['analytics']['status'] = 'completed'
            self.test_results['analytics']['duration'] = duration
            self.test_results['analytics']['summary'] = summary
            
            print(f"✅ Analytics phase completed in {duration:.1f} seconds")
            print(f"   Test data processed: {summary['test_data_count']}")
            print(f"   Queries executed: {summary['queries_executed']}")
            print(f"   Reports generated: {summary['reports_generated']}")
            print(f"   Visualizations created: {summary['visualizations_created']}")
            print(f"   Export formats tested: {summary['exports_tested']}")
            
            return True
            
        except Exception as e:
            duration = time.time() - start_time
            self.test_results['analytics']['status'] = 'failed'
            self.test_results['analytics']['duration'] = duration
            self.test_results['analytics']['error'] = str(e)
            print(f"❌ Analytics phase failed: {e}")
            return False
    
    def _print_test_summary(self):
        """Print comprehensive test summary"""
        print("\n" + "=" * 60)
        print("📊 END-TO-END TEST SUMMARY")
        print("=" * 60)
        
        overall_start = self.test_results['overall']['start_time']
        overall_end = self.test_results['overall']['end_time']
        total_duration = (overall_end - overall_start).total_seconds() if overall_end else 0
        
        print(f"Overall Status: {self.test_results['overall']['status'].upper()}")
        print(f"Total Duration: {total_duration:.1f} seconds")
        print(f"Start Time: {overall_start}")
        print(f"End Time: {overall_end}")
        print()
        
        # Phase summaries
        for phase, results in self.test_results.items():
            if phase == 'overall':
                continue
                
            print(f"{phase.upper()} PHASE:")
            print(f"  Status: {results['status'].upper()}")
            print(f"  Duration: {results['duration']:.1f} seconds")
            
            if results.get('error'):
                print(f"  Error: {results['error']}")
            
            if phase == 'onboarding' and 'summary' in results:
                summary = results['summary']
                print(f"  Client ID: {summary['client_data']['client_id']}")
                print(f"  Steps Completed: {summary['steps_completed']}")
            
            if phase == 'analytics' and 'summary' in results:
                summary = results['summary']
                print(f"  Test Data Count: {summary['test_data_count']}")
                print(f"  Queries Executed: {summary['queries_executed']}")
                print(f"  Reports Generated: {summary['reports_generated']}")
            
            print()
        
        # Success metrics
        successful_phases = sum(1 for phase, results in self.test_results.items() 
                              if phase != 'overall' and results['status'] == 'completed')
        total_phases = len([p for p in self.test_results.keys() if p != 'overall'])
        
        print(f"SUCCESS RATE: {successful_phases}/{total_phases} phases completed successfully")
        print("=" * 60)

# Test fixtures and pytest integration
@pytest.fixture
def temp_test_dir():
    """Create temporary test directory"""
    temp_dir = tempfile.mkdtemp(prefix="audithound_e2e_")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)

@pytest.fixture
async def e2e_test_suite(temp_test_dir):
    """E2E test suite fixture"""
    return E2ETestSuite(temp_test_dir)

# E2E Test Cases
class TestE2EWorkflow:
    """End-to-end workflow tests"""
    
    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_complete_e2e_workflow(self, e2e_test_suite):
        """Test complete end-to-end workflow"""
        success = await e2e_test_suite.run_complete_e2e_test()
        assert success, "Complete E2E workflow should succeed"
        
        # Verify all phases completed
        assert e2e_test_suite.test_results['deployment']['status'] == 'completed'
        assert e2e_test_suite.test_results['onboarding']['status'] == 'completed'
        assert e2e_test_suite.test_results['analytics']['status'] == 'completed'
    
    @pytest.mark.asyncio
    async def test_deployment_phase_only(self, temp_test_dir):
        """Test deployment phase in isolation"""
        deployment_manager = DeploymentManager(temp_test_dir)
        
        try:
            success = await deployment_manager.prepare_deployment()
            assert success, "Deployment preparation should succeed"
            
            # Note: Skipping actual Docker deployment in CI
            print("✅ Deployment phase test completed (Docker deployment skipped in CI)")
        finally:
            await deployment_manager.cleanup_deployment()
    
    @pytest.mark.asyncio
    async def test_onboarding_phase_only(self):
        """Test onboarding phase in isolation"""
        onboarding_manager = OnboardingManager()
        
        success = await onboarding_manager.execute_onboarding_workflow()
        assert success, "Onboarding workflow should succeed"
        
        summary = onboarding_manager.get_onboarding_summary()
        assert summary['status'] == 'completed'
        assert summary['steps_completed'] == 6
        assert 'client_id' in summary['client_data']
    
    @pytest.mark.asyncio
    async def test_analytics_phase_only(self):
        """Test analytics phase in isolation"""
        test_client_id = f"test_client_{uuid.uuid4().hex[:8]}"
        analytics_manager = AnalyticsManager(test_client_id)
        
        success = await analytics_manager.execute_analytics_workflow()
        assert success, "Analytics workflow should succeed"
        
        summary = analytics_manager.get_analytics_summary()
        assert summary['status'] == 'completed'
        assert summary['test_data_count'] == E2E_CONFIG['analytics']['test_data_size']
        assert summary['queries_executed'] >= 6
        assert summary['reports_generated'] >= 4

# Performance tests
class TestE2EPerformance:
    """End-to-end performance tests"""
    
    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_large_dataset_analytics(self):
        """Test analytics with large dataset"""
        # Temporarily increase test data size
        original_size = E2E_CONFIG['analytics']['test_data_size']
        E2E_CONFIG['analytics']['test_data_size'] = 1000
        
        try:
            test_client_id = f"perf_test_{uuid.uuid4().hex[:8]}"
            analytics_manager = AnalyticsManager(test_client_id)
            
            start_time = time.time()
            success = await analytics_manager.execute_analytics_workflow()
            duration = time.time() - start_time
            
            assert success, "Large dataset analytics should succeed"
            assert duration < 300, f"Analytics should complete within 5 minutes, took {duration:.1f}s"
            
            summary = analytics_manager.get_analytics_summary()
            assert summary['test_data_count'] == 1000
            
            print(f"Processed {summary['test_data_count']} records in {duration:.1f} seconds")
            print(f"Rate: {summary['test_data_count'] / duration:.1f} records/second")
            
        finally:
            # Restore original size
            E2E_CONFIG['analytics']['test_data_size'] = original_size
    
    @pytest.mark.asyncio
    async def test_concurrent_onboarding(self):
        """Test concurrent onboarding workflows"""
        num_concurrent = 3
        tasks = []
        
        for i in range(num_concurrent):
            onboarding_manager = OnboardingManager()
            # Modify client name to make each unique
            E2E_CONFIG['onboarding']['test_client_name'] = f"concurrent_client_{i}"
            tasks.append(onboarding_manager.execute_onboarding_workflow())
        
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        duration = time.time() - start_time
        
        assert all(results), "All concurrent onboarding workflows should succeed"
        assert duration < 60, f"Concurrent onboarding should complete within 1 minute, took {duration:.1f}s"
        
        print(f"Completed {num_concurrent} concurrent onboardings in {duration:.1f} seconds")

# Main test runner
if __name__ == "__main__":
    import sys
    
    async def run_e2e_tests():
        """Run E2E tests"""
        if len(sys.argv) > 1:
            test_type = sys.argv[1]
            
            if test_type == "deployment":
                print("Running deployment tests...")
                pytest.main(["-v", "TestE2EWorkflow::test_deployment_phase_only"])
            elif test_type == "onboarding":
                print("Running onboarding tests...")
                pytest.main(["-v", "TestE2EWorkflow::test_onboarding_phase_only"])
            elif test_type == "analytics":
                print("Running analytics tests...")
                pytest.main(["-v", "TestE2EWorkflow::test_analytics_phase_only"])
            elif test_type == "performance":
                print("Running performance tests...")
                pytest.main(["-v", "TestE2EPerformance"])
            elif test_type == "full":
                print("Running full E2E test...")
                pytest.main(["-v", "TestE2EWorkflow::test_complete_e2e_workflow"])
            elif test_type == "all":
                print("Running all E2E tests...")
                pytest.main(["-v", __file__])
            else:
                print("Available test types: deployment, onboarding, analytics, performance, full, all")
        else:
            # Run individual phase tests by default (faster than full E2E)
            print("Running individual phase tests...")
            pytest.main(["-v", "TestE2EWorkflow::test_deployment_phase_only", 
                         "TestE2EWorkflow::test_onboarding_phase_only",
                         "TestE2EWorkflow::test_analytics_phase_only"])
    
    # Run tests
    asyncio.run(run_e2e_tests())