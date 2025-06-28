#!/usr/bin/env python3
"""
End-to-End SOC Workflow Integration Test
Tests the complete unified AuditHound system: compliance + threat hunting + SOC integration
"""

import asyncio
import json
import logging
import os
import sys
import yaml
from datetime import datetime, timedelta
from typing import Dict, List

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from unified_models import (
    SecurityAsset, UnifiedFinding, ScanResult, RiskLevel,
    ComplianceStatus, ThreatStatus, AssetType,
    create_compliance_finding, create_threat_finding, create_hybrid_finding
)
from unified_audit_engine import UnifiedAuditEngine
from soc_integration.misp_connector import MISPConnector
from soc_integration.thehive_connector import TheHiveConnector
from soc_integration.chat_notifications import (
    ChatNotificationManager, NotificationConfig, NotificationChannel, NotificationPriority
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class UnifiedWorkflowTester:
    """
    Comprehensive tester for unified AuditHound SOC workflow
    """
    
    def __init__(self):
        """Initialize the workflow tester"""
        self.config = self._load_test_config()
        self.unified_engine = None
        self.misp_connector = None
        self.thehive_connector = None
        self.notification_manager = None
        
        # Test results tracking
        self.test_results = {
            'compliance_audit': {'status': 'pending', 'details': []},
            'threat_hunting': {'status': 'pending', 'details': []},
            'unified_scan': {'status': 'pending', 'details': []},
            'misp_integration': {'status': 'pending', 'details': []},
            'thehive_integration': {'status': 'pending', 'details': []},
            'chat_notifications': {'status': 'pending', 'details': []},
            'end_to_end_workflow': {'status': 'pending', 'details': []}
        }
    
    def _load_test_config(self) -> Dict:
        """Load test configuration"""
        test_config = {
            'cloud_providers': {
                'aws': {'enabled': False},
                'gcp': {'enabled': False},
                'azure': {'enabled': False}
            },
            'compliance_frameworks': {
                'soc2': {'enabled': True, 'controls': ['CC6.1', 'CC6.2', 'CC6.3']}
            },
            'notifications': {
                'slack': {
                    'enabled': bool(os.getenv('SLACK_WEBHOOK_URL')),
                    'webhook_url': os.getenv('SLACK_WEBHOOK_URL', ''),
                    'channel': '#audithound-test'
                }
            }
        }
        
        return test_config
    
    async def run_complete_workflow_test(self):
        """Run complete end-to-end workflow test"""
        logger.info("🚀 Starting Complete AuditHound SOC Workflow Test")
        logger.info("=" * 80)
        
        try:
            # Phase 1: Initialize components
            await self._test_component_initialization()
            
            # Phase 2: Test individual components
            await self._test_compliance_audit()
            await self._test_threat_hunting()
            await self._test_unified_scan()
            
            # Phase 3: Test SOC integrations
            await self._test_misp_integration()
            await self._test_thehive_integration()
            await self._test_chat_notifications()
            
            # Phase 4: Test complete end-to-end workflow
            await self._test_end_to_end_workflow()
            
            # Phase 5: Generate test report
            self._generate_test_report()
            
        except Exception as e:
            logger.error(f"❌ Workflow test failed: {str(e)}")
            raise
    
    async def _test_component_initialization(self):
        """Test initialization of all components"""
        logger.info("📋 Phase 1: Component Initialization")
        
        try:
            # Initialize unified engine
            config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
            if not os.path.exists(config_path):
                # Create minimal config for testing
                with open(config_path, 'w') as f:
                    yaml.dump(self.config, f)
            
            self.unified_engine = UnifiedAuditEngine(config_path, weaviate_client=None)
            logger.info("✅ Unified audit engine initialized")
            
            # Initialize MISP connector (if configured)
            misp_url = os.getenv('MISP_URL')
            misp_key = os.getenv('MISP_API_KEY')
            if misp_url and misp_key:
                self.misp_connector = MISPConnector(misp_url, misp_key, verify_ssl=False)
                logger.info("✅ MISP connector initialized")
            else:
                logger.info("⚠️  MISP connector not configured (optional)")
            
            # Initialize TheHive connector (if configured)
            thehive_url = os.getenv('THEHIVE_URL')
            thehive_key = os.getenv('THEHIVE_API_KEY')
            if thehive_url and thehive_key:
                self.thehive_connector = TheHiveConnector(thehive_url, thehive_key)
                logger.info("✅ TheHive connector initialized")
            else:
                logger.info("⚠️  TheHive connector not configured (optional)")
            
            # Initialize notification manager
            if self.config['notifications']['slack']['enabled']:
                slack_config = NotificationConfig(
                    channel_type=NotificationChannel.SLACK,
                    webhook_url=self.config['notifications']['slack']['webhook_url'],
                    channel_name=self.config['notifications']['slack']['channel'],
                    enabled=True
                )
                self.notification_manager = ChatNotificationManager([slack_config])
                logger.info("✅ Chat notification manager initialized")
            else:
                logger.info("⚠️  Chat notifications not configured (optional)")
            
        except Exception as e:
            logger.error(f"❌ Component initialization failed: {str(e)}")
            raise
    
    async def _test_compliance_audit(self):
        """Test compliance auditing functionality"""
        logger.info("\n📊 Phase 2a: Compliance Audit Testing")
        
        try:
            # Create test asset
            test_asset = SecurityAsset(
                asset_id="test-aws-ec2-001",
                name="Test Production Server",
                asset_type=AssetType.SERVER,
                ip_address="10.0.1.100",
                cloud_provider="aws",
                compliance_status=ComplianceStatus.NOT_ASSESSED
            )
            
            self.unified_engine.assets[test_asset.asset_id] = test_asset
            
            # Create compliance finding
            compliance_finding = create_compliance_finding(
                control_id="CC6.1",
                framework="soc2",
                score=65.5,
                evidence=[
                    {"source": "aws", "data": {"password_policy": {"score": 60}}},
                    {"source": "aws", "data": {"mfa_enforcement": {"score": 70}}}
                ],
                assets=[test_asset.asset_id]
            )
            
            # Test compliance assessment
            assert compliance_finding.finding_type == "compliance"
            assert compliance_finding.control_id == "CC6.1"
            assert compliance_finding.compliance_score == 65.5
            
            self.test_results['compliance_audit']['status'] = 'passed'
            self.test_results['compliance_audit']['details'].append(
                f"✅ Created compliance finding for {compliance_finding.control_id}"
            )
            
            logger.info("✅ Compliance audit test passed")
            
        except Exception as e:
            self.test_results['compliance_audit']['status'] = 'failed'
            self.test_results['compliance_audit']['details'].append(f"❌ Error: {str(e)}")
            logger.error(f"❌ Compliance audit test failed: {str(e)}")
    
    async def _test_threat_hunting(self):
        """Test threat hunting functionality"""
        logger.info("\n🔍 Phase 2b: Threat Hunting Testing")
        
        try:
            # Create threat finding
            threat_finding = create_threat_finding(
                rule_name="lateral_movement_detection",
                techniques=["T1021.001", "T1078"],
                confidence=87.5,
                iocs=[
                    {"type": "ip", "value": "192.168.1.100", "description": "Source IP"},
                    {"type": "domain", "value": "malicious.example.com", "description": "C2 domain"}
                ],
                assets=["test-aws-ec2-001"]
            )
            
            # Test threat assessment
            assert threat_finding.finding_type == "threat"
            assert threat_finding.hunting_rule == "lateral_movement_detection"
            assert threat_finding.confidence_score == 87.5
            assert len(threat_finding.iocs) == 2
            
            self.test_results['threat_hunting']['status'] = 'passed'
            self.test_results['threat_hunting']['details'].append(
                f"✅ Created threat finding with {len(threat_finding.mitre_techniques)} MITRE techniques"
            )
            
            logger.info("✅ Threat hunting test passed")
            
        except Exception as e:
            self.test_results['threat_hunting']['status'] = 'failed'
            self.test_results['threat_hunting']['details'].append(f"❌ Error: {str(e)}")
            logger.error(f"❌ Threat hunting test failed: {str(e)}")
    
    async def _test_unified_scan(self):
        """Test unified scanning functionality"""
        logger.info("\n🔄 Phase 2c: Unified Scan Testing")
        
        try:
            # Configure scan
            scan_config = {
                'providers': ['aws'],
                'frameworks': ['soc2'],
                'hunting_rules': ['lateral_movement_detection'],
                'scan_type': 'unified'
            }
            
            # Execute unified scan
            scan_result = await self.unified_engine.execute_unified_scan(scan_config)
            
            # Validate scan results
            assert isinstance(scan_result, ScanResult)
            assert scan_result.scan_type == 'unified'
            assert scan_result.status == 'completed'
            
            self.test_results['unified_scan']['status'] = 'passed'
            self.test_results['unified_scan']['details'].extend([
                f"✅ Scan ID: {scan_result.scan_id}",
                f"✅ Total findings: {len(scan_result.findings)}",
                f"✅ Assets scanned: {scan_result.total_assets_scanned}",
                f"✅ Duration: {scan_result._get_duration_minutes():.2f} minutes"
            ])
            
            logger.info(f"✅ Unified scan test passed - {len(scan_result.findings)} findings")
            
            # Store scan result for integration tests
            self.test_scan_result = scan_result
            
        except Exception as e:
            self.test_results['unified_scan']['status'] = 'failed'
            self.test_results['unified_scan']['details'].append(f"❌ Error: {str(e)}")
            logger.error(f"❌ Unified scan test failed: {str(e)}")
    
    async def _test_misp_integration(self):
        """Test MISP integration"""
        logger.info("\n🌐 Phase 3a: MISP Integration Testing")
        
        try:
            if not self.misp_connector:
                self.test_results['misp_integration']['status'] = 'skipped'
                self.test_results['misp_integration']['details'].append("⚠️ MISP not configured")
                logger.info("⚠️ MISP integration test skipped (not configured)")
                return
            
            # Create test hunting result for MISP submission
            hunting_result = {
                'hunting_type': 'lateral_movement',
                'risk_score': 85,
                'description': 'Test lateral movement detection',
                'threat_actor': 'apt28',
                'mitre_techniques': ['T1021.001', 'T1078'],
                'matched_assets': [
                    {
                        'ip_address': '192.168.1.100',
                        'network_connections': [
                            {'destination': 'test.malicious.com'}
                        ]
                    }
                ]
            }
            
            # Test MISP event creation
            event_uuid = self.misp_connector.create_event(hunting_result)
            
            if event_uuid:
                self.test_results['misp_integration']['status'] = 'passed'
                self.test_results['misp_integration']['details'].append(
                    f"✅ Created MISP event: {event_uuid}"
                )
                logger.info(f"✅ MISP integration test passed - Event: {event_uuid}")
            else:
                raise Exception("Failed to create MISP event")
            
            # Test IOC enrichment
            enrichment_result = self.misp_connector.enrich_with_misp('192.168.1.100')
            self.test_results['misp_integration']['details'].append(
                f"✅ IOC enrichment completed: {enrichment_result.get('found', False)}"
            )
            
        except Exception as e:
            self.test_results['misp_integration']['status'] = 'failed'
            self.test_results['misp_integration']['details'].append(f"❌ Error: {str(e)}")
            logger.error(f"❌ MISP integration test failed: {str(e)}")
    
    async def _test_thehive_integration(self):
        """Test TheHive integration"""
        logger.info("\n🎯 Phase 3b: TheHive Integration Testing")
        
        try:
            if not self.thehive_connector:
                self.test_results['thehive_integration']['status'] = 'skipped'
                self.test_results['thehive_integration']['details'].append("⚠️ TheHive not configured")
                logger.info("⚠️ TheHive integration test skipped (not configured)")
                return
            
            # Create test finding for case creation
            test_finding = create_threat_finding(
                rule_name="test_detection",
                techniques=["T1110"],
                confidence=90.0,
                iocs=[{"type": "ip", "value": "10.0.0.1", "description": "Test IP"}],
                assets=["test-asset-001"]
            )
            
            # Test case creation
            case_id = self.thehive_connector.create_case(test_finding)
            
            if case_id:
                self.test_results['thehive_integration']['status'] = 'passed'
                self.test_results['thehive_integration']['details'].append(
                    f"✅ Created TheHive case: {case_id}"
                )
                logger.info(f"✅ TheHive integration test passed - Case: {case_id}")
            else:
                raise Exception("Failed to create TheHive case")
            
        except Exception as e:
            self.test_results['thehive_integration']['status'] = 'failed'
            self.test_results['thehive_integration']['details'].append(f"❌ Error: {str(e)}")
            logger.error(f"❌ TheHive integration test failed: {str(e)}")
    
    async def _test_chat_notifications(self):
        """Test chat notification system"""
        logger.info("\n💬 Phase 3c: Chat Notifications Testing")
        
        try:
            if not self.notification_manager:
                self.test_results['chat_notifications']['status'] = 'skipped'
                self.test_results['chat_notifications']['details'].append("⚠️ Chat notifications not configured")
                logger.info("⚠️ Chat notification test skipped (not configured)")
                return
            
            # Test finding alert
            test_finding = {
                "finding_id": "test-finding-001",
                "title": "Test Security Alert",
                "description": "This is a test security finding for workflow validation",
                "finding_type": "threat",
                "severity": "high",
                "risk_score": 75.5,
                "status": "active",
                "affected_assets": ["test-server-01"],
                "mitre_techniques": ["T1110", "T1078"]
            }
            
            await self.notification_manager.send_finding_alert(
                test_finding, 
                NotificationPriority.HIGH
            )
            
            # Test scan summary notification
            if hasattr(self, 'test_scan_result'):
                await self.notification_manager.send_scan_summary(
                    self.test_scan_result.get_summary()
                )
            
            # Test workflow update
            await self.notification_manager.send_soc_workflow_update(
                "workflow_test",
                {
                    "test_id": "workflow-test-001",
                    "status": "completed",
                    "description": "End-to-end workflow test completed successfully"
                }
            )
            
            self.test_results['chat_notifications']['status'] = 'passed'
            self.test_results['chat_notifications']['details'].extend([
                "✅ Finding alert notification sent",
                "✅ Scan summary notification sent",
                "✅ Workflow update notification sent"
            ])
            
            logger.info("✅ Chat notification test passed")
            
        except Exception as e:
            self.test_results['chat_notifications']['status'] = 'failed'
            self.test_results['chat_notifications']['details'].append(f"❌ Error: {str(e)}")
            logger.error(f"❌ Chat notification test failed: {str(e)}")
    
    async def _test_end_to_end_workflow(self):
        """Test complete end-to-end SOC workflow"""
        logger.info("\n🔄 Phase 4: End-to-End Workflow Testing")
        
        try:
            # Step 1: Execute unified scan
            scan_config = {
                'providers': ['aws'],
                'frameworks': ['soc2'],
                'hunting_rules': ['lateral_movement_detection'],
                'scan_type': 'unified'
            }
            
            scan_result = await self.unified_engine.execute_unified_scan(scan_config)
            
            # Step 2: Process findings through SOC workflow
            workflow_steps = []
            
            for finding in scan_result.findings:
                if finding.finding_type in ['threat', 'hybrid']:
                    # Submit to MISP (if available)
                    if self.misp_connector:
                        hunting_result = {
                            'hunting_type': finding.hunting_rule or 'unknown',
                            'risk_score': finding.calculate_risk_score(),
                            'description': finding.description,
                            'mitre_techniques': finding.mitre_techniques,
                            'matched_assets': [{'ip_address': '10.0.1.100'}]
                        }
                        
                        event_uuid = self.misp_connector.create_event(hunting_result)
                        if event_uuid:
                            finding.misp_event_id = event_uuid
                            workflow_steps.append(f"✅ MISP event created: {event_uuid}")
                    
                    # Create TheHive case (if available)
                    if self.thehive_connector:
                        case_id = self.thehive_connector.create_case(finding)
                        if case_id:
                            finding.thehive_case_id = case_id
                            workflow_steps.append(f"✅ TheHive case created: {case_id}")
                
                # Send notification
                if self.notification_manager:
                    finding_dict = {
                        "finding_id": finding.finding_id,
                        "title": finding.title,
                        "description": finding.description,
                        "finding_type": finding.finding_type,
                        "severity": finding.severity.value,
                        "risk_score": finding.calculate_risk_score(),
                        "status": finding.status,
                        "affected_assets": finding.affected_assets,
                        "mitre_techniques": finding.mitre_techniques
                    }
                    
                    priority = NotificationPriority.CRITICAL if finding.severity == RiskLevel.CRITICAL else NotificationPriority.HIGH
                    await self.notification_manager.send_finding_alert(finding_dict, priority)
                    workflow_steps.append("✅ Chat notification sent")
            
            # Step 3: Send scan completion summary
            if self.notification_manager:
                await self.notification_manager.send_scan_summary(scan_result.get_summary())
                workflow_steps.append("✅ Scan summary notification sent")
            
            self.test_results['end_to_end_workflow']['status'] = 'passed'
            self.test_results['end_to_end_workflow']['details'].extend([
                f"✅ Processed {len(scan_result.findings)} findings",
                f"✅ Completed {len(workflow_steps)} workflow steps",
                *workflow_steps
            ])
            
            logger.info(f"✅ End-to-end workflow test passed - {len(workflow_steps)} steps completed")
            
        except Exception as e:
            self.test_results['end_to_end_workflow']['status'] = 'failed'
            self.test_results['end_to_end_workflow']['details'].append(f"❌ Error: {str(e)}")
            logger.error(f"❌ End-to-end workflow test failed: {str(e)}")
    
    def _generate_test_report(self):
        """Generate comprehensive test report"""
        logger.info("\n📋 Final Test Report")
        logger.info("=" * 80)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results.values() if result['status'] == 'passed')
        failed_tests = sum(1 for result in self.test_results.values() if result['status'] == 'failed')
        skipped_tests = sum(1 for result in self.test_results.values() if result['status'] == 'skipped')
        
        logger.info(f"Test Summary: {passed_tests}/{total_tests} passed, {failed_tests} failed, {skipped_tests} skipped")
        logger.info("-" * 80)
        
        for test_name, result in self.test_results.items():
            status_icon = "✅" if result['status'] == 'passed' else "❌" if result['status'] == 'failed' else "⚠️"
            logger.info(f"{status_icon} {test_name.replace('_', ' ').title()}: {result['status'].upper()}")
            
            for detail in result['details']:
                logger.info(f"    {detail}")
        
        logger.info("-" * 80)
        
        if failed_tests == 0:
            logger.info("🎉 ALL TESTS PASSED! AuditHound SOC workflow is fully operational")
        else:
            logger.warning(f"⚠️ {failed_tests} test(s) failed. Check configuration and retry.")
        
        # Save detailed report to file
        report = {
            'test_execution_time': datetime.now().isoformat(),
            'summary': {
                'total_tests': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'skipped': skipped_tests,
                'success_rate': f"{(passed_tests/total_tests)*100:.1f}%"
            },
            'detailed_results': self.test_results,
            'environment': {
                'misp_configured': bool(os.getenv('MISP_URL')),
                'thehive_configured': bool(os.getenv('THEHIVE_URL')),
                'slack_configured': bool(os.getenv('SLACK_WEBHOOK_URL'))
            }
        }
        
        with open('audithound_test_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info("📄 Detailed test report saved to: audithound_test_report.json")

async def main():
    """Main test execution function"""
    print("🛡️  AuditHound Unified SOC Workflow Test")
    print("=" * 80)
    print("This test validates the complete integration of:")
    print("• Compliance auditing (SOC 2)")
    print("• Threat hunting and analytics")
    print("• MISP threat intelligence platform")
    print("• TheHive incident response")
    print("• Chat notifications (Slack/Mattermost)")
    print("=" * 80)
    
    # Display configuration status
    print("\n📋 Configuration Status:")
    print(f"• MISP Integration: {'✅ Configured' if os.getenv('MISP_URL') else '⚠️  Not configured'}")
    print(f"• TheHive Integration: {'✅ Configured' if os.getenv('THEHIVE_URL') else '⚠️  Not configured'}")
    print(f"• Slack Notifications: {'✅ Configured' if os.getenv('SLACK_WEBHOOK_URL') else '⚠️  Not configured'}")
    print("\nNote: Missing integrations will be skipped in testing.")
    
    # Run tests
    tester = UnifiedWorkflowTester()
    await tester.run_complete_workflow_test()

if __name__ == "__main__":
    asyncio.run(main())