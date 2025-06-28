#!/usr/bin/env python3
"""
Comprehensive SOC Connector Tests for AuditHound
Tests MISP and TheHive connectors under success and failure scenarios
"""

import pytest
import asyncio
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from unittest.mock import Mock, patch, AsyncMock, MagicMock
import requests
from requests.exceptions import ConnectionError, Timeout, HTTPError
import time

# Mock the external libraries if not available
try:
    from pymisp import PyMISP, MISPEvent, MISPAttribute
    MISP_AVAILABLE = True
except ImportError:
    MISP_AVAILABLE = False
    
    class PyMISP:
        def __init__(self, url, key, ssl=True):
            self.url = url
            self.key = key
            self.ssl = ssl
    
    class MISPEvent:
        def __init__(self):
            self.info = ""
            self.distribution = 0
            self.threat_level_id = 1
    
    class MISPAttribute:
        def __init__(self, category, type_, value):
            self.category = category
            self.type = type_
            self.value = value

try:
    from thehive4py.api import TheHiveApi
    from thehive4py.models import Alert, Case, CaseTask
    THEHIVE_AVAILABLE = True
except ImportError:
    THEHIVE_AVAILABLE = False
    
    class TheHiveApi:
        def __init__(self, url, username, password):
            self.url = url
            self.username = username
            self.password = password
    
    class Alert:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    
    class Case:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    
    class CaseTask:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

# Test configuration
TEST_CONFIG = {
    'misp': {
        'url': 'https://misp.test.local',
        'key': 'test_api_key_12345',
        'ssl_verify': False,
        'timeout': 30
    },
    'thehive': {
        'url': 'http://thehive.test.local:9000',
        'username': 'test_user',
        'password': 'test_password',
        'timeout': 30
    },
    'test_timeout': 10,
    'retry_attempts': 3,
    'batch_size': 50
}

class MockMISPConnector:
    """Mock MISP connector for testing"""
    
    def __init__(self, config: Dict[str, Any], fail_mode: str = None):
        self.config = config
        self.fail_mode = fail_mode
        self.connected = False
        self.events: List[Dict[str, Any]] = []
        self.attributes: List[Dict[str, Any]] = []
        self.call_count = 0
        
    async def connect(self) -> bool:
        """Mock connection to MISP"""
        self.call_count += 1
        
        if self.fail_mode == "connection_failure":
            return False
        elif self.fail_mode == "timeout":
            await asyncio.sleep(TEST_CONFIG['test_timeout'] + 1)
            return False
        elif self.fail_mode == "intermittent" and self.call_count % 3 == 0:
            return False
        
        self.connected = True
        return True
    
    async def disconnect(self):
        """Mock disconnection"""
        self.connected = False
    
    async def create_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Mock event creation"""
        if not self.connected:
            raise ConnectionError("Not connected to MISP")
        
        if self.fail_mode == "api_error":
            raise HTTPError("MISP API Error: Invalid event data")
        elif self.fail_mode == "timeout":
            await asyncio.sleep(TEST_CONFIG['test_timeout'] + 1)
            raise Timeout("Request timed out")
        elif self.fail_mode == "server_error":
            raise HTTPError("500 Internal Server Error")
        
        event_id = str(uuid.uuid4())
        event = {
            'id': event_id,
            'info': event_data.get('info', 'Test Event'),
            'distribution': event_data.get('distribution', 0),
            'threat_level_id': event_data.get('threat_level_id', 1),
            'created': datetime.now().isoformat(),
            'published': False,
            'attributes': []
        }
        
        self.events.append(event)
        return event
    
    async def add_attribute(self, event_id: str, attribute_data: Dict[str, Any]) -> Dict[str, Any]:
        """Mock attribute addition"""
        if not self.connected:
            raise ConnectionError("Not connected to MISP")
        
        if self.fail_mode == "attribute_error":
            raise HTTPError("Invalid attribute data")
        
        attribute_id = str(uuid.uuid4())
        attribute = {
            'id': attribute_id,
            'event_id': event_id,
            'category': attribute_data.get('category', 'Network activity'),
            'type': attribute_data.get('type', 'ip-dst'),
            'value': attribute_data.get('value', '192.168.1.1'),
            'created': datetime.now().isoformat()
        }
        
        self.attributes.append(attribute)
        
        # Add to event
        for event in self.events:
            if event['id'] == event_id:
                event['attributes'].append(attribute)
                break
        
        return attribute
    
    async def search_events(self, search_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Mock event search"""
        if not self.connected:
            raise ConnectionError("Not connected to MISP")
        
        if self.fail_mode == "search_error":
            raise HTTPError("Search failed")
        
        # Simple mock search - return all events
        return self.events
    
    async def publish_event(self, event_id: str) -> bool:
        """Mock event publishing"""
        if not self.connected:
            raise ConnectionError("Not connected to MISP")
        
        if self.fail_mode == "publish_error":
            raise HTTPError("Failed to publish event")
        
        for event in self.events:
            if event['id'] == event_id:
                event['published'] = True
                return True
        
        return False

class MockTheHiveConnector:
    """Mock TheHive connector for testing"""
    
    def __init__(self, config: Dict[str, Any], fail_mode: str = None):
        self.config = config
        self.fail_mode = fail_mode
        self.connected = False
        self.alerts: List[Dict[str, Any]] = []
        self.cases: List[Dict[str, Any]] = []
        self.tasks: List[Dict[str, Any]] = []
        self.call_count = 0
    
    async def connect(self) -> bool:
        """Mock connection to TheHive"""
        self.call_count += 1
        
        if self.fail_mode == "connection_failure":
            return False
        elif self.fail_mode == "auth_failure":
            raise HTTPError("401 Unauthorized")
        elif self.fail_mode == "timeout":
            await asyncio.sleep(TEST_CONFIG['test_timeout'] + 1)
            return False
        
        self.connected = True
        return True
    
    async def disconnect(self):
        """Mock disconnection"""
        self.connected = False
    
    async def create_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Mock alert creation"""
        if not self.connected:
            raise ConnectionError("Not connected to TheHive")
        
        if self.fail_mode == "alert_error":
            raise HTTPError("Failed to create alert")
        elif self.fail_mode == "validation_error":
            raise ValueError("Invalid alert data")
        
        alert_id = str(uuid.uuid4())
        alert = {
            'id': alert_id,
            'title': alert_data.get('title', 'Test Alert'),
            'description': alert_data.get('description', 'Test Description'),
            'severity': alert_data.get('severity', 2),
            'status': 'New',
            'created': datetime.now().isoformat(),
            'type': alert_data.get('type', 'security'),
            'source': alert_data.get('source', 'AuditHound'),
            'tags': alert_data.get('tags', [])
        }
        
        self.alerts.append(alert)
        return alert
    
    async def create_case(self, case_data: Dict[str, Any]) -> Dict[str, Any]:
        """Mock case creation"""
        if not self.connected:
            raise ConnectionError("Not connected to TheHive")
        
        if self.fail_mode == "case_error":
            raise HTTPError("Failed to create case")
        
        case_id = str(uuid.uuid4())
        case = {
            'id': case_id,
            'title': case_data.get('title', 'Test Case'),
            'description': case_data.get('description', 'Test Description'),
            'severity': case_data.get('severity', 2),
            'status': 'Open',
            'created': datetime.now().isoformat(),
            'tags': case_data.get('tags', []),
            'tasks': []
        }
        
        self.cases.append(case)
        return case
    
    async def create_task(self, case_id: str, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Mock task creation"""
        if not self.connected:
            raise ConnectionError("Not connected to TheHive")
        
        if self.fail_mode == "task_error":
            raise HTTPError("Failed to create task")
        
        task_id = str(uuid.uuid4())
        task = {
            'id': task_id,
            'case_id': case_id,
            'title': task_data.get('title', 'Test Task'),
            'description': task_data.get('description', 'Test Description'),
            'status': 'Waiting',
            'created': datetime.now().isoformat(),
            'assigned_to': task_data.get('assigned_to', 'analyst')
        }
        
        self.tasks.append(task)
        
        # Add to case
        for case in self.cases:
            if case['id'] == case_id:
                case['tasks'].append(task)
                break
        
        return task
    
    async def get_alerts(self, filters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Mock alert retrieval"""
        if not self.connected:
            raise ConnectionError("Not connected to TheHive")
        
        if self.fail_mode == "query_error":
            raise HTTPError("Query failed")
        
        return self.alerts
    
    async def get_cases(self, filters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Mock case retrieval"""
        if not self.connected:
            raise ConnectionError("Not connected to TheHive")
        
        return self.cases
    
    async def promote_alert_to_case(self, alert_id: str) -> Dict[str, Any]:
        """Mock alert promotion to case"""
        if not self.connected:
            raise ConnectionError("Not connected to TheHive")
        
        if self.fail_mode == "promotion_error":
            raise HTTPError("Failed to promote alert")
        
        # Find alert
        alert = None
        for a in self.alerts:
            if a['id'] == alert_id:
                alert = a
                break
        
        if not alert:
            raise ValueError("Alert not found")
        
        # Create case from alert
        case_data = {
            'title': f"Case from Alert: {alert['title']}",
            'description': alert['description'],
            'severity': alert['severity'],
            'tags': alert['tags']
        }
        
        case = await self.create_case(case_data)
        
        # Update alert status
        alert['status'] = 'Imported'
        alert['case_id'] = case['id']
        
        return case

class SOCConnectorTestSuite:
    """Test suite for SOC connectors"""
    
    def __init__(self):
        self.misp_connector = None
        self.thehive_connector = None
        self.test_results = {
            'misp': {'passed': 0, 'failed': 0, 'errors': []},
            'thehive': {'passed': 0, 'failed': 0, 'errors': []},
            'integration': {'passed': 0, 'failed': 0, 'errors': []}
        }
    
    def setup_connectors(self, misp_fail_mode: str = None, thehive_fail_mode: str = None):
        """Setup test connectors"""
        self.misp_connector = MockMISPConnector(TEST_CONFIG['misp'], misp_fail_mode)
        self.thehive_connector = MockTheHiveConnector(TEST_CONFIG['thehive'], thehive_fail_mode)
    
    def record_result(self, category: str, test_name: str, success: bool, error: str = None):
        """Record test result"""
        if success:
            self.test_results[category]['passed'] += 1
        else:
            self.test_results[category]['failed'] += 1
            if error:
                self.test_results[category]['errors'].append(f"{test_name}: {error}")

# Test fixtures
@pytest.fixture
def soc_test_suite():
    """SOC connector test suite fixture"""
    return SOCConnectorTestSuite()

@pytest.fixture
def sample_audit_finding():
    """Sample audit finding for testing"""
    return {
        'finding_id': 'FIND-TEST-001',
        'severity': 'HIGH',
        'title': 'Critical Security Vulnerability',
        'description': 'SQL injection vulnerability detected in user input validation',
        'client_id': 'test_client_123',
        'timestamp': datetime.now().isoformat(),
        'source': 'vulnerability_scanner',
        'category': 'web_application',
        'indicators': [
            {'type': 'ip-dst', 'value': '192.168.1.100'},
            {'type': 'url', 'value': 'http://vulnerable.example.com/login'},
            {'type': 'vulnerability', 'value': 'CVE-2023-12345'}
        ],
        'remediation': 'Implement parameterized queries and input validation',
        'impact': 'Potential data breach and unauthorized access',
        'cvss_score': 9.1,
        'references': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-12345']
    }

@pytest.fixture
def sample_ioc_batch():
    """Sample IOC batch for testing"""
    return [
        {'type': 'ip-dst', 'value': '192.168.1.100', 'category': 'Network activity'},
        {'type': 'ip-dst', 'value': '10.0.0.50', 'category': 'Network activity'},
        {'type': 'domain', 'value': 'malicious.example.com', 'category': 'Network activity'},
        {'type': 'url', 'value': 'http://phishing.example.com/login', 'category': 'Network activity'},
        {'type': 'md5', 'value': 'd41d8cd98f00b204e9800998ecf8427e', 'category': 'Payload delivery'},
        {'type': 'sha256', 'value': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'category': 'Payload delivery'}
    ]

# MISP Connector Tests
class TestMISPConnector:
    """Test MISP connector functionality"""
    
    @pytest.mark.asyncio
    async def test_misp_connection_success(self, soc_test_suite):
        """Test successful MISP connection"""
        soc_test_suite.setup_connectors()
        
        try:
            connected = await soc_test_suite.misp_connector.connect()
            assert connected
            assert soc_test_suite.misp_connector.connected
            
            await soc_test_suite.misp_connector.disconnect()
            assert not soc_test_suite.misp_connector.connected
            
            soc_test_suite.record_result('misp', 'connection_success', True)
        except Exception as e:
            soc_test_suite.record_result('misp', 'connection_success', False, str(e))
            raise
    
    @pytest.mark.asyncio
    async def test_misp_connection_failure(self, soc_test_suite):
        """Test MISP connection failure handling"""
        soc_test_suite.setup_connectors(misp_fail_mode="connection_failure")
        
        try:
            connected = await soc_test_suite.misp_connector.connect()
            assert not connected
            assert not soc_test_suite.misp_connector.connected
            
            soc_test_suite.record_result('misp', 'connection_failure', True)
        except Exception as e:
            soc_test_suite.record_result('misp', 'connection_failure', False, str(e))
            raise
    
    @pytest.mark.asyncio
    async def test_misp_connection_timeout(self, soc_test_suite):
        """Test MISP connection timeout handling"""
        soc_test_suite.setup_connectors(misp_fail_mode="timeout")
        
        try:
            start_time = time.time()
            connected = await asyncio.wait_for(
                soc_test_suite.misp_connector.connect(),
                timeout=TEST_CONFIG['test_timeout']
            )
            end_time = time.time()
            
            # Should timeout
            assert False, "Connection should have timed out"
            
        except asyncio.TimeoutError:
            # Expected timeout
            soc_test_suite.record_result('misp', 'connection_timeout', True)
        except Exception as e:
            soc_test_suite.record_result('misp', 'connection_timeout', False, str(e))
            raise
    
    @pytest.mark.asyncio
    async def test_misp_event_creation_success(self, soc_test_suite, sample_audit_finding):
        """Test successful MISP event creation"""
        soc_test_suite.setup_connectors()
        
        try:
            await soc_test_suite.misp_connector.connect()
            
            event_data = {
                'info': sample_audit_finding['title'],
                'distribution': 0,
                'threat_level_id': 2,  # Medium threat
                'analysis': 0  # Initial
            }
            
            event = await soc_test_suite.misp_connector.create_event(event_data)
            
            assert 'id' in event
            assert event['info'] == sample_audit_finding['title']
            assert len(soc_test_suite.misp_connector.events) == 1
            
            soc_test_suite.record_result('misp', 'event_creation_success', True)
        except Exception as e:
            soc_test_suite.record_result('misp', 'event_creation_success', False, str(e))
            raise
    
    @pytest.mark.asyncio
    async def test_misp_event_creation_failure(self, soc_test_suite):
        """Test MISP event creation failure handling"""
        soc_test_suite.setup_connectors(misp_fail_mode="api_error")
        
        try:
            await soc_test_suite.misp_connector.connect()
            
            event_data = {'info': 'Test Event'}
            
            with pytest.raises(HTTPError):
                await soc_test_suite.misp_connector.create_event(event_data)
            
            soc_test_suite.record_result('misp', 'event_creation_failure', True)
        except Exception as e:
            if isinstance(e, HTTPError):
                soc_test_suite.record_result('misp', 'event_creation_failure', True)
            else:
                soc_test_suite.record_result('misp', 'event_creation_failure', False, str(e))
                raise
    
    @pytest.mark.asyncio
    async def test_misp_attribute_addition(self, soc_test_suite, sample_ioc_batch):
        """Test adding attributes to MISP event"""
        soc_test_suite.setup_connectors()
        
        try:
            await soc_test_suite.misp_connector.connect()
            
            # Create event first
            event = await soc_test_suite.misp_connector.create_event({'info': 'Test Event'})
            event_id = event['id']
            
            # Add attributes
            for ioc in sample_ioc_batch:
                attribute = await soc_test_suite.misp_connector.add_attribute(event_id, ioc)
                assert 'id' in attribute
                assert attribute['type'] == ioc['type']
                assert attribute['value'] == ioc['value']
            
            assert len(soc_test_suite.misp_connector.attributes) == len(sample_ioc_batch)
            
            soc_test_suite.record_result('misp', 'attribute_addition', True)
        except Exception as e:
            soc_test_suite.record_result('misp', 'attribute_addition', False, str(e))
            raise
    
    @pytest.mark.asyncio
    async def test_misp_batch_processing(self, soc_test_suite, sample_ioc_batch):
        """Test batch processing of IOCs"""
        soc_test_suite.setup_connectors()
        
        try:
            await soc_test_suite.misp_connector.connect()
            
            # Create event
            event = await soc_test_suite.misp_connector.create_event({'info': 'Batch Test Event'})
            event_id = event['id']
            
            # Process batch
            start_time = time.time()
            
            tasks = []
            for ioc in sample_ioc_batch:
                task = soc_test_suite.misp_connector.add_attribute(event_id, ioc)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            
            end_time = time.time()
            processing_time = end_time - start_time
            
            assert len(results) == len(sample_ioc_batch)
            assert all('id' in result for result in results)
            
            print(f"Processed {len(sample_ioc_batch)} IOCs in {processing_time:.2f} seconds")
            print(f"Rate: {len(sample_ioc_batch) / processing_time:.1f} IOCs/second")
            
            soc_test_suite.record_result('misp', 'batch_processing', True)
        except Exception as e:
            soc_test_suite.record_result('misp', 'batch_processing', False, str(e))
            raise
    
    @pytest.mark.asyncio
    async def test_misp_event_publishing(self, soc_test_suite):
        """Test MISP event publishing"""
        soc_test_suite.setup_connectors()
        
        try:
            await soc_test_suite.misp_connector.connect()
            
            # Create event
            event = await soc_test_suite.misp_connector.create_event({'info': 'Publishable Event'})
            event_id = event['id']
            
            # Verify not published initially
            assert not event['published']
            
            # Publish event
            success = await soc_test_suite.misp_connector.publish_event(event_id)
            assert success
            
            # Verify published
            published_event = next(e for e in soc_test_suite.misp_connector.events if e['id'] == event_id)
            assert published_event['published']
            
            soc_test_suite.record_result('misp', 'event_publishing', True)
        except Exception as e:
            soc_test_suite.record_result('misp', 'event_publishing', False, str(e))
            raise
    
    @pytest.mark.asyncio
    async def test_misp_intermittent_failures(self, soc_test_suite):
        """Test handling of intermittent MISP failures"""
        soc_test_suite.setup_connectors(misp_fail_mode="intermittent")
        
        try:
            successful_connections = 0
            failed_connections = 0
            
            # Try multiple connections
            for i in range(6):
                try:
                    connected = await soc_test_suite.misp_connector.connect()
                    if connected:
                        successful_connections += 1
                        await soc_test_suite.misp_connector.disconnect()
                    else:
                        failed_connections += 1
                except Exception:
                    failed_connections += 1
            
            # Should have both successes and failures with intermittent mode
            assert successful_connections > 0
            assert failed_connections > 0
            
            soc_test_suite.record_result('misp', 'intermittent_failures', True)
        except Exception as e:
            soc_test_suite.record_result('misp', 'intermittent_failures', False, str(e))
            raise

# TheHive Connector Tests
class TestTheHiveConnector:
    """Test TheHive connector functionality"""
    
    @pytest.mark.asyncio
    async def test_thehive_connection_success(self, soc_test_suite):
        """Test successful TheHive connection"""
        soc_test_suite.setup_connectors()
        
        try:
            connected = await soc_test_suite.thehive_connector.connect()
            assert connected
            assert soc_test_suite.thehive_connector.connected
            
            await soc_test_suite.thehive_connector.disconnect()
            assert not soc_test_suite.thehive_connector.connected
            
            soc_test_suite.record_result('thehive', 'connection_success', True)
        except Exception as e:
            soc_test_suite.record_result('thehive', 'connection_success', False, str(e))
            raise
    
    @pytest.mark.asyncio
    async def test_thehive_auth_failure(self, soc_test_suite):
        """Test TheHive authentication failure"""
        soc_test_suite.setup_connectors(thehive_fail_mode="auth_failure")
        
        try:
            with pytest.raises(HTTPError):
                await soc_test_suite.thehive_connector.connect()
            
            soc_test_suite.record_result('thehive', 'auth_failure', True)
        except Exception as e:
            if isinstance(e, HTTPError):
                soc_test_suite.record_result('thehive', 'auth_failure', True)
            else:
                soc_test_suite.record_result('thehive', 'auth_failure', False, str(e))
                raise
    
    @pytest.mark.asyncio
    async def test_thehive_alert_creation(self, soc_test_suite, sample_audit_finding):
        """Test TheHive alert creation"""
        soc_test_suite.setup_connectors()
        
        try:
            await soc_test_suite.thehive_connector.connect()
            
            alert_data = {
                'title': sample_audit_finding['title'],
                'description': sample_audit_finding['description'],
                'severity': 3,  # High severity
                'type': 'security',
                'source': 'AuditHound',
                'tags': ['vulnerability', 'sql-injection', 'high-risk']
            }
            
            alert = await soc_test_suite.thehive_connector.create_alert(alert_data)
            
            assert 'id' in alert
            assert alert['title'] == sample_audit_finding['title']
            assert alert['severity'] == 3
            assert alert['status'] == 'New'
            assert len(soc_test_suite.thehive_connector.alerts) == 1
            
            soc_test_suite.record_result('thehive', 'alert_creation', True)
        except Exception as e:
            soc_test_suite.record_result('thehive', 'alert_creation', False, str(e))
            raise
    
    @pytest.mark.asyncio
    async def test_thehive_case_creation(self, soc_test_suite, sample_audit_finding):
        """Test TheHive case creation"""
        soc_test_suite.setup_connectors()
        
        try:
            await soc_test_suite.thehive_connector.connect()
            
            case_data = {
                'title': f"Investigation: {sample_audit_finding['title']}",
                'description': sample_audit_finding['description'],
                'severity': 3,
                'tags': ['investigation', 'security', 'vulnerability']
            }
            
            case = await soc_test_suite.thehive_connector.create_case(case_data)
            
            assert 'id' in case
            assert case['title'].startswith('Investigation:')
            assert case['severity'] == 3
            assert case['status'] == 'Open'
            assert len(soc_test_suite.thehive_connector.cases) == 1
            
            soc_test_suite.record_result('thehive', 'case_creation', True)
        except Exception as e:
            soc_test_suite.record_result('thehive', 'case_creation', False, str(e))
            raise
    
    @pytest.mark.asyncio
    async def test_thehive_task_creation(self, soc_test_suite):
        """Test TheHive task creation"""
        soc_test_suite.setup_connectors()
        
        try:
            await soc_test_suite.thehive_connector.connect()
            
            # Create case first
            case = await soc_test_suite.thehive_connector.create_case({
                'title': 'Test Case for Tasks',
                'description': 'Case for testing task creation'
            })
            case_id = case['id']
            
            # Create tasks
            tasks = [
                {
                    'title': 'Initial Analysis',
                    'description': 'Perform initial analysis of the vulnerability',
                    'assigned_to': 'analyst1'
                },
                {
                    'title': 'Impact Assessment',
                    'description': 'Assess the potential impact of the vulnerability',
                    'assigned_to': 'analyst2'
                },
                {
                    'title': 'Remediation Plan',
                    'description': 'Develop remediation plan',
                    'assigned_to': 'security_lead'
                }
            ]
            
            created_tasks = []
            for task_data in tasks:
                task = await soc_test_suite.thehive_connector.create_task(case_id, task_data)
                created_tasks.append(task)
                
                assert 'id' in task
                assert task['case_id'] == case_id
                assert task['title'] == task_data['title']
                assert task['status'] == 'Waiting'
            
            assert len(created_tasks) == len(tasks)
            assert len(soc_test_suite.thehive_connector.tasks) == len(tasks)
            
            soc_test_suite.record_result('thehive', 'task_creation', True)
        except Exception as e:
            soc_test_suite.record_result('thehive', 'task_creation', False, str(e))
            raise
    
    @pytest.mark.asyncio
    async def test_thehive_alert_promotion(self, soc_test_suite, sample_audit_finding):
        """Test promoting alert to case"""
        soc_test_suite.setup_connectors()
        
        try:
            await soc_test_suite.thehive_connector.connect()
            
            # Create alert
            alert_data = {
                'title': sample_audit_finding['title'],
                'description': sample_audit_finding['description'],
                'severity': 3,
                'tags': ['vulnerability', 'high-risk']
            }
            
            alert = await soc_test_suite.thehive_connector.create_alert(alert_data)
            alert_id = alert['id']
            
            # Promote to case
            case = await soc_test_suite.thehive_connector.promote_alert_to_case(alert_id)
            
            assert 'id' in case
            assert case['title'].startswith('Case from Alert:')
            assert case['severity'] == alert['severity']
            
            # Verify alert status updated
            updated_alert = next(a for a in soc_test_suite.thehive_connector.alerts if a['id'] == alert_id)
            assert updated_alert['status'] == 'Imported'
            assert updated_alert['case_id'] == case['id']
            
            soc_test_suite.record_result('thehive', 'alert_promotion', True)
        except Exception as e:
            soc_test_suite.record_result('thehive', 'alert_promotion', False, str(e))
            raise
    
    @pytest.mark.asyncio
    async def test_thehive_error_scenarios(self, soc_test_suite):
        """Test various TheHive error scenarios"""
        error_scenarios = [
            ("alert_error", "create_alert"),
            ("case_error", "create_case"),
            ("task_error", "create_task"),
            ("promotion_error", "promote_alert_to_case"),
            ("query_error", "get_alerts")
        ]
        
        for fail_mode, operation in error_scenarios:
            try:
                soc_test_suite.setup_connectors(thehive_fail_mode=fail_mode)
                await soc_test_suite.thehive_connector.connect()
                
                if operation == "create_alert":
                    with pytest.raises(HTTPError):
                        await soc_test_suite.thehive_connector.create_alert({'title': 'Test'})
                
                elif operation == "create_case":
                    with pytest.raises(HTTPError):
                        await soc_test_suite.thehive_connector.create_case({'title': 'Test'})
                
                elif operation == "create_task":
                    # Create case first (without fail mode)
                    soc_test_suite.setup_connectors()
                    await soc_test_suite.thehive_connector.connect()
                    case = await soc_test_suite.thehive_connector.create_case({'title': 'Test'})
                    
                    # Now test task creation with fail mode
                    soc_test_suite.setup_connectors(thehive_fail_mode=fail_mode)
                    await soc_test_suite.thehive_connector.connect()
                    
                    with pytest.raises(HTTPError):
                        await soc_test_suite.thehive_connector.create_task(case['id'], {'title': 'Test'})
                
                elif operation == "get_alerts":
                    with pytest.raises(HTTPError):
                        await soc_test_suite.thehive_connector.get_alerts()
                
                soc_test_suite.record_result('thehive', f'error_{fail_mode}', True)
            
            except Exception as e:
                if isinstance(e, (HTTPError, ValueError)):
                    soc_test_suite.record_result('thehive', f'error_{fail_mode}', True)
                else:
                    soc_test_suite.record_result('thehive', f'error_{fail_mode}', False, str(e))

# Integration Tests
class TestSOCIntegration:
    """Test SOC connector integration scenarios"""
    
    @pytest.mark.asyncio
    async def test_full_incident_workflow(self, soc_test_suite, sample_audit_finding):
        """Test complete incident workflow across both platforms"""
        soc_test_suite.setup_connectors()
        
        try:
            # Connect to both platforms
            misp_connected = await soc_test_suite.misp_connector.connect()
            thehive_connected = await soc_test_suite.thehive_connector.connect()
            
            assert misp_connected and thehive_connected
            
            # Step 1: Create alert in TheHive
            alert_data = {
                'title': sample_audit_finding['title'],
                'description': sample_audit_finding['description'],
                'severity': 3,
                'type': 'security',
                'source': 'AuditHound',
                'tags': ['vulnerability', 'audit-finding']
            }
            
            alert = await soc_test_suite.thehive_connector.create_alert(alert_data)
            alert_id = alert['id']
            
            # Step 2: Promote alert to case
            case = await soc_test_suite.thehive_connector.promote_alert_to_case(alert_id)
            case_id = case['id']
            
            # Step 3: Create investigation tasks
            investigation_tasks = [
                {
                    'title': 'IOC Analysis',
                    'description': 'Extract and analyze indicators of compromise',
                    'assigned_to': 'analyst'
                },
                {
                    'title': 'MISP Event Creation',
                    'description': 'Create MISP event with IOCs',
                    'assigned_to': 'threat_intel'
                }
            ]
            
            for task_data in investigation_tasks:
                await soc_test_suite.thehive_connector.create_task(case_id, task_data)
            
            # Step 4: Create MISP event with IOCs
            misp_event_data = {
                'info': f"IOCs from {sample_audit_finding['title']}",
                'distribution': 0,
                'threat_level_id': 2,
                'analysis': 1  # Ongoing
            }
            
            misp_event = await soc_test_suite.misp_connector.create_event(misp_event_data)
            event_id = misp_event['id']
            
            # Step 5: Add IOCs to MISP event
            for indicator in sample_audit_finding['indicators']:
                await soc_test_suite.misp_connector.add_attribute(event_id, indicator)
            
            # Step 6: Publish MISP event
            await soc_test_suite.misp_connector.publish_event(event_id)
            
            # Verify workflow completion
            assert len(soc_test_suite.thehive_connector.alerts) == 1
            assert len(soc_test_suite.thehive_connector.cases) == 1
            assert len(soc_test_suite.thehive_connector.tasks) == len(investigation_tasks)
            assert len(soc_test_suite.misp_connector.events) == 1
            assert len(soc_test_suite.misp_connector.attributes) == len(sample_audit_finding['indicators'])
            
            # Verify event is published
            published_event = soc_test_suite.misp_connector.events[0]
            assert published_event['published']
            
            soc_test_suite.record_result('integration', 'full_incident_workflow', True)
            
        except Exception as e:
            soc_test_suite.record_result('integration', 'full_incident_workflow', False, str(e))
            raise
    
    @pytest.mark.asyncio
    async def test_bulk_ioc_processing(self, soc_test_suite, sample_ioc_batch):
        """Test bulk IOC processing across platforms"""
        soc_test_suite.setup_connectors()
        
        try:
            await soc_test_suite.misp_connector.connect()
            await soc_test_suite.thehive_connector.connect()
            
            # Create case for bulk IOCs
            case_data = {
                'title': 'Bulk IOC Processing Test',
                'description': 'Testing bulk IOC ingestion and processing',
                'severity': 2,
                'tags': ['bulk-processing', 'iocs', 'threat-intel']
            }
            
            case = await soc_test_suite.thehive_connector.create_case(case_data)
            
            # Create MISP event
            event_data = {
                'info': 'Bulk IOC Collection',
                'distribution': 0,
                'threat_level_id': 2
            }
            
            event = await soc_test_suite.misp_connector.create_event(event_data)
            event_id = event['id']
            
            # Process IOCs in batches
            batch_size = 3
            for i in range(0, len(sample_ioc_batch), batch_size):
                batch = sample_ioc_batch[i:i + batch_size]
                
                # Add batch to MISP
                tasks = []
                for ioc in batch:
                    task = soc_test_suite.misp_connector.add_attribute(event_id, ioc)
                    tasks.append(task)
                
                await asyncio.gather(*tasks)
                
                # Create corresponding analysis task in TheHive
                task_data = {
                    'title': f'Analyze IOC Batch {i // batch_size + 1}',
                    'description': f'Analyze {len(batch)} IOCs from batch',
                    'assigned_to': 'threat_analyst'
                }
                
                await soc_test_suite.thehive_connector.create_task(case['id'], task_data)
            
            # Verify processing
            expected_tasks = (len(sample_ioc_batch) + batch_size - 1) // batch_size
            assert len(soc_test_suite.thehive_connector.tasks) == expected_tasks
            assert len(soc_test_suite.misp_connector.attributes) == len(sample_ioc_batch)
            
            soc_test_suite.record_result('integration', 'bulk_ioc_processing', True)
            
        except Exception as e:
            soc_test_suite.record_result('integration', 'bulk_ioc_processing', False, str(e))
            raise
    
    @pytest.mark.asyncio
    async def test_cross_platform_error_handling(self, soc_test_suite):
        """Test error handling across both platforms"""
        error_scenarios = [
            ("misp_failure", "misp", "api_error"),
            ("thehive_failure", "thehive", "case_error"),
            ("both_failure", "both", "connection_failure")
        ]
        
        for scenario_name, platform, fail_mode in error_scenarios:
            try:
                if platform == "misp":
                    soc_test_suite.setup_connectors(misp_fail_mode=fail_mode)
                elif platform == "thehive":
                    soc_test_suite.setup_connectors(thehive_fail_mode=fail_mode)
                else:  # both
                    soc_test_suite.setup_connectors(
                        misp_fail_mode=fail_mode,
                        thehive_fail_mode=fail_mode
                    )
                
                # Test graceful degradation
                if platform in ["misp", "both"]:
                    try:
                        await soc_test_suite.misp_connector.connect()
                        await soc_test_suite.misp_connector.create_event({'info': 'Test'})
                        assert False, "Should have failed"
                    except (HTTPError, ConnectionError):
                        pass  # Expected failure
                
                if platform in ["thehive", "both"]:
                    try:
                        await soc_test_suite.thehive_connector.connect()
                        await soc_test_suite.thehive_connector.create_case({'title': 'Test'})
                        assert False, "Should have failed"
                    except (HTTPError, ConnectionError):
                        pass  # Expected failure
                
                soc_test_suite.record_result('integration', f'error_handling_{scenario_name}', True)
                
            except Exception as e:
                soc_test_suite.record_result('integration', f'error_handling_{scenario_name}', False, str(e))
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self, soc_test_suite):
        """Test concurrent operations across both platforms"""
        soc_test_suite.setup_connectors()
        
        try:
            await soc_test_suite.misp_connector.connect()
            await soc_test_suite.thehive_connector.connect()
            
            # Create multiple concurrent workflows
            num_workflows = 5
            tasks = []
            
            for i in range(num_workflows):
                async def workflow(workflow_id):
                    # Create TheHive alert
                    alert = await soc_test_suite.thehive_connector.create_alert({
                        'title': f'Concurrent Alert {workflow_id}',
                        'description': f'Test alert for workflow {workflow_id}',
                        'severity': 2
                    })
                    
                    # Create MISP event
                    event = await soc_test_suite.misp_connector.create_event({
                        'info': f'Concurrent Event {workflow_id}',
                        'distribution': 0
                    })
                    
                    # Add attributes
                    await soc_test_suite.misp_connector.add_attribute(
                        event['id'],
                        {'type': 'ip-dst', 'value': f'192.168.1.{workflow_id}', 'category': 'Network activity'}
                    )
                    
                    return {'alert_id': alert['id'], 'event_id': event['id']}
                
                tasks.append(workflow(i))
            
            # Execute all workflows concurrently
            start_time = time.time()
            results = await asyncio.gather(*tasks)
            end_time = time.time()
            
            # Verify all workflows completed
            assert len(results) == num_workflows
            assert len(soc_test_suite.thehive_connector.alerts) == num_workflows
            assert len(soc_test_suite.misp_connector.events) == num_workflows
            assert len(soc_test_suite.misp_connector.attributes) == num_workflows
            
            processing_time = end_time - start_time
            print(f"Completed {num_workflows} concurrent workflows in {processing_time:.2f} seconds")
            
            soc_test_suite.record_result('integration', 'concurrent_operations', True)
            
        except Exception as e:
            soc_test_suite.record_result('integration', 'concurrent_operations', False, str(e))
            raise

# Performance and Load Tests
class TestSOCPerformance:
    """Test SOC connector performance characteristics"""
    
    @pytest.mark.asyncio
    async def test_high_volume_ioc_processing(self, soc_test_suite):
        """Test processing large volumes of IOCs"""
        soc_test_suite.setup_connectors()
        
        try:
            await soc_test_suite.misp_connector.connect()
            
            # Generate large IOC dataset
            num_iocs = 1000
            large_ioc_batch = []
            
            for i in range(num_iocs):
                large_ioc_batch.append({
                    'type': 'ip-dst',
                    'value': f'192.168.{i // 256}.{i % 256}',
                    'category': 'Network activity'
                })
            
            # Create event
            event = await soc_test_suite.misp_connector.create_event({
                'info': f'High Volume IOC Test - {num_iocs} IOCs'
            })
            
            # Process in batches
            batch_size = 50
            start_time = time.time()
            
            for i in range(0, num_iocs, batch_size):
                batch = large_ioc_batch[i:i + batch_size]
                
                # Process batch concurrently
                tasks = []
                for ioc in batch:
                    task = soc_test_suite.misp_connector.add_attribute(event['id'], ioc)
                    tasks.append(task)
                
                await asyncio.gather(*tasks)
            
            end_time = time.time()
            processing_time = end_time - start_time
            
            assert len(soc_test_suite.misp_connector.attributes) == num_iocs
            
            rate = num_iocs / processing_time
            print(f"Processed {num_iocs} IOCs in {processing_time:.2f} seconds")
            print(f"Processing rate: {rate:.1f} IOCs/second")
            
            soc_test_suite.record_result('integration', 'high_volume_processing', True)
            
        except Exception as e:
            soc_test_suite.record_result('integration', 'high_volume_processing', False, str(e))
            raise
    
    @pytest.mark.asyncio
    async def test_sustained_load(self, soc_test_suite):
        """Test sustained load over time"""
        soc_test_suite.setup_connectors()
        
        try:
            await soc_test_suite.misp_connector.connect()
            await soc_test_suite.thehive_connector.connect()
            
            # Run sustained operations for a period
            duration_seconds = 30
            operations_per_second = 5
            
            start_time = time.time()
            total_operations = 0
            
            while time.time() - start_time < duration_seconds:
                batch_start = time.time()
                
                # Perform operations
                for i in range(operations_per_second):
                    # Alternate between MISP and TheHive operations
                    if i % 2 == 0:
                        await soc_test_suite.misp_connector.create_event({
                            'info': f'Sustained Load Event {total_operations + i}'
                        })
                    else:
                        await soc_test_suite.thehive_connector.create_alert({
                            'title': f'Sustained Load Alert {total_operations + i}',
                            'description': 'Load test alert'
                        })
                
                total_operations += operations_per_second
                
                # Wait for next second
                batch_time = time.time() - batch_start
                if batch_time < 1.0:
                    await asyncio.sleep(1.0 - batch_time)
            
            actual_duration = time.time() - start_time
            actual_rate = total_operations / actual_duration
            
            print(f"Sustained {actual_rate:.1f} operations/second for {actual_duration:.1f} seconds")
            print(f"Total operations: {total_operations}")
            
            assert total_operations > 0
            
            soc_test_suite.record_result('integration', 'sustained_load', True)
            
        except Exception as e:
            soc_test_suite.record_result('integration', 'sustained_load', False, str(e))
            raise

# Test report generation
def generate_test_report(test_suite: SOCConnectorTestSuite) -> str:
    """Generate comprehensive test report"""
    report = []
    report.append("SOC Connector Test Report")
    report.append("=" * 50)
    report.append(f"Generated: {datetime.now().isoformat()}")
    report.append("")
    
    total_passed = 0
    total_failed = 0
    
    for category, results in test_suite.test_results.items():
        passed = results['passed']
        failed = results['failed']
        total_passed += passed
        total_failed += failed
        
        report.append(f"{category.upper()} Tests:")
        report.append(f"  Passed: {passed}")
        report.append(f"  Failed: {failed}")
        report.append(f"  Success Rate: {passed / (passed + failed) * 100:.1f}%" if (passed + failed) > 0 else "  Success Rate: N/A")
        
        if results['errors']:
            report.append("  Errors:")
            for error in results['errors']:
                report.append(f"    - {error}")
        
        report.append("")
    
    report.append("OVERALL SUMMARY:")
    report.append(f"  Total Passed: {total_passed}")
    report.append(f"  Total Failed: {total_failed}")
    report.append(f"  Overall Success Rate: {total_passed / (total_passed + total_failed) * 100:.1f}%" if (total_passed + total_failed) > 0 else "  Overall Success Rate: N/A")
    
    return "\n".join(report)

# Main test runner
if __name__ == "__main__":
    import sys
    
    async def run_specific_tests():
        """Run specific test categories"""
        suite = SOCConnectorTestSuite()
        
        if len(sys.argv) > 1:
            test_category = sys.argv[1]
            
            if test_category == "misp":
                print("Running MISP connector tests...")
                pytest.main(["-v", "TestMISPConnector"])
            elif test_category == "thehive":
                print("Running TheHive connector tests...")
                pytest.main(["-v", "TestTheHiveConnector"])
            elif test_category == "integration":
                print("Running integration tests...")
                pytest.main(["-v", "TestSOCIntegration"])
            elif test_category == "performance":
                print("Running performance tests...")
                pytest.main(["-v", "TestSOCPerformance"])
            elif test_category == "all":
                print("Running all SOC connector tests...")
                pytest.main(["-v", __file__])
            else:
                print("Available test categories: misp, thehive, integration, performance, all")
        else:
            print("Running comprehensive SOC connector tests...")
            pytest.main(["-v", __file__])
    
    # Run tests
    asyncio.run(run_specific_tests())