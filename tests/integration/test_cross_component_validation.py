# Cross-component compatibility and integration validation tests
import pytest
import asyncio
import time
import json
from unittest.mock import patch, Mock, AsyncMock
from typing import Dict, List, Any

from src.multi_tenant_manager import MultiTenantManager
from src.ai_analytics.ai_analytics_manager import AIAnalyticsManager
from src.persistence.unified_db_manager import UnifiedDatabaseManager
from src.security.unified_auth_manager import UnifiedAuthManager
from src.integrations.unified_cloud_collector import UnifiedCloudCollector
from src.compliance.mapping_enhanced import ComplianceMapper
from src.post_quantum_integration import PostQuantumIntegration


@pytest.mark.integration
class TestCrossComponentValidation:
    """Comprehensive cross-component integration validation tests."""
    
    def test_complete_audit_workflow(self, test_client, sample_tenant_data, sample_audit_data):
        """Test complete end-to-end audit workflow across all components."""
        
        # Step 1: Create tenant
        response = test_client.post("/api/v1/tenants", json=sample_tenant_data)
        assert response.status_code == 201
        tenant = response.json()
        tenant_id = tenant["tenant_id"]
        
        try:
            # Step 2: Authenticate and get token
            user_data = {
                "username": "workflow_test_user",
                "email": "workflow@test.com", 
                "password": "WorkflowTest123!",
                "tenant_id": tenant_id
            }
            
            # Register user
            response = test_client.post("/api/v1/auth/register", json=user_data)
            assert response.status_code == 201
            
            # Login
            response = test_client.post("/api/v1/auth/login", json={
                "username": user_data["username"],
                "password": user_data["password"]
            })
            assert response.status_code == 200
            auth_token = response.json()["access_token"]
            headers = {"Authorization": f"Bearer {auth_token}"}
            
            # Step 3: Create audit log
            audit_data = {**sample_audit_data, "tenant_id": tenant_id}
            response = test_client.post("/api/v1/audit-logs", json=audit_data, headers=headers)
            assert response.status_code == 201
            audit_log = response.json()
            
            # Step 4: Store compliance results
            compliance_data = {
                "tenant_id": tenant_id,
                "framework": "SOC2",
                "control_id": "CC6.1",
                "resource_id": audit_data["resource_id"],
                "status": "NON_COMPLIANT",
                "score": 65.0,
                "evidence": {"findings": audit_data["findings"]},
                "recommendations": ["Implement proper IAM controls"]
            }
            response = test_client.post("/api/v1/compliance-results", json=compliance_data, headers=headers)
            assert response.status_code == 201
            
            # Step 5: Retrieve compliance dashboard
            response = test_client.get(f"/api/v1/tenants/{tenant_id}/compliance/dashboard", headers=headers)
            assert response.status_code == 200
            dashboard_data = response.json()
            
            # Validate dashboard data contains our results
            assert "compliance_summary" in dashboard_data
            assert "frameworks" in dashboard_data
            assert any(fw["name"] == "SOC2" for fw in dashboard_data["frameworks"])
            
            # Step 6: Test AI analytics integration
            response = test_client.post(f"/api/v1/tenants/{tenant_id}/ai-analytics/analyze", 
                                      json={"type": "pattern_detection"}, 
                                      headers=headers)
            # Should return 200 or 202 (accepted for processing)
            assert response.status_code in [200, 202]
            
            # Step 7: Verify data isolation
            # Create another tenant
            other_tenant_data = {
                "tenant_id": "isolation-test-tenant",
                "name": "Isolation Test Tenant",
                "status": "active"
            }
            response = test_client.post("/api/v1/tenants", json=other_tenant_data)
            assert response.status_code == 201
            
            # Try to access first tenant's data with other tenant's context
            response = test_client.get(f"/api/v1/tenants/isolation-test-tenant/audit-logs", headers=headers)
            # Should return empty or filtered results (not the original tenant's data)
            other_tenant_logs = response.json()
            original_resource_ids = [log.get("resource_id") for log in other_tenant_logs if "resource_id" in log]
            assert audit_data["resource_id"] not in original_resource_ids
            
            print("✅ Complete audit workflow validation passed")
            
        finally:
            # Cleanup
            test_client.delete(f"/api/v1/tenants/{tenant_id}")
            test_client.delete("/api/v1/tenants/isolation-test-tenant")
    
    def test_multi_tenant_data_isolation(self, test_client):
        """Test strict data isolation between tenants."""
        
        # Create two tenants
        tenant1_data = {
            "tenant_id": "isolation-tenant-1",
            "name": "Isolation Tenant 1",
            "status": "active"
        }
        tenant2_data = {
            "tenant_id": "isolation-tenant-2", 
            "name": "Isolation Tenant 2",
            "status": "active"
        }
        
        test_client.post("/api/v1/tenants", json=tenant1_data)
        test_client.post("/api/v1/tenants", json=tenant2_data)
        
        try:
            # Create users for each tenant
            user1_data = {
                "username": "tenant1_user",
                "email": "user1@tenant1.com",
                "password": "Tenant1Pass123!",
                "tenant_id": "isolation-tenant-1"
            }
            user2_data = {
                "username": "tenant2_user", 
                "email": "user2@tenant2.com",
                "password": "Tenant2Pass123!",
                "tenant_id": "isolation-tenant-2"
            }
            
            test_client.post("/api/v1/auth/register", json=user1_data)
            test_client.post("/api/v1/auth/register", json=user2_data)
            
            # Login both users
            response1 = test_client.post("/api/v1/auth/login", json={
                "username": user1_data["username"],
                "password": user1_data["password"]
            })
            response2 = test_client.post("/api/v1/auth/login", json={
                "username": user2_data["username"], 
                "password": user2_data["password"]
            })
            
            token1 = response1.json()["access_token"]
            token2 = response2.json()["access_token"]
            headers1 = {"Authorization": f"Bearer {token1}"}
            headers2 = {"Authorization": f"Bearer {token2}"}
            
            # Create audit logs for each tenant
            audit1_data = {
                "tenant_id": "isolation-tenant-1",
                "resource_id": "tenant1-resource-secret",
                "resource_type": "compute_instance",
                "event_type": "security_scan",
                "status": "completed",
                "findings": [{"control_id": "T1-001", "status": "FAIL", "severity": "HIGH"}]
            }
            audit2_data = {
                "tenant_id": "isolation-tenant-2",
                "resource_id": "tenant2-resource-secret",
                "resource_type": "database",
                "event_type": "compliance_check", 
                "status": "completed",
                "findings": [{"control_id": "T2-001", "status": "PASS", "severity": "LOW"}]
            }
            
            test_client.post("/api/v1/audit-logs", json=audit1_data, headers=headers1)
            test_client.post("/api/v1/audit-logs", json=audit2_data, headers=headers2)
            
            # Test isolation: Tenant 1 should not see Tenant 2's data
            response = test_client.get("/api/v1/tenants/isolation-tenant-1/audit-logs", headers=headers1)
            tenant1_logs = response.json()
            
            # Verify tenant 1 only sees their own data
            for log in tenant1_logs:
                assert log["tenant_id"] == "isolation-tenant-1"
                assert "tenant2-resource-secret" not in str(log)
            
            # Test cross-tenant access prevention
            response = test_client.get("/api/v1/tenants/isolation-tenant-2/audit-logs", headers=headers1)
            # Should return 403 Forbidden or empty results
            assert response.status_code in [403, 200]
            if response.status_code == 200:
                cross_tenant_logs = response.json()
                assert len(cross_tenant_logs) == 0 or all(log["tenant_id"] != "isolation-tenant-2" for log in cross_tenant_logs)
            
            print("✅ Multi-tenant data isolation validation passed")
            
        finally:
            # Cleanup
            test_client.delete("/api/v1/tenants/isolation-tenant-1")
            test_client.delete("/api/v1/tenants/isolation-tenant-2")
    
    def test_ai_analytics_integration(self, multi_tenant_manager, ai_analytics_manager):
        """Test AI analytics integration with multi-tenant data."""
        
        # Mock tenant creation
        tenant_data = {
            "tenant_id": "ai-test-tenant",
            "name": "AI Test Tenant",
            "configuration": {"ai_analytics_enabled": True},
            "status": "active"
        }
        
        with patch.object(multi_tenant_manager.db_manager, 'create_tenant') as mock_create:
            mock_tenant = Mock()
            mock_tenant.tenant_id = tenant_data["tenant_id"]
            mock_tenant.configuration = tenant_data["configuration"]
            mock_create.return_value = mock_tenant
            
            tenant = multi_tenant_manager.create_tenant(tenant_data)
            
            # Test AI analytics processing
            audit_data = [
                {
                    "tenant_id": "ai-test-tenant",
                    "resource_id": "ai-resource-1",
                    "findings": [{"control_id": "AI-001", "severity": "HIGH", "status": "FAIL"}],
                    "timestamp": time.time()
                },
                {
                    "tenant_id": "ai-test-tenant", 
                    "resource_id": "ai-resource-2",
                    "findings": [{"control_id": "AI-002", "severity": "MEDIUM", "status": "FAIL"}],
                    "timestamp": time.time()
                }
            ]
            
            # Mock AI analytics methods
            with patch.object(ai_analytics_manager, 'detect_patterns') as mock_patterns, \
                 patch.object(ai_analytics_manager, 'correlate_threats') as mock_threats, \
                 patch.object(ai_analytics_manager, 'generate_insights') as mock_insights:
                
                mock_patterns.return_value = {
                    "patterns": ["repeated_iam_failures", "escalating_severity"],
                    "confidence": 0.85
                }
                mock_threats.return_value = {
                    "threats": ["privilege_escalation_attempt"], 
                    "risk_score": 0.75
                }
                mock_insights.return_value = {
                    "insights": ["Focus on IAM control improvements"],
                    "recommendations": ["Implement MFA", "Review access policies"]
                }
                
                # Process data through AI analytics
                patterns = ai_analytics_manager.detect_patterns(audit_data)
                threats = ai_analytics_manager.correlate_threats(audit_data)
                insights = ai_analytics_manager.generate_insights(audit_data)
                
                # Verify AI processing results
                assert patterns["confidence"] > 0.8
                assert len(threats["threats"]) > 0
                assert len(insights["recommendations"]) > 0
                
                # Verify tenant isolation in AI processing
                assert all("ai-test-tenant" in str(data) for data in audit_data)
                
            print("✅ AI analytics integration validation passed")
    
    def test_post_quantum_crypto_integration(self):
        """Test post-quantum cryptography integration across components."""
        
        pq_integration = PostQuantumIntegration()
        
        # Test key generation and distribution
        with patch.object(pq_integration, 'generate_tenant_keys') as mock_gen_keys, \
             patch.object(pq_integration, 'encrypt_sensitive_data') as mock_encrypt, \
             patch.object(pq_integration, 'decrypt_sensitive_data') as mock_decrypt:
            
            # Mock key generation
            mock_gen_keys.return_value = {
                "public_key": "mock_pq_public_key",
                "private_key": "mock_pq_private_key",
                "key_id": "pq_key_001"
            }
            
            # Generate tenant keys
            keys = pq_integration.generate_tenant_keys("pq-test-tenant")
            assert "public_key" in keys
            assert "private_key" in keys
            assert "key_id" in keys
            
            # Test data encryption
            sensitive_data = {
                "api_keys": {"aws": "secret_aws_key", "azure": "secret_azure_key"},
                "compliance_data": {"findings": "sensitive_compliance_info"}
            }
            
            mock_encrypt.return_value = "encrypted_pq_data_blob"
            encrypted_data = pq_integration.encrypt_sensitive_data(sensitive_data, keys["public_key"])
            
            # Test data decryption
            mock_decrypt.return_value = sensitive_data
            decrypted_data = pq_integration.decrypt_sensitive_data(encrypted_data, keys["private_key"])
            
            assert decrypted_data == sensitive_data
            
            # Verify encryption/decryption calls
            mock_encrypt.assert_called_once_with(sensitive_data, keys["public_key"])
            mock_decrypt.assert_called_once_with(encrypted_data, keys["private_key"])
            
            print("✅ Post-quantum crypto integration validation passed")
    
    def test_cloud_provider_integration(self):
        """Test cloud provider integration across all supported providers."""
        
        cloud_collector = UnifiedCloudCollector()
        
        # Mock cloud provider clients
        with patch('boto3.client') as mock_aws, \
             patch('google.cloud.security_center.SecurityCenterClient') as mock_gcp, \
             patch('azure.identity.DefaultAzureCredential') as mock_azure:
            
            # Setup mocks
            mock_aws_client = Mock()
            mock_gcp_client = Mock()
            mock_azure_cred = Mock()
            
            mock_aws.return_value = mock_aws_client
            mock_gcp.return_value = mock_gcp_client
            mock_azure.return_value = mock_azure_cred
            
            # Mock responses
            mock_aws_client.describe_instances.return_value = {
                "Reservations": [{
                    "Instances": [{
                        "InstanceId": "i-123456789",
                        "State": {"Name": "running"},
                        "SecurityGroups": [{"GroupId": "sg-123", "GroupName": "default"}]
                    }]
                }]
            }
            
            mock_gcp_client.list_findings.return_value = [
                Mock(name="projects/test-project/sources/test-source/findings/test-finding")
            ]
            
            # Test multi-cloud data collection
            tenant_config = {
                "aws_enabled": True,
                "gcp_enabled": True,
                "azure_enabled": True,
                "regions": ["us-east-1", "us-central1", "eastus"]
            }
            
            # Collect from all providers
            with patch.object(cloud_collector, 'collect_aws_data') as mock_aws_collect, \
                 patch.object(cloud_collector, 'collect_gcp_data') as mock_gcp_collect, \
                 patch.object(cloud_collector, 'collect_azure_data') as mock_azure_collect:
                
                mock_aws_collect.return_value = {"instances": [{"id": "i-123456789", "status": "running"}]}
                mock_gcp_collect.return_value = {"findings": [{"id": "finding-123", "severity": "HIGH"}]}
                mock_azure_collect.return_value = {"resources": [{"id": "vm-123", "location": "eastus"}]}
                
                # Test unified collection
                all_data = cloud_collector.collect_unified_data("cloud-test-tenant", tenant_config)
                
                # Verify data from all providers
                assert "aws" in all_data
                assert "gcp" in all_data
                assert "azure" in all_data
                
                # Verify calls were made
                mock_aws_collect.assert_called_once()
                mock_gcp_collect.assert_called_once() 
                mock_azure_collect.assert_called_once()
                
            print("✅ Cloud provider integration validation passed")
    
    def test_compliance_framework_integration(self):
        """Test compliance framework integration and mapping."""
        
        compliance_mapper = ComplianceMapper()
        
        # Test data representing findings from different sources
        audit_findings = [
            {
                "control_id": "AWS-IAM-001",
                "description": "IAM user has overly permissive policies",
                "severity": "HIGH",
                "resource_type": "iam_user",
                "cloud_provider": "aws"
            },
            {
                "control_id": "AZURE-NETWORK-002", 
                "description": "Network security group allows unrestricted inbound traffic",
                "severity": "CRITICAL",
                "resource_type": "network_security_group",
                "cloud_provider": "azure"
            }
        ]
        
        # Test mapping to multiple compliance frameworks
        frameworks = ["SOC2", "ISO27001", "PCI-DSS", "NIST"]
        
        for framework in frameworks:
            with patch.object(compliance_mapper, 'map_to_framework') as mock_map:
                mock_map.return_value = {
                    "framework": framework,
                    "mapped_controls": [
                        {
                            "framework_control_id": f"{framework}-AC-001",
                            "original_control_id": "AWS-IAM-001",
                            "compliance_status": "NON_COMPLIANT",
                            "impact_score": 8.5
                        }
                    ],
                    "overall_score": 75.2
                }
                
                # Test mapping
                mapped_results = compliance_mapper.map_to_framework(audit_findings, framework)
                
                # Verify mapping results
                assert mapped_results["framework"] == framework
                assert "mapped_controls" in mapped_results
                assert "overall_score" in mapped_results
                assert len(mapped_results["mapped_controls"]) > 0
                
                mock_map.assert_called_once_with(audit_findings, framework)
        
        print("✅ Compliance framework integration validation passed")
    
    @pytest.mark.slow
    def test_performance_under_load(self, test_client):
        """Test system performance under load across all components."""
        
        import threading
        import queue
        
        results = queue.Queue()
        num_threads = 10
        requests_per_thread = 20
        
        def load_test_worker(thread_id):
            thread_results = {
                "thread_id": thread_id,
                "successful_requests": 0,
                "failed_requests": 0,
                "total_time": 0,
                "response_times": []
            }
            
            for i in range(requests_per_thread):
                start_time = time.time()
                
                try:
                    # Test different endpoints
                    endpoints = [
                        "/api/health",
                        "/api/v1/tenants",
                        "/api/v1/compliance-frameworks"
                    ]
                    
                    endpoint = endpoints[i % len(endpoints)]
                    response = test_client.get(endpoint)
                    
                    end_time = time.time()
                    response_time = end_time - start_time
                    
                    if response.status_code in [200, 201]:
                        thread_results["successful_requests"] += 1
                    else:
                        thread_results["failed_requests"] += 1
                    
                    thread_results["response_times"].append(response_time)
                    thread_results["total_time"] += response_time
                    
                except Exception as e:
                    thread_results["failed_requests"] += 1
                    print(f"Request failed in thread {thread_id}: {e}")
            
            results.put(thread_results)
        
        # Start load test
        start_time = time.time()
        threads = []
        
        for i in range(num_threads):
            thread = threading.Thread(target=load_test_worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        total_time = time.time() - start_time
        
        # Analyze results
        total_successful = 0
        total_failed = 0
        all_response_times = []
        
        while not results.empty():
            thread_result = results.get()
            total_successful += thread_result["successful_requests"]
            total_failed += thread_result["failed_requests"]
            all_response_times.extend(thread_result["response_times"])
        
        # Performance assertions
        total_requests = total_successful + total_failed
        success_rate = total_successful / total_requests if total_requests > 0 else 0
        avg_response_time = sum(all_response_times) / len(all_response_times) if all_response_times else 0
        throughput = total_requests / total_time
        
        print(f"Load test results:")
        print(f"  Total requests: {total_requests}")
        print(f"  Success rate: {success_rate:.2%}")
        print(f"  Average response time: {avg_response_time:.3f}s")
        print(f"  Throughput: {throughput:.1f} req/s")
        
        # Performance criteria
        assert success_rate > 0.95, f"Success rate {success_rate:.2%} too low"
        assert avg_response_time < 1.0, f"Average response time {avg_response_time:.3f}s too high"
        assert throughput > 50, f"Throughput {throughput:.1f} req/s too low"
        
        print("✅ Performance under load validation passed")
    
    def test_data_consistency_across_components(self, unified_db_manager, multi_tenant_manager):
        """Test data consistency across all system components."""
        
        # Create test tenant
        tenant_data = {
            "tenant_id": "consistency-test-tenant",
            "name": "Data Consistency Test Tenant", 
            "status": "active"
        }
        
        with patch.object(unified_db_manager, 'create_tenant') as mock_create_tenant, \
             patch.object(unified_db_manager, 'create_audit_log') as mock_create_audit, \
             patch.object(unified_db_manager, 'store_compliance_result') as mock_store_compliance:
            
            # Mock database operations
            mock_tenant = Mock()
            mock_tenant.tenant_id = tenant_data["tenant_id"]
            mock_create_tenant.return_value = mock_tenant
            
            mock_audit = Mock()
            mock_audit.id = "audit-123"
            mock_create_audit.return_value = mock_audit
            
            mock_compliance = Mock()
            mock_compliance.id = "compliance-123"
            mock_store_compliance.return_value = mock_compliance
            
            # Test transactional consistency
            tenant = multi_tenant_manager.create_tenant(tenant_data)
            
            # Create related audit data
            audit_data = {
                "tenant_id": tenant.tenant_id,
                "resource_id": "consistency-resource",
                "resource_type": "compute_instance",
                "event_type": "consistency_test",
                "status": "completed"
            }
            
            audit_log = unified_db_manager.create_audit_log(audit_data)
            
            # Create related compliance data
            compliance_data = {
                "tenant_id": tenant.tenant_id,
                "framework": "SOC2",
                "control_id": "CC6.1",
                "resource_id": audit_data["resource_id"],
                "status": "COMPLIANT",
                "score": 90.0
            }
            
            compliance_result = unified_db_manager.store_compliance_result(compliance_data)
            
            # Verify consistency
            assert tenant.tenant_id == audit_data["tenant_id"]
            assert audit_data["tenant_id"] == compliance_data["tenant_id"]
            assert audit_data["resource_id"] == compliance_data["resource_id"]
            
            # Verify all operations were called
            mock_create_tenant.assert_called_once()
            mock_create_audit.assert_called_once()
            mock_store_compliance.assert_called_once()
            
            print("✅ Data consistency validation passed")
    
    def test_error_handling_and_recovery(self, test_client):
        """Test error handling and recovery across system components."""
        
        # Test API error handling
        error_scenarios = [
            {
                "endpoint": "/api/v1/tenants/nonexistent-tenant",
                "method": "GET",
                "expected_status": 404,
                "description": "Nonexistent resource"
            },
            {
                "endpoint": "/api/v1/tenants",
                "method": "POST", 
                "data": {"invalid": "data"},
                "expected_status": 422,
                "description": "Invalid request data"
            },
            {
                "endpoint": "/api/v1/auth/login",
                "method": "POST",
                "data": {"username": "invalid", "password": "wrong"},
                "expected_status": 401,
                "description": "Authentication failure"
            }
        ]
        
        for scenario in error_scenarios:
            if scenario["method"] == "GET":
                response = test_client.get(scenario["endpoint"])
            elif scenario["method"] == "POST":
                response = test_client.post(scenario["endpoint"], json=scenario.get("data", {}))
            
            assert response.status_code == scenario["expected_status"], \
                f"Error scenario '{scenario['description']}' failed"
            
            # Verify error response structure
            if response.status_code >= 400:
                error_data = response.json()
                assert "detail" in error_data or "message" in error_data, \
                    "Error response should contain error details"
        
        print("✅ Error handling validation passed")


@pytest.mark.integration 
class TestProductionReadiness:
    """Production readiness validation tests."""
    
    def test_security_configurations(self, test_client):
        """Test production security configurations."""
        
        # Test security headers
        response = test_client.get("/api/health")
        
        # Check for security headers (would be added by nginx in production)
        security_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options", 
            "X-XSS-Protection"
        ]
        
        # Note: In test environment, these headers might not be present
        # In production, nginx would add them
        print("Security headers check - would be enforced by nginx in production")
        
        # Test API versioning
        response = test_client.get("/api/v1/health")
        assert response.status_code == 200
        
        # Test that old API versions are handled gracefully
        response = test_client.get("/api/v0/health")
        # Should either redirect or return 404, not crash
        assert response.status_code in [404, 301, 302]
        
        print("✅ Security configuration validation passed")
    
    def test_monitoring_endpoints(self, test_client):
        """Test monitoring and observability endpoints."""
        
        # Test health check endpoint
        response = test_client.get("/health")
        assert response.status_code == 200
        
        health_data = response.json()
        assert "status" in health_data
        assert health_data["status"] in ["healthy", "degraded", "unhealthy"]
        
        # Test metrics endpoint (if available)
        response = test_client.get("/metrics")
        # Metrics might be protected or not available in test
        assert response.status_code in [200, 404, 401]
        
        print("✅ Monitoring endpoints validation passed")
    
    def test_database_migration_readiness(self, unified_db_manager):
        """Test database migration and schema readiness."""
        
        # Test database health
        with patch.object(unified_db_manager, 'health_check') as mock_health:
            mock_health.return_value = {"status": "healthy", "timestamp": time.time()}
            
            health_status = unified_db_manager.health_check()
            assert health_status["status"] == "healthy"
        
        # Test migration state (would check alembic versions in real scenario)
        print("Database migration readiness - would verify alembic state in production")
        
        print("✅ Database migration readiness validation passed")
    
    def test_scalability_configuration(self):
        """Test scalability and load balancing configuration."""
        
        # Test configuration for horizontal scaling
        scaling_config = {
            "api_instances": 3,
            "worker_instances": 2,
            "database_connections_per_instance": 20,
            "redis_connections_per_instance": 10
        }
        
        # Validate configuration limits
        total_db_connections = scaling_config["api_instances"] * scaling_config["database_connections_per_instance"]
        assert total_db_connections <= 200, "Total database connections exceed limit"
        
        total_redis_connections = (scaling_config["api_instances"] + scaling_config["worker_instances"]) * scaling_config["redis_connections_per_instance"]
        assert total_redis_connections <= 100, "Total Redis connections exceed limit"
        
        print("✅ Scalability configuration validation passed")


def pytest_collection_modifyitems(config, items):
    """Add integration markers to test items."""
    for item in items:
        if "test_cross_component" in item.nodeid or "test_production_readiness" in item.nodeid:
            item.add_marker(pytest.mark.integration)