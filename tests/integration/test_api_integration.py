# Integration tests for API endpoints
import pytest
import json
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock

from src.api.main import app


@pytest.mark.integration
class TestAPIIntegration:
    """Integration tests for API endpoints."""
    
    def test_health_check_endpoint(self, test_client):
        """Test health check endpoint."""
        response = test_client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "version" in data
    
    def test_tenant_creation_workflow(self, test_client):
        """Test complete tenant creation workflow."""
        tenant_data = {
            "tenant_id": "integration-test-tenant",
            "name": "Integration Test Tenant",
            "description": "Tenant for integration testing",
            "configuration": {
                "compliance_frameworks": ["SOC2", "ISO27001"],
                "ai_analytics_enabled": True
            },
            "subscription_plan": "enterprise",
            "status": "active"
        }
        
        # Create tenant
        response = test_client.post("/api/v1/tenants", json=tenant_data)
        assert response.status_code == 201
        
        created_tenant = response.json()
        assert created_tenant["tenant_id"] == tenant_data["tenant_id"]
        assert created_tenant["name"] == tenant_data["name"]
        
        # Retrieve tenant
        response = test_client.get(f"/api/v1/tenants/{tenant_data['tenant_id']}")
        assert response.status_code == 200
        
        retrieved_tenant = response.json()
        assert retrieved_tenant["tenant_id"] == tenant_data["tenant_id"]
        
        # Update tenant
        update_data = {"name": "Updated Integration Test Tenant"}
        response = test_client.put(
            f"/api/v1/tenants/{tenant_data['tenant_id']}", 
            json=update_data
        )
        assert response.status_code == 200
        
        updated_tenant = response.json()
        assert updated_tenant["name"] == update_data["name"]
        
        # Delete tenant
        response = test_client.delete(f"/api/v1/tenants/{tenant_data['tenant_id']}")
        assert response.status_code == 204
        
        # Verify deletion
        response = test_client.get(f"/api/v1/tenants/{tenant_data['tenant_id']}")
        assert response.status_code == 404
    
    def test_audit_log_workflow(self, test_client):
        """Test audit log creation and retrieval workflow."""
        # First create a tenant
        tenant_data = {
            "tenant_id": "audit-test-tenant",
            "name": "Audit Test Tenant",
            "status": "active"
        }
        test_client.post("/api/v1/tenants", json=tenant_data)
        
        # Create audit log
        audit_data = {
            "tenant_id": "audit-test-tenant",
            "resource_id": "test-resource-001",
            "resource_type": "compute_instance",
            "event_type": "security_scan",
            "status": "completed",
            "findings": [
                {
                    "control_id": "IAM-001",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "description": "Overly permissive IAM role"
                }
            ],
            "metadata": {"scan_duration": 120}
        }
        
        response = test_client.post("/api/v1/audit-logs", json=audit_data)
        assert response.status_code == 201
        
        created_log = response.json()
        assert created_log["tenant_id"] == audit_data["tenant_id"]
        assert created_log["resource_id"] == audit_data["resource_id"]
        
        # Retrieve audit logs for tenant
        response = test_client.get(f"/api/v1/tenants/{tenant_data['tenant_id']}/audit-logs")
        assert response.status_code == 200
        
        logs = response.json()
        assert len(logs) >= 1
        assert any(log["resource_id"] == audit_data["resource_id"] for log in logs)
        
        # Cleanup
        test_client.delete(f"/api/v1/tenants/{tenant_data['tenant_id']}")
    
    def test_compliance_results_workflow(self, test_client):
        """Test compliance results storage and retrieval workflow."""
        # Create tenant
        tenant_data = {
            "tenant_id": "compliance-test-tenant",
            "name": "Compliance Test Tenant",
            "status": "active"
        }
        test_client.post("/api/v1/tenants", json=tenant_data)
        
        # Store compliance results
        compliance_data = {
            "tenant_id": "compliance-test-tenant",
            "framework": "SOC2",
            "control_id": "CC6.1",
            "resource_id": "test-resource-compliance",
            "status": "COMPLIANT",
            "score": 95.5,
            "evidence": {"test": "evidence"},
            "recommendations": ["Maintain current security posture"]
        }
        
        response = test_client.post("/api/v1/compliance-results", json=compliance_data)
        assert response.status_code == 201
        
        created_result = response.json()
        assert created_result["framework"] == compliance_data["framework"]
        assert created_result["status"] == compliance_data["status"]
        
        # Retrieve compliance dashboard data
        response = test_client.get(f"/api/v1/tenants/{tenant_data['tenant_id']}/compliance/dashboard")
        assert response.status_code == 200
        
        dashboard_data = response.json()
        assert "compliance_summary" in dashboard_data
        assert "frameworks" in dashboard_data
        
        # Cleanup
        test_client.delete(f"/api/v1/tenants/{tenant_data['tenant_id']}")
    
    def test_authentication_workflow(self, test_client):
        """Test user authentication workflow."""
        # Register user
        user_data = {
            "username": "integration_test_user",
            "email": "test@integration.com",
            "password": "test_password_123",
            "tenant_id": "test-tenant-auth"
        }
        
        response = test_client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 201
        
        # Login user
        login_data = {
            "username": user_data["username"],
            "password": user_data["password"]
        }
        
        response = test_client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 200
        
        auth_response = response.json()
        assert "access_token" in auth_response
        assert "token_type" in auth_response
        
        # Use token for authenticated request
        headers = {"Authorization": f"Bearer {auth_response['access_token']}"}
        response = test_client.get("/api/v1/auth/me", headers=headers)
        assert response.status_code == 200
        
        user_info = response.json()
        assert user_info["username"] == user_data["username"]
        assert user_info["email"] == user_data["email"]
    
    def test_multi_tenant_isolation(self, test_client):
        """Test multi-tenant data isolation."""
        # Create two tenants
        tenant1_data = {
            "tenant_id": "isolation-tenant-1",
            "name": "Isolation Test Tenant 1",
            "status": "active"
        }
        tenant2_data = {
            "tenant_id": "isolation-tenant-2",
            "name": "Isolation Test Tenant 2",
            "status": "active"
        }
        
        test_client.post("/api/v1/tenants", json=tenant1_data)
        test_client.post("/api/v1/tenants", json=tenant2_data)
        
        # Create audit logs for each tenant
        audit1_data = {
            "tenant_id": "isolation-tenant-1",
            "resource_id": "tenant1-resource",
            "resource_type": "compute_instance",
            "event_type": "security_scan",
            "status": "completed"
        }
        
        audit2_data = {
            "tenant_id": "isolation-tenant-2",
            "resource_id": "tenant2-resource",
            "resource_type": "compute_instance",
            "event_type": "security_scan",
            "status": "completed"
        }
        
        test_client.post("/api/v1/audit-logs", json=audit1_data)
        test_client.post("/api/v1/audit-logs", json=audit2_data)
        
        # Verify tenant1 only sees its own data
        response = test_client.get("/api/v1/tenants/isolation-tenant-1/audit-logs")
        assert response.status_code == 200
        
        tenant1_logs = response.json()
        assert all(log["tenant_id"] == "isolation-tenant-1" for log in tenant1_logs)
        assert not any(log["resource_id"] == "tenant2-resource" for log in tenant1_logs)
        
        # Verify tenant2 only sees its own data
        response = test_client.get("/api/v1/tenants/isolation-tenant-2/audit-logs")
        assert response.status_code == 200
        
        tenant2_logs = response.json()
        assert all(log["tenant_id"] == "isolation-tenant-2" for log in tenant2_logs)
        assert not any(log["resource_id"] == "tenant1-resource" for log in tenant2_logs)
        
        # Cleanup
        test_client.delete("/api/v1/tenants/isolation-tenant-1")
        test_client.delete("/api/v1/tenants/isolation-tenant-2")
    
    def test_error_handling(self, test_client):
        """Test API error handling."""
        # Test 404 for non-existent tenant
        response = test_client.get("/api/v1/tenants/nonexistent-tenant")
        assert response.status_code == 404
        
        error_data = response.json()
        assert "detail" in error_data
        
        # Test 400 for invalid data
        invalid_tenant_data = {
            "name": "Missing tenant_id"
            # Missing required tenant_id field
        }
        
        response = test_client.post("/api/v1/tenants", json=invalid_tenant_data)
        assert response.status_code == 422  # Validation error
        
        # Test 409 for duplicate tenant creation
        tenant_data = {
            "tenant_id": "duplicate-test-tenant",
            "name": "Duplicate Test Tenant",
            "status": "active"
        }
        
        # Create tenant first time
        response = test_client.post("/api/v1/tenants", json=tenant_data)
        assert response.status_code == 201
        
        # Try to create again (should fail)
        response = test_client.post("/api/v1/tenants", json=tenant_data)
        assert response.status_code == 409
        
        # Cleanup
        test_client.delete(f"/api/v1/tenants/{tenant_data['tenant_id']}")
    
    def test_pagination(self, test_client):
        """Test API pagination functionality."""
        # Create multiple tenants for pagination testing
        for i in range(15):
            tenant_data = {
                "tenant_id": f"pagination-tenant-{i:02d}",
                "name": f"Pagination Test Tenant {i}",
                "status": "active"
            }
            test_client.post("/api/v1/tenants", json=tenant_data)
        
        # Test first page
        response = test_client.get("/api/v1/tenants?page=1&size=10")
        assert response.status_code == 200
        
        page1_data = response.json()
        assert len(page1_data["items"]) == 10
        assert page1_data["page"] == 1
        assert page1_data["size"] == 10
        assert page1_data["total"] >= 15
        
        # Test second page
        response = test_client.get("/api/v1/tenants?page=2&size=10")
        assert response.status_code == 200
        
        page2_data = response.json()
        assert len(page2_data["items"]) >= 5
        assert page2_data["page"] == 2
        
        # Cleanup
        for i in range(15):
            test_client.delete(f"/api/v1/tenants/pagination-tenant-{i:02d}")
    
    def test_filtering_and_sorting(self, test_client):
        """Test API filtering and sorting functionality."""
        # Create tenants with different statuses
        tenants_data = [
            {"tenant_id": "filter-active-1", "name": "Active Tenant 1", "status": "active"},
            {"tenant_id": "filter-active-2", "name": "Active Tenant 2", "status": "active"},
            {"tenant_id": "filter-suspended-1", "name": "Suspended Tenant 1", "status": "suspended"},
        ]
        
        for tenant_data in tenants_data:
            test_client.post("/api/v1/tenants", json=tenant_data)
        
        # Test filtering by status
        response = test_client.get("/api/v1/tenants?status=active")
        assert response.status_code == 200
        
        active_tenants = response.json()
        assert all(tenant["status"] == "active" for tenant in active_tenants["items"])
        
        # Test sorting by name
        response = test_client.get("/api/v1/tenants?sort_by=name&sort_order=asc")
        assert response.status_code == 200
        
        sorted_tenants = response.json()
        names = [tenant["name"] for tenant in sorted_tenants["items"]]
        assert names == sorted(names)
        
        # Cleanup
        for tenant_data in tenants_data:
            test_client.delete(f"/api/v1/tenants/{tenant_data['tenant_id']}")
    
    @pytest.mark.slow
    def test_api_performance(self, test_client, performance_metrics):
        """Test API performance under load."""
        import time
        
        # Test tenant creation performance
        start_time = time.time()
        
        for i in range(10):
            tenant_data = {
                "tenant_id": f"perf-tenant-{i}",
                "name": f"Performance Test Tenant {i}",
                "status": "active"
            }
            
            response = test_client.post("/api/v1/tenants", json=tenant_data)
            assert response.status_code == 201
            
            performance_metrics['response_times'].append(time.time() - start_time)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Should create 10 tenants within reasonable time
        assert total_time < 5.0  # 5 seconds for 10 creations
        
        # Test bulk retrieval performance
        start_time = time.time()
        response = test_client.get("/api/v1/tenants?size=100")
        end_time = time.time()
        
        assert response.status_code == 200
        retrieval_time = end_time - start_time
        assert retrieval_time < 1.0  # 1 second for bulk retrieval
        
        # Cleanup
        for i in range(10):
            test_client.delete(f"/api/v1/tenants/perf-tenant-{i}")
    
    def test_concurrent_requests(self, test_client):
        """Test handling of concurrent API requests."""
        import threading
        import queue
        
        results = queue.Queue()
        
        def create_tenant(thread_id):
            tenant_data = {
                "tenant_id": f"concurrent-tenant-{thread_id}",
                "name": f"Concurrent Test Tenant {thread_id}",
                "status": "active"
            }
            
            response = test_client.post("/api/v1/tenants", json=tenant_data)
            results.put((thread_id, response.status_code))
        
        # Create multiple threads for concurrent requests
        threads = []
        for i in range(5):
            thread = threading.Thread(target=create_tenant, args=(i,))
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all requests succeeded
        assert results.qsize() == 5
        while not results.empty():
            thread_id, status_code = results.get()
            assert status_code == 201
        
        # Cleanup
        for i in range(5):
            test_client.delete(f"/api/v1/tenants/concurrent-tenant-{i}")
    
    def test_api_versioning(self, test_client):
        """Test API versioning functionality."""
        # Test v1 endpoint
        response = test_client.get("/api/v1/health")
        assert response.status_code == 200
        
        v1_response = response.json()
        assert "version" in v1_response
        
        # Test version negotiation through headers
        headers = {"Accept": "application/vnd.audithound.v1+json"}
        response = test_client.get("/api/health", headers=headers)
        assert response.status_code == 200