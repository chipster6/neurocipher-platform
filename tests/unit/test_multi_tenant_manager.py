# Unit tests for MultiTenantManager
import pytest
from unittest.mock import Mock, patch, call
from datetime import datetime

from src.multi_tenant_manager import MultiTenantManager
from src.persistence.unified_db_manager import UnifiedDatabaseManager


@pytest.mark.unit
class TestMultiTenantManager:
    """Test cases for MultiTenantManager."""
    
    def test_init(self, unified_db_manager):
        """Test MultiTenantManager initialization."""
        manager = MultiTenantManager(db_manager=unified_db_manager)
        assert manager.db_manager == unified_db_manager
        assert hasattr(manager, 'tenant_cache')
    
    def test_create_tenant_success(self, multi_tenant_manager, sample_tenant_data):
        """Test successful tenant creation."""
        with patch.object(multi_tenant_manager.db_manager, 'create_tenant') as mock_create:
            mock_tenant = Mock()
            mock_tenant.tenant_id = sample_tenant_data['tenant_id']
            mock_create.return_value = mock_tenant
            
            result = multi_tenant_manager.create_tenant(sample_tenant_data)
            
            assert result.tenant_id == sample_tenant_data['tenant_id']
            mock_create.assert_called_once_with(sample_tenant_data)
    
    def test_create_tenant_duplicate(self, multi_tenant_manager, sample_tenant_data):
        """Test tenant creation with duplicate tenant ID."""
        with patch.object(multi_tenant_manager.db_manager, 'get_tenant_by_id') as mock_get, \
             patch.object(multi_tenant_manager.db_manager, 'create_tenant') as mock_create:
            
            mock_get.return_value = Mock()  # Existing tenant
            
            with pytest.raises(ValueError, match="Tenant with ID .* already exists"):
                multi_tenant_manager.create_tenant(sample_tenant_data)
            
            mock_create.assert_not_called()
    
    def test_get_tenant_from_cache(self, multi_tenant_manager):
        """Test retrieving tenant from cache."""
        tenant_id = "test-tenant-cache"
        mock_tenant = Mock()
        mock_tenant.tenant_id = tenant_id
        
        # Add to cache
        multi_tenant_manager.tenant_cache[tenant_id] = mock_tenant
        
        with patch.object(multi_tenant_manager.db_manager, 'get_tenant_by_id') as mock_get:
            result = multi_tenant_manager.get_tenant(tenant_id)
            
            assert result == mock_tenant
            mock_get.assert_not_called()  # Should not hit database
    
    def test_get_tenant_from_database(self, multi_tenant_manager):
        """Test retrieving tenant from database when not in cache."""
        tenant_id = "test-tenant-db"
        mock_tenant = Mock()
        mock_tenant.tenant_id = tenant_id
        
        with patch.object(multi_tenant_manager.db_manager, 'get_tenant_by_id') as mock_get:
            mock_get.return_value = mock_tenant
            
            result = multi_tenant_manager.get_tenant(tenant_id)
            
            assert result == mock_tenant
            assert multi_tenant_manager.tenant_cache[tenant_id] == mock_tenant
            mock_get.assert_called_once_with(tenant_id)
    
    def test_get_nonexistent_tenant(self, multi_tenant_manager):
        """Test retrieving non-existent tenant."""
        tenant_id = "nonexistent-tenant"
        
        with patch.object(multi_tenant_manager.db_manager, 'get_tenant_by_id') as mock_get:
            mock_get.return_value = None
            
            result = multi_tenant_manager.get_tenant(tenant_id)
            
            assert result is None
            assert tenant_id not in multi_tenant_manager.tenant_cache
    
    def test_update_tenant(self, multi_tenant_manager):
        """Test tenant update functionality."""
        tenant_id = "test-tenant-update"
        updates = {'name': 'Updated Name', 'status': 'suspended'}
        mock_updated_tenant = Mock()
        
        with patch.object(multi_tenant_manager.db_manager, 'update_tenant') as mock_update:
            mock_update.return_value = mock_updated_tenant
            
            result = multi_tenant_manager.update_tenant(tenant_id, updates)
            
            assert result == mock_updated_tenant
            # Cache should be invalidated
            assert tenant_id not in multi_tenant_manager.tenant_cache
            mock_update.assert_called_once_with(tenant_id, updates)
    
    def test_delete_tenant(self, multi_tenant_manager):
        """Test tenant deletion."""
        tenant_id = "test-tenant-delete"
        
        # Add to cache first
        multi_tenant_manager.tenant_cache[tenant_id] = Mock()
        
        with patch.object(multi_tenant_manager.db_manager, 'delete_tenant') as mock_delete:
            mock_delete.return_value = True
            
            result = multi_tenant_manager.delete_tenant(tenant_id)
            
            assert result is True
            assert tenant_id not in multi_tenant_manager.tenant_cache
            mock_delete.assert_called_once_with(tenant_id)
    
    def test_list_tenants(self, multi_tenant_manager):
        """Test listing all tenants."""
        mock_tenants = [Mock(), Mock(), Mock()]
        
        with patch.object(multi_tenant_manager.db_manager, 'list_tenants') as mock_list:
            mock_list.return_value = mock_tenants
            
            result = multi_tenant_manager.list_tenants()
            
            assert result == mock_tenants
            mock_list.assert_called_once()
    
    def test_list_tenants_with_filters(self, multi_tenant_manager):
        """Test listing tenants with filters."""
        filters = {'status': 'active', 'subscription_plan': 'enterprise'}
        mock_tenants = [Mock(), Mock()]
        
        with patch.object(multi_tenant_manager.db_manager, 'list_tenants') as mock_list:
            mock_list.return_value = mock_tenants
            
            result = multi_tenant_manager.list_tenants(filters=filters)
            
            assert result == mock_tenants
            mock_list.assert_called_once_with(filters=filters)
    
    def test_validate_tenant_access(self, multi_tenant_manager):
        """Test tenant access validation."""
        tenant_id = "test-tenant-access"
        user_id = "test-user"
        mock_tenant = Mock()
        mock_tenant.status = 'active'
        
        with patch.object(multi_tenant_manager, 'get_tenant') as mock_get_tenant, \
             patch.object(multi_tenant_manager, 'is_user_authorized') as mock_auth:
            
            mock_get_tenant.return_value = mock_tenant
            mock_auth.return_value = True
            
            result = multi_tenant_manager.validate_tenant_access(tenant_id, user_id)
            
            assert result is True
            mock_get_tenant.assert_called_once_with(tenant_id)
            mock_auth.assert_called_once_with(user_id, tenant_id)
    
    def test_validate_tenant_access_inactive_tenant(self, multi_tenant_manager):
        """Test tenant access validation with inactive tenant."""
        tenant_id = "test-tenant-inactive"
        user_id = "test-user"
        mock_tenant = Mock()
        mock_tenant.status = 'suspended'
        
        with patch.object(multi_tenant_manager, 'get_tenant') as mock_get_tenant:
            mock_get_tenant.return_value = mock_tenant
            
            result = multi_tenant_manager.validate_tenant_access(tenant_id, user_id)
            
            assert result is False
    
    def test_validate_tenant_access_unauthorized_user(self, multi_tenant_manager):
        """Test tenant access validation with unauthorized user."""
        tenant_id = "test-tenant-unauth"
        user_id = "unauthorized-user"
        mock_tenant = Mock()
        mock_tenant.status = 'active'
        
        with patch.object(multi_tenant_manager, 'get_tenant') as mock_get_tenant, \
             patch.object(multi_tenant_manager, 'is_user_authorized') as mock_auth:
            
            mock_get_tenant.return_value = mock_tenant
            mock_auth.return_value = False
            
            result = multi_tenant_manager.validate_tenant_access(tenant_id, user_id)
            
            assert result is False
    
    def test_is_user_authorized(self, multi_tenant_manager):
        """Test user authorization check."""
        user_id = "test-user"
        tenant_id = "test-tenant"
        
        with patch.object(multi_tenant_manager.db_manager, 'get_user_tenant_association') as mock_assoc:
            mock_assoc.return_value = Mock()
            
            result = multi_tenant_manager.is_user_authorized(user_id, tenant_id)
            
            assert result is True
            mock_assoc.assert_called_once_with(user_id, tenant_id)
    
    def test_is_user_not_authorized(self, multi_tenant_manager):
        """Test user authorization check for unauthorized user."""
        user_id = "unauthorized-user"
        tenant_id = "test-tenant"
        
        with patch.object(multi_tenant_manager.db_manager, 'get_user_tenant_association') as mock_assoc:
            mock_assoc.return_value = None
            
            result = multi_tenant_manager.is_user_authorized(user_id, tenant_id)
            
            assert result is False
    
    def test_get_tenant_configuration(self, multi_tenant_manager):
        """Test retrieving tenant configuration."""
        tenant_id = "test-tenant-config"
        mock_tenant = Mock()
        mock_tenant.configuration = {
            'compliance_frameworks': ['SOC2', 'ISO27001'],
            'ai_analytics_enabled': True
        }
        
        with patch.object(multi_tenant_manager, 'get_tenant') as mock_get:
            mock_get.return_value = mock_tenant
            
            config = multi_tenant_manager.get_tenant_configuration(tenant_id)
            
            assert config == mock_tenant.configuration
    
    def test_update_tenant_configuration(self, multi_tenant_manager):
        """Test updating tenant configuration."""
        tenant_id = "test-tenant-config-update"
        new_config = {
            'compliance_frameworks': ['SOC2', 'PCI-DSS'],
            'ai_analytics_enabled': False
        }
        
        with patch.object(multi_tenant_manager, 'update_tenant') as mock_update:
            mock_update.return_value = Mock()
            
            result = multi_tenant_manager.update_tenant_configuration(tenant_id, new_config)
            
            mock_update.assert_called_once_with(tenant_id, {'configuration': new_config})
    
    def test_get_tenant_statistics(self, multi_tenant_manager):
        """Test retrieving tenant statistics."""
        tenant_id = "test-tenant-stats"
        mock_stats = {
            'audit_logs_count': 100,
            'compliance_results_count': 50,
            'users_count': 5
        }
        
        with patch.object(multi_tenant_manager.db_manager, 'get_tenant_statistics') as mock_stats_call:
            mock_stats_call.return_value = mock_stats
            
            stats = multi_tenant_manager.get_tenant_statistics(tenant_id)
            
            assert stats == mock_stats
            mock_stats_call.assert_called_once_with(tenant_id)
    
    def test_cache_invalidation(self, multi_tenant_manager):
        """Test cache invalidation functionality."""
        tenant_id = "test-tenant-cache-invalidate"
        mock_tenant = Mock()
        
        # Add to cache
        multi_tenant_manager.tenant_cache[tenant_id] = mock_tenant
        assert tenant_id in multi_tenant_manager.tenant_cache
        
        # Invalidate cache
        multi_tenant_manager.invalidate_tenant_cache(tenant_id)
        assert tenant_id not in multi_tenant_manager.tenant_cache
    
    def test_cache_clear_all(self, multi_tenant_manager):
        """Test clearing entire tenant cache."""
        # Add multiple tenants to cache
        for i in range(3):
            tenant_id = f"tenant-{i}"
            multi_tenant_manager.tenant_cache[tenant_id] = Mock()
        
        assert len(multi_tenant_manager.tenant_cache) == 3
        
        # Clear all cache
        multi_tenant_manager.clear_tenant_cache()
        assert len(multi_tenant_manager.tenant_cache) == 0
    
    def test_tenant_isolation_validation(self, multi_tenant_manager):
        """Test tenant data isolation validation."""
        tenant_id = "test-tenant-isolation"
        resource_data = {
            'tenant_id': tenant_id,
            'resource_id': 'test-resource',
            'data': 'sensitive-data'
        }
        
        # Should pass validation for matching tenant
        result = multi_tenant_manager.validate_tenant_isolation(resource_data, tenant_id)
        assert result is True
        
        # Should fail validation for different tenant
        different_tenant_id = "different-tenant"
        result = multi_tenant_manager.validate_tenant_isolation(resource_data, different_tenant_id)
        assert result is False
    
    def test_bulk_tenant_operations(self, multi_tenant_manager):
        """Test bulk tenant operations."""
        tenant_ids = ["tenant-1", "tenant-2", "tenant-3"]
        operation_data = {'status': 'suspended'}
        
        with patch.object(multi_tenant_manager, 'update_tenant') as mock_update:
            mock_update.return_value = Mock()
            
            results = multi_tenant_manager.bulk_update_tenants(tenant_ids, operation_data)
            
            assert len(results) == 3
            assert mock_update.call_count == 3
            
            # Verify all tenants were updated
            expected_calls = [call(tid, operation_data) for tid in tenant_ids]
            mock_update.assert_has_calls(expected_calls, any_order=True)
    
    @pytest.mark.slow
    def test_cache_performance(self, multi_tenant_manager):
        """Test cache performance under load."""
        import time
        
        # Populate cache with many tenants
        for i in range(1000):
            tenant_id = f"tenant-{i}"
            mock_tenant = Mock()
            mock_tenant.tenant_id = tenant_id
            multi_tenant_manager.tenant_cache[tenant_id] = mock_tenant
        
        # Measure cache lookup performance
        start_time = time.time()
        
        for i in range(100):
            tenant_id = f"tenant-{i}"
            tenant = multi_tenant_manager.tenant_cache.get(tenant_id)
            assert tenant is not None
        
        end_time = time.time()
        lookup_time = end_time - start_time
        
        # Cache lookups should be very fast
        assert lookup_time < 0.1  # 100ms for 100 lookups
    
    def test_memory_usage_monitoring(self, multi_tenant_manager):
        """Test tenant cache memory usage monitoring."""
        # Add tenants to cache
        for i in range(10):
            tenant_id = f"tenant-{i}"
            mock_tenant = Mock()
            multi_tenant_manager.tenant_cache[tenant_id] = mock_tenant
        
        memory_info = multi_tenant_manager.get_cache_memory_usage()
        
        assert 'cache_size' in memory_info
        assert 'estimated_memory_bytes' in memory_info
        assert memory_info['cache_size'] == 10