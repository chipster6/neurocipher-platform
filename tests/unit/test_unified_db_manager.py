# Unit tests for UnifiedDatabaseManager
import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from src.persistence.unified_db_manager import UnifiedDatabaseManager
from src.unified_models import Tenant, User, AuditLog, ComplianceResult


@pytest.mark.unit
class TestUnifiedDatabaseManager:
    """Test cases for UnifiedDatabaseManager."""
    
    def test_init_with_default_config(self, test_config):
        """Test initialization with default configuration."""
        with patch.dict('os.environ', test_config):
            manager = UnifiedDatabaseManager()
            assert manager is not None
            assert hasattr(manager, 'engine')
    
    def test_init_with_custom_config(self, test_config):
        """Test initialization with custom configuration."""
        custom_config = {**test_config, "DATABASE_POOL_SIZE": "10"}
        with patch.dict('os.environ', custom_config):
            manager = UnifiedDatabaseManager()
            assert manager is not None
    
    def test_get_session_context_manager(self, unified_db_manager):
        """Test database session context manager."""
        with unified_db_manager.get_session() as session:
            assert isinstance(session, Session)
            assert session.is_active
    
    def test_create_tenant(self, unified_db_manager, db_session, sample_tenant_data):
        """Test tenant creation."""
        with patch.object(unified_db_manager, 'get_session') as mock_session:
            mock_session.return_value.__enter__.return_value = db_session
            
            tenant = unified_db_manager.create_tenant(sample_tenant_data)
            
            assert tenant.tenant_id == sample_tenant_data['tenant_id']
            assert tenant.name == sample_tenant_data['name']
            assert tenant.status == sample_tenant_data['status']
    
    def test_get_tenant_by_id(self, unified_db_manager, db_session, test_utils):
        """Test retrieving tenant by ID."""
        # Create test tenant
        tenant_data = {
            'tenant_id': 'test-tenant-retrieve',
            'name': 'Test Retrieval Tenant',
            'description': 'Test tenant for retrieval testing',
            'configuration': {},
            'subscription_plan': 'basic',
            'status': 'active'
        }
        
        with patch.object(unified_db_manager, 'get_session') as mock_session:
            mock_session.return_value.__enter__.return_value = db_session
            
            # Create tenant
            created_tenant = unified_db_manager.create_tenant(tenant_data)
            
            # Retrieve tenant
            retrieved_tenant = unified_db_manager.get_tenant_by_id(created_tenant.tenant_id)
            
            assert retrieved_tenant is not None
            assert retrieved_tenant.tenant_id == created_tenant.tenant_id
    
    def test_get_nonexistent_tenant(self, unified_db_manager, db_session):
        """Test retrieving non-existent tenant returns None."""
        with patch.object(unified_db_manager, 'get_session') as mock_session:
            mock_session.return_value.__enter__.return_value = db_session
            
            tenant = unified_db_manager.get_tenant_by_id('nonexistent-tenant')
            assert tenant is None
    
    def test_update_tenant(self, unified_db_manager, db_session, sample_tenant_data):
        """Test tenant update functionality."""
        with patch.object(unified_db_manager, 'get_session') as mock_session:
            mock_session.return_value.__enter__.return_value = db_session
            
            # Create tenant
            tenant = unified_db_manager.create_tenant(sample_tenant_data)
            
            # Update tenant
            updates = {'name': 'Updated Tenant Name', 'status': 'suspended'}
            updated_tenant = unified_db_manager.update_tenant(tenant.tenant_id, updates)
            
            assert updated_tenant.name == 'Updated Tenant Name'
            assert updated_tenant.status == 'suspended'
    
    def test_delete_tenant(self, unified_db_manager, db_session, sample_tenant_data):
        """Test tenant deletion."""
        with patch.object(unified_db_manager, 'get_session') as mock_session:
            mock_session.return_value.__enter__.return_value = db_session
            
            # Create tenant
            tenant = unified_db_manager.create_tenant(sample_tenant_data)
            tenant_id = tenant.tenant_id
            
            # Delete tenant
            result = unified_db_manager.delete_tenant(tenant_id)
            assert result is True
            
            # Verify deletion
            deleted_tenant = unified_db_manager.get_tenant_by_id(tenant_id)
            assert deleted_tenant is None
    
    def test_create_audit_log(self, unified_db_manager, db_session, sample_audit_data):
        """Test audit log creation."""
        with patch.object(unified_db_manager, 'get_session') as mock_session:
            mock_session.return_value.__enter__.return_value = db_session
            
            audit_log = unified_db_manager.create_audit_log(sample_audit_data)
            
            assert audit_log.tenant_id == sample_audit_data['tenant_id']
            assert audit_log.resource_id == sample_audit_data['resource_id']
            assert audit_log.resource_type == sample_audit_data['resource_type']
    
    def test_get_audit_logs_by_tenant(self, unified_db_manager, db_session, sample_audit_data):
        """Test retrieving audit logs by tenant."""
        with patch.object(unified_db_manager, 'get_session') as mock_session:
            mock_session.return_value.__enter__.return_value = db_session
            
            # Create multiple audit logs
            for i in range(3):
                log_data = {**sample_audit_data, 'resource_id': f'resource-{i}'}
                unified_db_manager.create_audit_log(log_data)
            
            # Retrieve logs
            logs = unified_db_manager.get_audit_logs_by_tenant(sample_audit_data['tenant_id'])
            
            assert len(logs) >= 3
            assert all(log.tenant_id == sample_audit_data['tenant_id'] for log in logs)
    
    def test_get_audit_logs_with_date_filter(self, unified_db_manager, db_session, sample_audit_data):
        """Test retrieving audit logs with date filtering."""
        with patch.object(unified_db_manager, 'get_session') as mock_session:
            mock_session.return_value.__enter__.return_value = db_session
            
            # Create audit log
            audit_log = unified_db_manager.create_audit_log(sample_audit_data)
            
            # Test date filtering
            start_date = datetime.utcnow() - timedelta(hours=1)
            end_date = datetime.utcnow() + timedelta(hours=1)
            
            logs = unified_db_manager.get_audit_logs_by_tenant(
                sample_audit_data['tenant_id'],
                start_date=start_date,
                end_date=end_date
            )
            
            assert len(logs) >= 1
    
    def test_store_compliance_result(self, unified_db_manager, db_session):
        """Test storing compliance results."""
        compliance_data = {
            'tenant_id': 'test-tenant-001',
            'framework': 'SOC2',
            'control_id': 'CC6.1',
            'resource_id': 'test-resource',
            'status': 'COMPLIANT',
            'score': 95.5,
            'evidence': {'test': 'evidence'},
            'recommendations': ['Recommendation 1']
        }
        
        with patch.object(unified_db_manager, 'get_session') as mock_session:
            mock_session.return_value.__enter__.return_value = db_session
            
            result = unified_db_manager.store_compliance_result(compliance_data)
            
            assert result.framework == 'SOC2'
            assert result.control_id == 'CC6.1'
            assert result.status == 'COMPLIANT'
            assert result.score == 95.5
    
    def test_get_compliance_dashboard_data(self, unified_db_manager, db_session):
        """Test retrieving compliance dashboard data."""
        with patch.object(unified_db_manager, 'get_session') as mock_session:
            mock_session.return_value.__enter__.return_value = db_session
            
            # Create test compliance results
            frameworks = ['SOC2', 'ISO27001', 'PCI-DSS']
            for framework in frameworks:
                for i in range(3):
                    compliance_data = {
                        'tenant_id': 'test-tenant-001',
                        'framework': framework,
                        'control_id': f'{framework}-{i}',
                        'resource_id': f'resource-{i}',
                        'status': 'COMPLIANT' if i % 2 == 0 else 'NON_COMPLIANT',
                        'score': 90.0 if i % 2 == 0 else 50.0
                    }
                    unified_db_manager.store_compliance_result(compliance_data)
            
            # Get dashboard data
            dashboard_data = unified_db_manager.get_compliance_dashboard_data('test-tenant-001')
            
            assert 'compliance_summary' in dashboard_data
            assert 'frameworks' in dashboard_data
            assert len(dashboard_data['frameworks']) == 3
    
    def test_database_health_check(self, unified_db_manager):
        """Test database health check functionality."""
        with patch.object(unified_db_manager, 'engine') as mock_engine:
            mock_connection = Mock()
            mock_engine.connect.return_value.__enter__.return_value = mock_connection
            mock_connection.execute.return_value = Mock()
            
            health_status = unified_db_manager.health_check()
            
            assert health_status['status'] == 'healthy'
            assert 'timestamp' in health_status
            assert 'database_url' in health_status
    
    def test_database_health_check_failure(self, unified_db_manager):
        """Test database health check with connection failure."""
        with patch.object(unified_db_manager, 'engine') as mock_engine:
            mock_engine.connect.side_effect = Exception("Connection failed")
            
            health_status = unified_db_manager.health_check()
            
            assert health_status['status'] == 'unhealthy'
            assert 'error' in health_status
    
    def test_get_tenant_statistics(self, unified_db_manager, db_session, sample_tenant_data):
        """Test retrieving tenant statistics."""
        with patch.object(unified_db_manager, 'get_session') as mock_session:
            mock_session.return_value.__enter__.return_value = db_session
            
            # Create tenant and some data
            tenant = unified_db_manager.create_tenant(sample_tenant_data)
            
            # Create audit logs
            for i in range(5):
                audit_data = {
                    'tenant_id': tenant.tenant_id,
                    'resource_id': f'resource-{i}',
                    'resource_type': 'compute_instance',
                    'event_type': 'security_scan',
                    'status': 'completed'
                }
                unified_db_manager.create_audit_log(audit_data)
            
            # Get statistics
            stats = unified_db_manager.get_tenant_statistics(tenant.tenant_id)
            
            assert 'audit_logs_count' in stats
            assert 'compliance_results_count' in stats
            assert stats['audit_logs_count'] >= 5
    
    @pytest.mark.slow
    def test_bulk_insert_performance(self, unified_db_manager, db_session):
        """Test bulk insert performance for large datasets."""
        with patch.object(unified_db_manager, 'get_session') as mock_session:
            mock_session.return_value.__enter__.return_value = db_session
            
            # Create bulk data
            bulk_data = []
            for i in range(100):
                audit_data = {
                    'tenant_id': 'test-tenant-bulk',
                    'resource_id': f'bulk-resource-{i}',
                    'resource_type': 'compute_instance',
                    'event_type': 'bulk_scan',
                    'status': 'completed'
                }
                bulk_data.append(audit_data)
            
            # Measure bulk insert time
            import time
            start_time = time.time()
            
            for data in bulk_data:
                unified_db_manager.create_audit_log(data)
            
            end_time = time.time()
            insert_time = end_time - start_time
            
            # Should complete within reasonable time (adjust threshold as needed)
            assert insert_time < 5.0  # 5 seconds for 100 inserts
    
    def test_transaction_rollback(self, unified_db_manager, db_session, sample_tenant_data):
        """Test transaction rollback on error."""
        with patch.object(unified_db_manager, 'get_session') as mock_session:
            mock_session.return_value.__enter__.return_value = db_session
            
            # Force a database error during tenant creation
            with patch.object(db_session, 'commit', side_effect=Exception("Database error")):
                with pytest.raises(Exception):
                    unified_db_manager.create_tenant(sample_tenant_data)
                
                # Verify rollback occurred - tenant should not exist
                tenant = unified_db_manager.get_tenant_by_id(sample_tenant_data['tenant_id'])
                assert tenant is None
    
    def test_connection_pool_management(self, unified_db_manager):
        """Test database connection pool management."""
        with patch.object(unified_db_manager, 'engine') as mock_engine:
            mock_pool = Mock()
            mock_engine.pool = mock_pool
            mock_pool.size.return_value = 5
            mock_pool.checked_in.return_value = 3
            mock_pool.checked_out.return_value = 2
            
            pool_status = unified_db_manager.get_connection_pool_status()
            
            assert pool_status['pool_size'] == 5
            assert pool_status['checked_in'] == 3
            assert pool_status['checked_out'] == 2