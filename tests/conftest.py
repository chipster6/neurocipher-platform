# Test configuration and fixtures for AuditHound comprehensive testing suite
import os
import pytest
import asyncio
import tempfile
import shutil
from unittest.mock import Mock, patch
from typing import Generator, AsyncGenerator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from fastapi.testclient import TestClient
import redis
from weaviate import Client as WeaviateClient

# Import application components
from src.api.main import app
from src.persistence.unified_db_manager import UnifiedDatabaseManager
from src.multi_tenant_manager import MultiTenantManager
from src.security.unified_auth_manager import UnifiedAuthManager
from src.ai_analytics.ai_analytics_manager import AIAnalyticsManager


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_config():
    """Test configuration settings."""
    return {
        "DATABASE_URL": "sqlite:///test_audithound.db",
        "REDIS_URL": "redis://localhost:6379/15",  # Use different DB for tests
        "WEAVIATE_URL": "http://localhost:8080",
        "SECRET_KEY": "test-secret-key-for-testing-only",
        "JWT_SECRET": "test-jwt-secret",
        "ENCRYPTION_KEY": "test-encryption-key-32-bytes-long!",
        "ENVIRONMENT": "testing",
        "DEBUG": True,
        "TESTING": True,
        "AI_ENABLED": False,  # Disable AI features in tests by default
        "PERFORMANCE_MONITORING": False,
    }


@pytest.fixture(scope="session")
def test_database(test_config):
    """Create test database and manage its lifecycle."""
    # Create test database engine
    engine = create_engine(test_config["DATABASE_URL"], echo=False)
    
    # Create all tables
    from src.unified_models import Base
    Base.metadata.create_all(engine)
    
    yield engine
    
    # Cleanup
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def db_session(test_database):
    """Create a database session for testing."""
    SessionLocal = sessionmaker(bind=test_database)
    session = SessionLocal()
    
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def test_client(test_config):
    """Create FastAPI test client."""
    with patch.dict(os.environ, test_config):
        client = TestClient(app)
        yield client


@pytest.fixture
def mock_redis():
    """Mock Redis client for testing."""
    with patch('redis.Redis') as mock_redis_class:
        mock_redis_instance = Mock()
        mock_redis_class.return_value = mock_redis_instance
        yield mock_redis_instance


@pytest.fixture
def mock_weaviate():
    """Mock Weaviate client for testing."""
    with patch('weaviate.Client') as mock_weaviate_class:
        mock_weaviate_instance = Mock()
        mock_weaviate_class.return_value = mock_weaviate_instance
        yield mock_weaviate_instance


@pytest.fixture
def temp_directory():
    """Create temporary directory for file-based tests."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def sample_audit_data():
    """Sample audit data for testing."""
    return {
        "timestamp": "2024-01-01T12:00:00Z",
        "resource_id": "test-resource-001",
        "resource_type": "compute_instance",
        "region": "us-east-1",
        "findings": [
            {
                "control_id": "IAM-001",
                "status": "FAIL",
                "severity": "HIGH",
                "description": "Instance has overly permissive IAM role"
            }
        ],
        "compliance_frameworks": ["SOC2", "ISO27001"],
        "tenant_id": "test-tenant-001"
    }


@pytest.fixture
def sample_tenant_data():
    """Sample tenant data for testing."""
    return {
        "tenant_id": "test-tenant-001",
        "name": "Test Tenant",
        "description": "Test tenant for unit testing",
        "configuration": {
            "compliance_frameworks": ["SOC2", "ISO27001"],
            "ai_analytics_enabled": True,
            "post_quantum_enabled": True
        },
        "subscription_plan": "enterprise",
        "status": "active"
    }


@pytest.fixture
def unified_db_manager(test_config, db_session):
    """Create UnifiedDatabaseManager for testing."""
    with patch.dict(os.environ, test_config):
        manager = UnifiedDatabaseManager()
        yield manager


@pytest.fixture
def multi_tenant_manager(test_config, unified_db_manager):
    """Create MultiTenantManager for testing."""
    with patch.dict(os.environ, test_config):
        manager = MultiTenantManager(db_manager=unified_db_manager)
        yield manager


@pytest.fixture
def auth_manager(test_config):
    """Create UnifiedAuthManager for testing."""
    with patch.dict(os.environ, test_config):
        manager = UnifiedAuthManager()
        yield manager


@pytest.fixture
def ai_analytics_manager(test_config, mock_weaviate):
    """Create AIAnalyticsManager for testing."""
    with patch.dict(os.environ, test_config):
        manager = AIAnalyticsManager()
        yield manager


@pytest.fixture
def mock_cloud_apis():
    """Mock cloud provider APIs."""
    with patch('boto3.client') as mock_boto3, \
         patch('google.cloud.security_center.SecurityCenterClient') as mock_gcp, \
         patch('azure.identity.DefaultAzureCredential') as mock_azure:
        
        # Mock AWS
        mock_aws_client = Mock()
        mock_boto3.return_value = mock_aws_client
        
        # Mock GCP
        mock_gcp_client = Mock()
        mock_gcp.return_value = mock_gcp_client
        
        # Mock Azure
        mock_azure_client = Mock()
        mock_azure.return_value = mock_azure_client
        
        yield {
            'aws': mock_aws_client,
            'gcp': mock_gcp_client,
            'azure': mock_azure_client
        }


@pytest.fixture
def performance_metrics():
    """Performance testing metrics collector."""
    metrics = {
        'response_times': [],
        'memory_usage': [],
        'cpu_usage': [],
        'database_queries': [],
        'cache_hits': 0,
        'cache_misses': 0
    }
    yield metrics


# Pytest hooks for custom behavior
def pytest_configure(config):
    """Configure pytest with custom markers and settings."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )
    config.addinivalue_line(
        "markers", "e2e: marks tests as end-to-end tests"
    )
    config.addinivalue_line(
        "markers", "security: marks tests as security-related"
    )
    config.addinivalue_line(
        "markers", "performance: marks tests as performance tests"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test paths."""
    for item in items:
        # Add markers based on test file names
        if "test_e2e" in item.nodeid:
            item.add_marker(pytest.mark.e2e)
        elif "test_integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        elif "test_performance" in item.nodeid:
            item.add_marker(pytest.mark.performance)
        elif "test_security" in item.nodeid:
            item.add_marker(pytest.mark.security)
        else:
            item.add_marker(pytest.mark.unit)
        
        # Mark slow tests
        if "slow" in item.keywords:
            item.add_marker(pytest.mark.slow)


# Test utilities
class TestUtils:
    """Utility functions for testing."""
    
    @staticmethod
    def create_test_user(db_session, tenant_id="test-tenant-001"):
        """Create a test user in the database."""
        from src.unified_models import User
        user = User(
            username=f"testuser_{tenant_id}",
            email=f"test@{tenant_id}.com",
            hashed_password="test-password-hash",
            tenant_id=tenant_id,
            is_active=True
        )
        db_session.add(user)
        db_session.commit()
        return user
    
    @staticmethod
    def create_test_audit_log(db_session, tenant_id="test-tenant-001"):
        """Create a test audit log entry."""
        from src.unified_models import AuditLog
        audit_log = AuditLog(
            tenant_id=tenant_id,
            resource_id="test-resource",
            resource_type="compute_instance",
            event_type="security_scan",
            status="completed",
            metadata={"test": True}
        )
        db_session.add(audit_log)
        db_session.commit()
        return audit_log


@pytest.fixture
def test_utils():
    """Provide test utilities."""
    return TestUtils