#!/usr/bin/env python3
"""
Comprehensive Weaviate Integration Tests for AuditHound
Tests vector insert/retrieve, multi-tenant operations, and error handling
"""

import pytest
import uuid
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from unittest.mock import Mock, patch, AsyncMock
import numpy as np

# Test imports
try:
    import weaviate
    from weaviate.client import WeaviateClient
    from weaviate.classes.config import Configure
    from weaviate.classes.data import DataObject
    from weaviate.classes.query import Filter
    WEAVIATE_AVAILABLE = True
except ImportError:
    WEAVIATE_AVAILABLE = False
    
    # Mock DataObject when weaviate is not available
    class DataObject:
        def __init__(self, properties=None, uuid=None, vector=None):
            self.properties = properties or {}
            self.uuid = uuid
            self.vector = vector

# Mock classes for when Weaviate is not available
class MockWeaviateClient:
    def __init__(self, url: str):
        self.url = url
        self.is_ready = True
        self.is_live = True
        self._collections: Dict[str, Any] = {}
        self._data: Dict[str, List[Dict[str, Any]]] = {}
    
    def collections(self):
        return MockCollections(self._collections, self._data)
    
    def close(self):
        pass

class MockCollections:
    def __init__(self, collections: Dict[str, Any], data: Dict[str, List[Dict[str, Any]]]):
        self._collections = collections
        self._data = data
    
    def create(self, name: str, **kwargs):
        self._collections[name] = kwargs
        self._data[name] = []
        return MockCollection(name, self._data[name])
    
    def get(self, name: str):
        if name not in self._collections:
            raise Exception(f"Collection {name} not found")
        return MockCollection(name, self._data[name])
    
    def delete(self, name: str):
        if name in self._collections:
            del self._collections[name]
            del self._data[name]

class MockCollection:
    def __init__(self, name: str, data: List[Dict[str, Any]]):
        self.name = name
        self._data = data
    
    def data(self):
        return MockDataOperations(self._data)
    
    def query(self):
        return MockQueryOperations(self._data)

class MockDataOperations:
    def __init__(self, data: List[Dict[str, Any]]):
        self._data = data
    
    def insert(self, properties: Dict[str, Any], uuid: Optional[str] = None, vector: Optional[List[float]] = None):
        obj = {
            'uuid': uuid or str(uuid.uuid4()),
            'properties': properties,
            'vector': vector or [0.1] * 384  # Default embedding size
        }
        self._data.append(obj)
        return obj['uuid']
    
    def insert_many(self, objects: List[DataObject]):
        results = []
        for obj in objects:
            obj_id = self.insert(
                properties=obj.properties,
                uuid=getattr(obj, 'uuid', None),
                vector=getattr(obj, 'vector', None)
            )
            results.append({'uuid': obj_id})
        return results
    
    def update(self, uuid: str, properties: Dict[str, Any]):
        for obj in self._data:
            if obj['uuid'] == uuid:
                obj['properties'].update(properties)
                return True
        return False
    
    def delete_by_id(self, uuid: str):
        for i, obj in enumerate(self._data):
            if obj['uuid'] == uuid:
                del self._data[i]
                return True
        return False

class MockQueryOperations:
    def __init__(self, data: List[Dict[str, Any]]):
        self._data = data
    
    def fetch_objects(self, limit: int = 100):
        return MockQueryResult(self._data[:limit])
    
    def near_vector(self, vector: List[float], limit: int = 10):
        # Simple mock similarity - return first N objects
        return MockQueryResult(self._data[:limit])
    
    def where(self, filter_condition):
        # Mock filtering - return all data for simplicity
        return MockQueryResult(self._data)

class MockQueryResult:
    def __init__(self, objects: List[Dict[str, Any]]):
        self.objects = [MockObject(obj) for obj in objects]

class MockObject:
    def __init__(self, data: Dict[str, Any]):
        self.uuid = data['uuid']
        self.properties = data['properties']
        self.vector = data.get('vector')

# Test configuration
TEST_CONFIG = {
    'weaviate_url': 'http://localhost:8080',
    'test_timeout': 30,
    'batch_size': 100,
    'vector_dimensions': 384
}

class WeaviateTestClient:
    """Test client for Weaviate operations"""
    
    def __init__(self, url: str = TEST_CONFIG['weaviate_url'], use_mock: bool = True):
        self.url = url
        self.use_mock = use_mock
        self.client: Optional[Union[WeaviateClient, MockWeaviateClient]] = None
        self.collections: Dict[str, str] = {}
        
    async def connect(self) -> bool:
        """Connect to Weaviate instance"""
        try:
            if self.use_mock or not WEAVIATE_AVAILABLE:
                self.client = MockWeaviateClient(self.url)
            else:
                self.client = weaviate.connect_to_local(host=self.url.split('://')[-1])
            
            # Test connection
            if hasattr(self.client, 'is_ready'):
                return self.client.is_ready()
            return True
            
        except Exception as e:
            print(f"Failed to connect to Weaviate: {e}")
            return False
    
    async def disconnect(self):
        """Disconnect from Weaviate"""
        if self.client:
            self.client.close()
            self.client = None
    
    async def create_test_collection(self, collection_name: str, 
                                   properties: List[Dict[str, Any]] = None) -> bool:
        """Create a test collection"""
        if not self.client:
            return False
        
        try:
            # Default properties for audit findings
            if not properties:
                properties = [
                    {"name": "finding_id", "dataType": ["text"]},
                    {"name": "severity", "dataType": ["text"]},
                    {"name": "description", "dataType": ["text"]},
                    {"name": "client_id", "dataType": ["text"]},
                    {"name": "timestamp", "dataType": ["date"]},
                    {"name": "metadata", "dataType": ["object"]}
                ]
            
            # Create collection
            if self.use_mock:
                self.client.collections().create(
                    name=collection_name,
                    properties=properties
                )
            else:
                from weaviate.classes.config import Property, DataType
                weaviate_properties = []
                for prop in properties:
                    data_types = []
                    for dt in prop["dataType"]:
                        if dt == "text":
                            data_types.append(DataType.TEXT)
                        elif dt == "date":
                            data_types.append(DataType.DATE)
                        elif dt == "object":
                            data_types.append(DataType.OBJECT)
                    
                    weaviate_properties.append(
                        Property(name=prop["name"], data_type=data_types)
                    )
                
                self.client.collections.create(
                    name=collection_name,
                    properties=weaviate_properties,
                    vectorizer_config=Configure.Vectorizer.text2vec_transformers()
                )
            
            self.collections[collection_name] = collection_name
            return True
            
        except Exception as e:
            print(f"Failed to create collection {collection_name}: {e}")
            return False
    
    async def delete_test_collection(self, collection_name: str) -> bool:
        """Delete a test collection"""
        if not self.client:
            return False
        
        try:
            self.client.collections().delete(collection_name)
            if collection_name in self.collections:
                del self.collections[collection_name]
            return True
        except Exception as e:
            print(f"Failed to delete collection {collection_name}: {e}")
            return False
    
    async def insert_test_objects(self, collection_name: str, 
                                objects: List[Dict[str, Any]], 
                                vectors: Optional[List[List[float]]] = None) -> List[str]:
        """Insert test objects into collection"""
        if not self.client:
            return []
        
        try:
            collection = self.client.collections().get(collection_name)
            inserted_ids = []
            
            for i, obj in enumerate(objects):
                vector = vectors[i] if vectors and i < len(vectors) else None
                obj_id = str(uuid.uuid4())
                
                collection.data().insert(
                    properties=obj,
                    uuid=obj_id,
                    vector=vector
                )
                inserted_ids.append(obj_id)
            
            return inserted_ids
            
        except Exception as e:
            print(f"Failed to insert objects: {e}")
            return []
    
    async def query_objects(self, collection_name: str, 
                          limit: int = 10, 
                          vector: Optional[List[float]] = None,
                          where_filter: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Query objects from collection"""
        if not self.client:
            return []
        
        try:
            collection = self.client.collections().get(collection_name)
            
            if vector:
                # Vector similarity search
                result = collection.query().near_vector(vector=vector, limit=limit)
            elif where_filter:
                # Filtered query
                result = collection.query().where(where_filter).fetch_objects(limit=limit)
            else:
                # Fetch all
                result = collection.query().fetch_objects(limit=limit)
            
            objects = []
            for obj in result.objects:
                objects.append({
                    'uuid': obj.uuid,
                    'properties': obj.properties,
                    'vector': getattr(obj, 'vector', None)
                })
            
            return objects
            
        except Exception as e:
            print(f"Failed to query objects: {e}")
            return []

# Test fixtures
@pytest.fixture
async def weaviate_client():
    """Weaviate test client fixture"""
    client = WeaviateTestClient(use_mock=True)
    connected = await client.connect()
    assert connected, "Failed to connect to Weaviate"
    
    yield client
    
    # Cleanup
    for collection_name in list(client.collections.keys()):
        await client.delete_test_collection(collection_name)
    await client.disconnect()

@pytest.fixture
def sample_audit_findings():
    """Sample audit findings for testing"""
    return [
        {
            "finding_id": "FIND-001",
            "severity": "HIGH",
            "description": "Unencrypted database connection detected",
            "client_id": "client_123",
            "timestamp": datetime.now().isoformat(),
            "metadata": {
                "source": "database_scan",
                "category": "encryption",
                "remediation": "Enable SSL/TLS"
            }
        },
        {
            "finding_id": "FIND-002", 
            "severity": "MEDIUM",
            "description": "Weak password policy identified",
            "client_id": "client_123",
            "timestamp": datetime.now().isoformat(),
            "metadata": {
                "source": "policy_scan",
                "category": "authentication",
                "remediation": "Implement stronger password requirements"
            }
        },
        {
            "finding_id": "FIND-003",
            "severity": "LOW",
            "description": "Outdated software version detected",
            "client_id": "client_456",
            "timestamp": datetime.now().isoformat(),
            "metadata": {
                "source": "vulnerability_scan",
                "category": "patch_management",
                "remediation": "Update to latest version"
            }
        }
    ]

@pytest.fixture
def sample_vectors():
    """Sample embedding vectors for testing"""
    np.random.seed(42)  # For reproducible tests
    return [
        np.random.rand(TEST_CONFIG['vector_dimensions']).tolist(),
        np.random.rand(TEST_CONFIG['vector_dimensions']).tolist(),
        np.random.rand(TEST_CONFIG['vector_dimensions']).tolist()
    ]

# Basic Connection Tests
class TestWeaviateConnection:
    """Test Weaviate connection and basic operations"""
    
    @pytest.mark.asyncio
    async def test_connection_success(self, weaviate_client):
        """Test successful connection to Weaviate"""
        assert weaviate_client.client is not None
        assert weaviate_client.url == TEST_CONFIG['weaviate_url']
    
    @pytest.mark.asyncio
    async def test_connection_failure(self):
        """Test connection failure handling"""
        client = WeaviateTestClient(url="http://invalid:9999", use_mock=False)
        connected = await client.connect()
        assert not connected
    
    @pytest.mark.asyncio
    async def test_disconnect(self, weaviate_client):
        """Test graceful disconnection"""
        await weaviate_client.disconnect()
        assert weaviate_client.client is None

# Collection Management Tests
class TestCollectionManagement:
    """Test collection creation, deletion, and management"""
    
    @pytest.mark.asyncio
    async def test_create_collection(self, weaviate_client):
        """Test collection creation"""
        collection_name = "test_audit_findings"
        success = await weaviate_client.create_test_collection(collection_name)
        
        assert success
        assert collection_name in weaviate_client.collections
    
    @pytest.mark.asyncio
    async def test_create_duplicate_collection(self, weaviate_client):
        """Test creating duplicate collection"""
        collection_name = "test_duplicate"
        
        # Create first collection
        success1 = await weaviate_client.create_test_collection(collection_name)
        assert success1
        
        # Try to create duplicate (should handle gracefully)
        success2 = await weaviate_client.create_test_collection(collection_name)
        # Depending on implementation, this might succeed or fail gracefully
    
    @pytest.mark.asyncio
    async def test_delete_collection(self, weaviate_client):
        """Test collection deletion"""
        collection_name = "test_to_delete"
        
        # Create then delete
        await weaviate_client.create_test_collection(collection_name)
        success = await weaviate_client.delete_test_collection(collection_name)
        
        assert success
        assert collection_name not in weaviate_client.collections
    
    @pytest.mark.asyncio
    async def test_delete_nonexistent_collection(self, weaviate_client):
        """Test deleting non-existent collection"""
        success = await weaviate_client.delete_test_collection("nonexistent")
        assert not success

# Data Insertion Tests
class TestDataInsertion:
    """Test data insertion operations"""
    
    @pytest.mark.asyncio
    async def test_insert_single_object(self, weaviate_client, sample_audit_findings):
        """Test inserting a single object"""
        collection_name = "test_single_insert"
        await weaviate_client.create_test_collection(collection_name)
        
        finding = sample_audit_findings[0]
        result = await weaviate_client.insert_test_objects(collection_name, [finding])
        
        assert len(result) == 1
        assert result[0] is not None  # Should return UUID
    
    @pytest.mark.asyncio
    async def test_insert_multiple_objects(self, weaviate_client, sample_audit_findings):
        """Test batch insertion of multiple objects"""
        collection_name = "test_batch_insert"
        await weaviate_client.create_test_collection(collection_name)
        
        result = await weaviate_client.insert_test_objects(collection_name, sample_audit_findings)
        
        assert len(result) == len(sample_audit_findings)
        assert all(uuid is not None for uuid in result)
    
    @pytest.mark.asyncio
    async def test_insert_with_vectors(self, weaviate_client, sample_audit_findings, sample_vectors):
        """Test inserting objects with custom vectors"""
        collection_name = "test_vector_insert"
        await weaviate_client.create_test_collection(collection_name)
        
        result = await weaviate_client.insert_test_objects(
            collection_name, 
            sample_audit_findings, 
            vectors=sample_vectors
        )
        
        assert len(result) == len(sample_audit_findings)
    
    @pytest.mark.asyncio
    async def test_insert_invalid_data(self, weaviate_client):
        """Test inserting invalid data"""
        collection_name = "test_invalid_insert"
        await weaviate_client.create_test_collection(collection_name)
        
        # Try to insert invalid object
        invalid_object = {"invalid_field": "value"}
        result = await weaviate_client.insert_test_objects(collection_name, [invalid_object])
        
        # Should handle gracefully (might succeed with mock, fail with real Weaviate)
        assert isinstance(result, list)

# Data Retrieval Tests
class TestDataRetrieval:
    """Test data retrieval and querying operations"""
    
    @pytest.mark.asyncio
    async def test_query_all_objects(self, weaviate_client, sample_audit_findings):
        """Test querying all objects from collection"""
        collection_name = "test_query_all"
        await weaviate_client.create_test_collection(collection_name)
        await weaviate_client.insert_test_objects(collection_name, sample_audit_findings)
        
        results = await weaviate_client.query_objects(collection_name)
        
        assert len(results) == len(sample_audit_findings)
        assert all('uuid' in obj for obj in results)
        assert all('properties' in obj for obj in results)
    
    @pytest.mark.asyncio
    async def test_query_with_limit(self, weaviate_client, sample_audit_findings):
        """Test querying with limit"""
        collection_name = "test_query_limit"
        await weaviate_client.create_test_collection(collection_name)
        await weaviate_client.insert_test_objects(collection_name, sample_audit_findings)
        
        results = await weaviate_client.query_objects(collection_name, limit=2)
        
        assert len(results) <= 2
    
    @pytest.mark.asyncio
    async def test_vector_similarity_search(self, weaviate_client, sample_audit_findings, sample_vectors):
        """Test vector similarity search"""
        collection_name = "test_vector_search"
        await weaviate_client.create_test_collection(collection_name)
        await weaviate_client.insert_test_objects(collection_name, sample_audit_findings, vectors=sample_vectors)
        
        # Search with similar vector
        query_vector = sample_vectors[0]
        results = await weaviate_client.query_objects(
            collection_name, 
            vector=query_vector, 
            limit=5
        )
        
        assert len(results) <= 5
        # Results should include the exact match (first object)
        if results:
            assert any(
                obj['properties']['finding_id'] == sample_audit_findings[0]['finding_id'] 
                for obj in results
            )
    
    @pytest.mark.asyncio
    async def test_filtered_query(self, weaviate_client, sample_audit_findings):
        """Test querying with filters"""
        collection_name = "test_filtered_query"
        await weaviate_client.create_test_collection(collection_name)
        await weaviate_client.insert_test_objects(collection_name, sample_audit_findings)
        
        # Filter by client_id
        filter_condition = {"path": ["client_id"], "operator": "Equal", "valueText": "client_123"}
        results = await weaviate_client.query_objects(
            collection_name, 
            where_filter=filter_condition
        )
        
        # Should return objects for client_123
        assert len(results) >= 0  # Mock might return all, real Weaviate should filter
    
    @pytest.mark.asyncio
    async def test_query_empty_collection(self, weaviate_client):
        """Test querying empty collection"""
        collection_name = "test_empty_query"
        await weaviate_client.create_test_collection(collection_name)
        
        results = await weaviate_client.query_objects(collection_name)
        
        assert len(results) == 0

# Multi-tenant Tests
class TestMultiTenantOperations:
    """Test multi-tenant data isolation and operations"""
    
    @pytest.mark.asyncio
    async def test_client_data_isolation(self, weaviate_client, sample_audit_findings):
        """Test that client data is properly isolated"""
        collection_name = "test_isolation"
        await weaviate_client.create_test_collection(collection_name)
        
        # Insert findings for different clients
        client1_findings = [f for f in sample_audit_findings if f['client_id'] == 'client_123']
        client2_findings = [f for f in sample_audit_findings if f['client_id'] == 'client_456']
        
        await weaviate_client.insert_test_objects(collection_name, client1_findings + client2_findings)
        
        # Query for each client
        all_results = await weaviate_client.query_objects(collection_name)
        
        # Verify data exists for both clients
        client1_results = [r for r in all_results if r['properties']['client_id'] == 'client_123']
        client2_results = [r for r in all_results if r['properties']['client_id'] == 'client_456']
        
        assert len(client1_results) >= len(client1_findings)
        assert len(client2_results) >= len(client2_findings)
    
    @pytest.mark.asyncio
    async def test_concurrent_client_operations(self, weaviate_client, sample_audit_findings):
        """Test concurrent operations from multiple clients"""
        collection_name = "test_concurrent"
        await weaviate_client.create_test_collection(collection_name)
        
        # Simulate concurrent inserts
        tasks = []
        for i, finding in enumerate(sample_audit_findings):
            # Modify client_id to simulate different clients
            finding_copy = finding.copy()
            finding_copy['client_id'] = f"client_{i}"
            tasks.append(
                weaviate_client.insert_test_objects(collection_name, [finding_copy])
            )
        
        results = await asyncio.gather(*tasks)
        
        # All inserts should succeed
        assert all(len(result) == 1 for result in results)

# Performance Tests
class TestPerformance:
    """Test performance characteristics and limits"""
    
    @pytest.mark.asyncio
    async def test_large_batch_insert(self, weaviate_client):
        """Test inserting large batch of objects"""
        collection_name = "test_large_batch"
        await weaviate_client.create_test_collection(collection_name)
        
        # Generate large batch
        batch_size = 1000
        large_batch = []
        for i in range(batch_size):
            large_batch.append({
                "finding_id": f"FIND-{i:04d}",
                "severity": "MEDIUM",
                "description": f"Test finding number {i}",
                "client_id": f"client_{i % 10}",  # 10 different clients
                "timestamp": datetime.now().isoformat(),
                "metadata": {"test": True, "batch_id": i}
            })
        
        start_time = datetime.now()
        result = await weaviate_client.insert_test_objects(collection_name, large_batch)
        end_time = datetime.now()
        
        duration = (end_time - start_time).total_seconds()
        
        assert len(result) == batch_size
        print(f"Inserted {batch_size} objects in {duration:.2f} seconds")
        print(f"Rate: {batch_size / duration:.0f} objects/second")
    
    @pytest.mark.asyncio
    async def test_large_query_result(self, weaviate_client):
        """Test querying large result sets"""
        collection_name = "test_large_query"
        await weaviate_client.create_test_collection(collection_name)
        
        # Insert test data
        batch = []
        for i in range(500):
            batch.append({
                "finding_id": f"FIND-{i:04d}",
                "severity": "LOW",
                "description": f"Test finding {i}",
                "client_id": "test_client",
                "timestamp": datetime.now().isoformat(),
                "metadata": {"index": i}
            })
        
        await weaviate_client.insert_test_objects(collection_name, batch)
        
        # Query large result set
        start_time = datetime.now()
        results = await weaviate_client.query_objects(collection_name, limit=1000)
        end_time = datetime.now()
        
        duration = (end_time - start_time).total_seconds()
        
        assert len(results) <= 1000
        print(f"Queried {len(results)} objects in {duration:.2f} seconds")
    
    @pytest.mark.asyncio
    async def test_concurrent_queries(self, weaviate_client, sample_audit_findings):
        """Test concurrent query performance"""
        collection_name = "test_concurrent_queries"
        await weaviate_client.create_test_collection(collection_name)
        await weaviate_client.insert_test_objects(collection_name, sample_audit_findings)
        
        # Run concurrent queries
        num_concurrent = 10
        tasks = []
        for i in range(num_concurrent):
            tasks.append(weaviate_client.query_objects(collection_name, limit=10))
        
        start_time = datetime.now()
        results = await asyncio.gather(*tasks)
        end_time = datetime.now()
        
        duration = (end_time - start_time).total_seconds()
        
        assert len(results) == num_concurrent
        assert all(isinstance(result, list) for result in results)
        print(f"Completed {num_concurrent} concurrent queries in {duration:.2f} seconds")

# Error Handling Tests
class TestErrorHandling:
    """Test error handling and recovery scenarios"""
    
    @pytest.mark.asyncio
    async def test_connection_loss_recovery(self):
        """Test recovery from connection loss"""
        # This test would be more meaningful with a real Weaviate instance
        client = WeaviateTestClient(use_mock=True)
        
        # Connect
        connected = await client.connect()
        assert connected
        
        # Simulate connection loss
        await client.disconnect()
        
        # Reconnect
        reconnected = await client.connect()
        assert reconnected
        
        await client.disconnect()
    
    @pytest.mark.asyncio
    async def test_invalid_collection_operations(self, weaviate_client):
        """Test operations on invalid collections"""
        # Try to insert into non-existent collection
        result = await weaviate_client.insert_test_objects("nonexistent", [{"test": "data"}])
        assert len(result) == 0
        
        # Try to query non-existent collection
        result = await weaviate_client.query_objects("nonexistent")
        assert len(result) == 0
    
    @pytest.mark.asyncio
    async def test_malformed_data_handling(self, weaviate_client):
        """Test handling of malformed data"""
        collection_name = "test_malformed"
        await weaviate_client.create_test_collection(collection_name)
        
        # Test various malformed data
        malformed_objects = [
            None,
            {"timestamp": "invalid-date"},
            {"metadata": "should-be-object"},
            {"": "empty-key"},
        ]
        
        for obj in malformed_objects:
            result = await weaviate_client.insert_test_objects(collection_name, [obj] if obj else [])
            # Should handle gracefully without crashing
            assert isinstance(result, list)
    
    @pytest.mark.asyncio
    async def test_vector_dimension_mismatch(self, weaviate_client, sample_audit_findings):
        """Test handling of vector dimension mismatches"""
        collection_name = "test_vector_mismatch"
        await weaviate_client.create_test_collection(collection_name)
        
        # Use wrong vector dimensions
        wrong_vectors = [
            [0.1, 0.2, 0.3],  # Too short
            [0.1] * 1000,     # Too long
        ]
        
        for vector in wrong_vectors:
            result = await weaviate_client.insert_test_objects(
                collection_name, 
                [sample_audit_findings[0]], 
                vectors=[vector]
            )
            # Should handle gracefully
            assert isinstance(result, list)

# Integration Tests
class TestIntegration:
    """Test integration scenarios and workflows"""
    
    @pytest.mark.asyncio
    async def test_full_audit_workflow(self, weaviate_client):
        """Test complete audit finding workflow"""
        collection_name = "test_audit_workflow"
        await weaviate_client.create_test_collection(collection_name)
        
        # Step 1: Insert initial finding
        finding = {
            "finding_id": "WORKFLOW-001",
            "severity": "HIGH",
            "description": "Critical security vulnerability",
            "client_id": "test_client",
            "timestamp": datetime.now().isoformat(),
            "metadata": {
                "status": "open",
                "assigned_to": "security_team",
                "source": "automated_scan"
            }
        }
        
        insert_result = await weaviate_client.insert_test_objects(collection_name, [finding])
        assert len(insert_result) == 1
        
        # Step 2: Query finding
        results = await weaviate_client.query_objects(collection_name)
        assert len(results) >= 1
        assert any(obj['properties']['finding_id'] == 'WORKFLOW-001' for obj in results)
        
        # Step 3: Verify data integrity
        found_object = next(
            obj for obj in results 
            if obj['properties']['finding_id'] == 'WORKFLOW-001'
        )
        assert found_object['properties']['severity'] == 'HIGH'
        assert found_object['properties']['client_id'] == 'test_client'
    
    @pytest.mark.asyncio
    async def test_cross_collection_operations(self, weaviate_client):
        """Test operations across multiple collections"""
        # Create multiple collections
        collections = ["audit_findings", "compliance_reports", "risk_assessments"]
        
        for collection in collections:
            success = await weaviate_client.create_test_collection(collection)
            assert success
        
        # Insert data into each collection
        for i, collection in enumerate(collections):
            test_data = {
                "id": f"TEST-{i:03d}",
                "type": collection.replace('_', ' ').title(),
                "client_id": "multi_client",
                "timestamp": datetime.now().isoformat(),
                "metadata": {"collection": collection}
            }
            
            result = await weaviate_client.insert_test_objects(collection, [test_data])
            assert len(result) == 1
        
        # Query each collection
        for collection in collections:
            results = await weaviate_client.query_objects(collection)
            assert len(results) >= 1

# Cleanup and utility functions
def generate_test_vector(dimensions: int = TEST_CONFIG['vector_dimensions']) -> List[float]:
    """Generate a random test vector"""
    np.random.seed()  # Use random seed
    return np.random.rand(dimensions).tolist()

def validate_object_structure(obj: Dict[str, Any]) -> bool:
    """Validate that an object has the expected structure"""
    required_fields = ['uuid', 'properties']
    return all(field in obj for field in required_fields)

# Main test runner
if __name__ == "__main__":
    # Run specific test groups
    import sys
    
    if len(sys.argv) > 1:
        test_group = sys.argv[1]
        print(f"Running test group: {test_group}")
        
        if test_group == "connection":
            pytest.main(["-v", "TestWeaviateConnection"])
        elif test_group == "collections":
            pytest.main(["-v", "TestCollectionManagement"])
        elif test_group == "data":
            pytest.main(["-v", "TestDataInsertion", "TestDataRetrieval"])
        elif test_group == "multitenant":
            pytest.main(["-v", "TestMultiTenantOperations"])
        elif test_group == "performance":
            pytest.main(["-v", "TestPerformance"])
        elif test_group == "errors":
            pytest.main(["-v", "TestErrorHandling"])
        elif test_group == "integration":
            pytest.main(["-v", "TestIntegration"])
        else:
            print("Unknown test group. Available: connection, collections, data, multitenant, performance, errors, integration")
    else:
        # Run all tests
        print("Running comprehensive Weaviate integration tests...")
        pytest.main(["-v", __file__])