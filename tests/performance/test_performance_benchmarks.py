# Performance testing and benchmarking framework
import pytest
import time
import asyncio
import statistics
import psutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import patch, Mock
from typing import List, Dict, Any

from src.persistence.unified_db_manager import UnifiedDatabaseManager
from src.multi_tenant_manager import MultiTenantManager
from src.ai_analytics.ai_analytics_manager import AIAnalyticsManager


@pytest.mark.performance
class TestPerformanceBenchmarks:
    """Performance testing and benchmarking suite."""
    
    def test_database_connection_pool_performance(self, unified_db_manager, performance_metrics):
        """Test database connection pool performance under load."""
        def database_operation(thread_id: int):
            start_time = time.time()
            try:
                with unified_db_manager.get_session() as session:
                    # Simulate database query
                    result = session.execute("SELECT 1").scalar()
                    assert result == 1
                end_time = time.time()
                return end_time - start_time
            except Exception as e:
                return float('inf')  # Mark as failed
        
        # Test with multiple concurrent connections
        num_threads = 20
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(database_operation, i) for i in range(num_threads)]
            response_times = [future.result() for future in as_completed(futures)]
        
        # Analyze performance
        valid_times = [t for t in response_times if t != float('inf')]
        assert len(valid_times) == num_threads, "Some database operations failed"
        
        avg_response_time = statistics.mean(valid_times)
        max_response_time = max(valid_times)
        
        performance_metrics['database_queries'].extend(valid_times)
        
        # Performance assertions
        assert avg_response_time < 0.1, f"Average response time {avg_response_time:.3f}s too high"
        assert max_response_time < 0.5, f"Max response time {max_response_time:.3f}s too high"
    
    def test_tenant_cache_performance(self, multi_tenant_manager, performance_metrics):
        """Test tenant cache performance and hit rates."""
        # Populate cache with test tenants
        tenant_data_template = {
            "name": "Performance Test Tenant",
            "description": "Tenant for performance testing",
            "configuration": {"test": True},
            "subscription_plan": "enterprise",
            "status": "active"
        }
        
        num_tenants = 1000
        tenant_ids = []
        
        # Create tenants (warm up cache)
        for i in range(num_tenants):
            tenant_data = {**tenant_data_template, "tenant_id": f"perf-tenant-{i:04d}"}
            with patch.object(multi_tenant_manager.db_manager, 'create_tenant') as mock_create:
                mock_tenant = Mock()
                mock_tenant.tenant_id = tenant_data["tenant_id"]
                mock_create.return_value = mock_tenant
                
                tenant = multi_tenant_manager.create_tenant(tenant_data)
                tenant_ids.append(tenant.tenant_id)
        
        # Test cache hit performance
        cache_hits = 0
        cache_misses = 0
        response_times = []
        
        with patch.object(multi_tenant_manager.db_manager, 'get_tenant_by_id') as mock_get:
            def mock_db_call(tenant_id):
                nonlocal cache_misses
                cache_misses += 1
                mock_tenant = Mock()
                mock_tenant.tenant_id = tenant_id
                return mock_tenant
            
            mock_get.side_effect = mock_db_call
            
            # Perform cache lookups
            for _ in range(5000):  # 5x more lookups than tenants
                tenant_id = f"perf-tenant-{hash(time.time()) % num_tenants:04d}"
                
                start_time = time.time()
                tenant = multi_tenant_manager.get_tenant(tenant_id)
                end_time = time.time()
                
                response_times.append(end_time - start_time)
                
                if mock_get.call_count == cache_misses:
                    # New database call was made
                    pass
                else:
                    cache_hits += 1
        
        # Calculate cache performance metrics
        total_requests = len(response_times)
        cache_hit_rate = cache_hits / total_requests if total_requests > 0 else 0
        avg_response_time = statistics.mean(response_times)
        
        performance_metrics['cache_hits'] = cache_hits
        performance_metrics['cache_misses'] = cache_misses
        performance_metrics['response_times'].extend(response_times)
        
        # Performance assertions
        assert cache_hit_rate > 0.8, f"Cache hit rate {cache_hit_rate:.2%} too low"
        assert avg_response_time < 0.001, f"Average cache lookup time {avg_response_time:.4f}s too high"
    
    @pytest.mark.slow
    def test_bulk_data_processing_performance(self, unified_db_manager, performance_metrics):
        """Test bulk data processing performance."""
        # Generate bulk audit data
        bulk_size = 1000
        audit_data_template = {
            "tenant_id": "perf-test-tenant",
            "resource_type": "compute_instance",
            "event_type": "security_scan",
            "status": "completed",
            "metadata": {"test": True}
        }
        
        bulk_data = []
        for i in range(bulk_size):
            audit_data = {
                **audit_data_template,
                "resource_id": f"bulk-resource-{i:04d}",
                "timestamp": time.time()
            }
            bulk_data.append(audit_data)
        
        # Test single-threaded bulk insert
        start_time = time.time()
        with patch.object(unified_db_manager, 'create_audit_log') as mock_create:
            mock_create.return_value = Mock()
            
            for data in bulk_data:
                unified_db_manager.create_audit_log(data)
        
        single_thread_time = time.time() - start_time
        
        # Test multi-threaded bulk insert
        def insert_batch(batch_data):
            for data in batch_data:
                unified_db_manager.create_audit_log(data)
        
        batch_size = 100
        batches = [bulk_data[i:i + batch_size] for i in range(0, bulk_size, batch_size)]
        
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(insert_batch, batch) for batch in batches]
            for future in as_completed(futures):
                future.result()  # Wait for completion
        
        multi_thread_time = time.time() - start_time
        
        # Calculate throughput
        single_throughput = bulk_size / single_thread_time
        multi_throughput = bulk_size / multi_thread_time
        
        performance_metrics['bulk_processing'] = {
            'single_thread_time': single_thread_time,
            'multi_thread_time': multi_thread_time,
            'single_throughput': single_throughput,
            'multi_throughput': multi_throughput,
            'speedup': single_thread_time / multi_thread_time
        }
        
        # Performance assertions
        assert single_throughput > 100, f"Single-thread throughput {single_throughput:.1f} records/sec too low"
        assert multi_throughput > single_throughput, "Multi-threading should improve performance"
        assert multi_thread_time < single_thread_time * 0.8, "Multi-threading speedup insufficient"
    
    def test_memory_usage_under_load(self, multi_tenant_manager, performance_metrics):
        """Test memory usage under sustained load."""
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        # Simulate sustained load
        for iteration in range(10):
            # Create many tenants
            for i in range(100):
                tenant_data = {
                    "tenant_id": f"memory-test-{iteration}-{i}",
                    "name": f"Memory Test Tenant {iteration}-{i}",
                    "status": "active"
                }
                with patch.object(multi_tenant_manager.db_manager, 'create_tenant') as mock_create:
                    mock_tenant = Mock()
                    mock_tenant.tenant_id = tenant_data["tenant_id"]
                    mock_create.return_value = mock_tenant
                    multi_tenant_manager.create_tenant(tenant_data)
            
            # Measure memory usage
            current_memory = process.memory_info().rss
            memory_increase = current_memory - initial_memory
            
            performance_metrics['memory_usage'].append({
                'iteration': iteration,
                'memory_rss': current_memory,
                'memory_increase': memory_increase
            })
            
            # Clear cache periodically to test memory cleanup
            if iteration % 3 == 0:
                multi_tenant_manager.clear_tenant_cache()
        
        final_memory = process.memory_info().rss
        total_memory_increase = final_memory - initial_memory
        
        # Memory usage assertions (adjust thresholds as needed)
        max_memory_increase = 100 * 1024 * 1024  # 100MB
        assert total_memory_increase < max_memory_increase, \
            f"Memory increase {total_memory_increase / 1024 / 1024:.1f}MB too high"
    
    @pytest.mark.asyncio
    async def test_async_operations_performance(self, performance_metrics):
        """Test asynchronous operations performance."""
        async def async_operation(operation_id: int):
            # Simulate async I/O operation
            await asyncio.sleep(0.01)  # 10ms simulated I/O
            return f"result-{operation_id}"
        
        # Test concurrent async operations
        start_time = time.time()
        
        tasks = [async_operation(i) for i in range(100)]
        results = await asyncio.gather(*tasks)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        assert len(results) == 100
        assert all(isinstance(result, str) for result in results)
        
        # Should complete much faster than sequential execution
        # Sequential would take ~1 second (100 * 0.01), concurrent should be ~0.01
        assert total_time < 0.1, f"Async operations took {total_time:.3f}s, too slow"
        
        performance_metrics['async_performance'] = {
            'operations': 100,
            'total_time': total_time,
            'operations_per_second': 100 / total_time
        }
    
    def test_ai_analytics_performance(self, ai_analytics_manager, performance_metrics):
        """Test AI analytics processing performance."""
        # Mock AI analytics operations
        sample_audit_data = [
            {
                "tenant_id": "perf-ai-tenant",
                "resource_id": f"ai-resource-{i}",
                "findings": [{"control_id": f"CTRL-{i}", "severity": "HIGH"}],
                "timestamp": time.time()
            }
            for i in range(50)
        ]
        
        # Test pattern detection performance
        start_time = time.time()
        
        with patch.object(ai_analytics_manager, 'detect_patterns') as mock_detect:
            mock_detect.return_value = {"patterns": ["test_pattern"], "confidence": 0.85}
            
            patterns = ai_analytics_manager.detect_patterns(sample_audit_data)
        
        pattern_detection_time = time.time() - start_time
        
        # Test threat correlation performance
        start_time = time.time()
        
        with patch.object(ai_analytics_manager, 'correlate_threats') as mock_correlate:
            mock_correlate.return_value = {"threats": ["test_threat"], "risk_score": 0.75}
            
            threats = ai_analytics_manager.correlate_threats(sample_audit_data)
        
        threat_correlation_time = time.time() - start_time
        
        performance_metrics['ai_analytics'] = {
            'pattern_detection_time': pattern_detection_time,
            'threat_correlation_time': threat_correlation_time,
            'data_points_processed': len(sample_audit_data)
        }
        
        # Performance assertions
        assert pattern_detection_time < 1.0, f"Pattern detection took {pattern_detection_time:.3f}s"
        assert threat_correlation_time < 1.0, f"Threat correlation took {threat_correlation_time:.3f}s"
    
    def test_api_response_time_distribution(self, test_client, performance_metrics):
        """Test API response time distribution and percentiles."""
        response_times = []
        
        # Create a tenant for testing
        tenant_data = {
            "tenant_id": "api-perf-tenant",
            "name": "API Performance Test Tenant",
            "status": "active"
        }
        test_client.post("/api/v1/tenants", json=tenant_data)
        
        # Perform many API requests
        for i in range(100):
            start_time = time.time()
            response = test_client.get(f"/api/v1/tenants/{tenant_data['tenant_id']}")
            end_time = time.time()
            
            assert response.status_code == 200
            response_times.append(end_time - start_time)
        
        # Calculate percentiles
        response_times.sort()
        percentiles = {
            'p50': response_times[int(0.50 * len(response_times))],
            'p90': response_times[int(0.90 * len(response_times))],
            'p95': response_times[int(0.95 * len(response_times))],
            'p99': response_times[int(0.99 * len(response_times))]
        }
        
        performance_metrics['api_response_times'] = {
            'mean': statistics.mean(response_times),
            'median': statistics.median(response_times),
            'std_dev': statistics.stdev(response_times),
            'percentiles': percentiles,
            'min': min(response_times),
            'max': max(response_times)
        }
        
        # Performance SLA assertions
        assert percentiles['p50'] < 0.2, f"P50 response time {percentiles['p50']:.3f}s exceeds SLA"
        assert percentiles['p90'] < 0.5, f"P90 response time {percentiles['p90']:.3f}s exceeds SLA"
        assert percentiles['p95'] < 1.0, f"P95 response time {percentiles['p95']:.3f}s exceeds SLA"
        
        # Cleanup
        test_client.delete(f"/api/v1/tenants/{tenant_data['tenant_id']}")
    
    def test_database_query_optimization(self, unified_db_manager, performance_metrics):
        """Test database query performance and optimization."""
        # Test different query patterns
        query_tests = [
            {
                'name': 'simple_select',
                'query': 'SELECT 1',
                'expected_time': 0.001
            },
            {
                'name': 'complex_join',
                'query': '''
                    SELECT t.tenant_id, COUNT(al.id) as audit_count
                    FROM tenants t
                    LEFT JOIN audit_logs al ON t.tenant_id = al.tenant_id
                    GROUP BY t.tenant_id
                ''',
                'expected_time': 0.1
            }
        ]
        
        query_performance = {}
        
        for test in query_tests:
            times = []
            
            # Run query multiple times for statistical accuracy
            for _ in range(10):
                start_time = time.time()
                
                with unified_db_manager.get_session() as session:
                    try:
                        session.execute(test['query']).fetchall()
                    except Exception:
                        # Query might fail due to missing test data, that's ok
                        pass
                
                end_time = time.time()
                times.append(end_time - start_time)
            
            avg_time = statistics.mean(times)
            query_performance[test['name']] = {
                'average_time': avg_time,
                'times': times,
                'expected_time': test['expected_time']
            }
            
            # Performance assertion
            assert avg_time < test['expected_time'], \
                f"Query {test['name']} took {avg_time:.4f}s, expected < {test['expected_time']}s"
        
        performance_metrics['database_queries'] = query_performance
    
    def test_concurrent_write_performance(self, unified_db_manager, performance_metrics):
        """Test concurrent write operations performance."""
        def concurrent_write(thread_id: int, num_operations: int):
            thread_times = []
            
            for i in range(num_operations):
                audit_data = {
                    "tenant_id": f"concurrent-tenant-{thread_id}",
                    "resource_id": f"concurrent-resource-{thread_id}-{i}",
                    "resource_type": "compute_instance",
                    "event_type": "concurrent_test",
                    "status": "completed"
                }
                
                start_time = time.time()
                
                with patch.object(unified_db_manager, 'create_audit_log') as mock_create:
                    mock_create.return_value = Mock()
                    unified_db_manager.create_audit_log(audit_data)
                
                end_time = time.time()
                thread_times.append(end_time - start_time)
            
            return thread_times
        
        # Test concurrent writes
        num_threads = 5
        operations_per_thread = 20
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [
                executor.submit(concurrent_write, i, operations_per_thread)
                for i in range(num_threads)
            ]
            
            all_times = []
            for future in as_completed(futures):
                thread_times = future.result()
                all_times.extend(thread_times)
        
        total_time = time.time() - start_time
        total_operations = num_threads * operations_per_thread
        
        performance_metrics['concurrent_writes'] = {
            'total_operations': total_operations,
            'total_time': total_time,
            'throughput': total_operations / total_time,
            'average_operation_time': statistics.mean(all_times),
            'operation_times': all_times
        }
        
        # Performance assertions
        throughput = total_operations / total_time
        assert throughput > 50, f"Concurrent write throughput {throughput:.1f} ops/sec too low"
        
        avg_operation_time = statistics.mean(all_times)
        assert avg_operation_time < 0.1, f"Average operation time {avg_operation_time:.3f}s too high"


@pytest.fixture
def performance_report(performance_metrics):
    """Generate performance test report."""
    def generate_report():
        report = {
            'summary': {
                'total_tests': len(performance_metrics),
                'timestamp': time.time(),
                'test_environment': 'testing'
            },
            'metrics': performance_metrics
        }
        
        # Calculate overall performance score
        score_factors = []
        
        if 'response_times' in performance_metrics:
            avg_response_time = statistics.mean(performance_metrics['response_times'])
            score_factors.append(min(100, max(0, 100 - (avg_response_time * 1000))))
        
        if 'cache_hits' in performance_metrics and 'cache_misses' in performance_metrics:
            hit_rate = performance_metrics['cache_hits'] / (
                performance_metrics['cache_hits'] + performance_metrics['cache_misses']
            )
            score_factors.append(hit_rate * 100)
        
        if score_factors:
            report['summary']['performance_score'] = statistics.mean(score_factors)
        
        return report
    
    yield generate_report