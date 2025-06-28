# Database query optimization module
import time
import logging
from typing import Dict, List, Any, Optional, Tuple
from sqlalchemy import text, event, Index
from sqlalchemy.orm import Session
from sqlalchemy.engine import Engine
from contextlib import contextmanager
import functools
from collections import defaultdict
import threading

logger = logging.getLogger(__name__)


class QueryOptimizer:
    """Database query optimization and monitoring."""
    
    def __init__(self):
        self.query_stats = defaultdict(list)
        self.slow_query_threshold = 0.1  # 100ms
        self.query_cache = {}
        self.cache_hits = 0
        self.cache_misses = 0
        self._lock = threading.Lock()
    
    def setup_query_monitoring(self, engine: Engine):
        """Set up query monitoring for performance tracking."""
        
        @event.listens_for(engine, "before_cursor_execute")
        def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            context._query_start_time = time.time()
            context._query_statement = statement
        
        @event.listens_for(engine, "after_cursor_execute")
        def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            total_time = time.time() - context._query_start_time
            
            with self._lock:
                self.query_stats[statement].append({
                    'execution_time': total_time,
                    'timestamp': time.time(),
                    'parameters': str(parameters)[:200] if parameters else None
                })
            
            if total_time > self.slow_query_threshold:
                logger.warning(
                    f"Slow query detected: {total_time:.3f}s - {statement[:200]}..."
                )
    
    def create_optimized_indexes(self, session: Session):
        """Create database indexes for optimal query performance."""
        
        # Define indexes for common query patterns
        indexes = [
            # Tenant-based queries
            Index('idx_audit_logs_tenant_timestamp', 
                  'audit_logs.tenant_id', 'audit_logs.timestamp'),
            Index('idx_compliance_results_tenant_framework', 
                  'compliance_results.tenant_id', 'compliance_results.framework'),
            Index('idx_users_tenant_email', 
                  'users.tenant_id', 'users.email'),
            
            # Resource-based queries
            Index('idx_audit_logs_resource_type', 
                  'audit_logs.resource_id', 'audit_logs.resource_type'),
            Index('idx_compliance_results_resource_control', 
                  'compliance_results.resource_id', 'compliance_results.control_id'),
            
            # Status and filtering queries
            Index('idx_audit_logs_status_severity', 
                  'audit_logs.status', 'audit_logs.severity'),
            Index('idx_tenants_status_plan', 
                  'tenants.status', 'tenants.subscription_plan'),
            
            # Composite indexes for complex queries
            Index('idx_audit_logs_composite', 
                  'audit_logs.tenant_id', 'audit_logs.timestamp', 'audit_logs.status'),
            Index('idx_compliance_composite', 
                  'compliance_results.tenant_id', 'compliance_results.framework', 
                  'compliance_results.status', 'compliance_results.score')
        ]
        
        try:
            # Create indexes if they don't exist
            for index in indexes:
                try:
                    index.create(session.bind, checkfirst=True)
                    logger.info(f"Created index: {index.name}")
                except Exception as e:
                    logger.warning(f"Failed to create index {index.name}: {e}")
            
            session.commit()
            logger.info("Database optimization indexes created successfully")
            
        except Exception as e:
            logger.error(f"Failed to create optimization indexes: {e}")
            session.rollback()
    
    def optimize_tenant_queries(self, session: Session):
        """Optimize common tenant-related queries."""
        
        # Analyze and optimize tenant statistics query
        optimized_tenant_stats_query = text("""
            WITH tenant_stats AS (
                SELECT 
                    t.tenant_id,
                    t.name,
                    t.status,
                    COUNT(DISTINCT al.id) as audit_logs_count,
                    COUNT(DISTINCT cr.id) as compliance_results_count,
                    COUNT(DISTINCT u.id) as users_count,
                    AVG(cr.score) as avg_compliance_score,
                    MAX(al.timestamp) as last_audit_timestamp
                FROM tenants t
                LEFT JOIN audit_logs al ON t.tenant_id = al.tenant_id
                LEFT JOIN compliance_results cr ON t.tenant_id = cr.tenant_id
                LEFT JOIN users u ON t.tenant_id = u.tenant_id
                WHERE t.status = 'active'
                GROUP BY t.tenant_id, t.name, t.status
            )
            SELECT * FROM tenant_stats
            ORDER BY last_audit_timestamp DESC NULLS LAST
        """)
        
        # Cache this query result for 5 minutes
        cache_key = "tenant_stats_active"
        cached_result = self.get_cached_query_result(cache_key)
        
        if cached_result is not None:
            self.cache_hits += 1
            return cached_result
        
        try:
            start_time = time.time()
            result = session.execute(optimized_tenant_stats_query).fetchall()
            execution_time = time.time() - start_time
            
            # Cache the result
            self.cache_query_result(cache_key, result, ttl=300)  # 5 minutes
            self.cache_misses += 1
            
            logger.info(f"Optimized tenant stats query executed in {execution_time:.3f}s")
            return result
            
        except Exception as e:
            logger.error(f"Failed to execute optimized tenant stats query: {e}")
            return []
    
    def optimize_compliance_dashboard_query(self, session: Session, tenant_id: str):
        """Optimize compliance dashboard data retrieval."""
        
        cache_key = f"compliance_dashboard_{tenant_id}"
        cached_result = self.get_cached_query_result(cache_key)
        
        if cached_result is not None:
            self.cache_hits += 1
            return cached_result
        
        # Optimized query for compliance dashboard
        optimized_query = text("""
            WITH framework_stats AS (
                SELECT 
                    framework,
                    COUNT(*) as total_controls,
                    COUNT(CASE WHEN status = 'COMPLIANT' THEN 1 END) as compliant_controls,
                    COUNT(CASE WHEN status = 'NON_COMPLIANT' THEN 1 END) as non_compliant_controls,
                    AVG(score) as avg_score,
                    MAX(updated_at) as last_assessment
                FROM compliance_results
                WHERE tenant_id = :tenant_id
                GROUP BY framework
            ),
            severity_breakdown AS (
                SELECT 
                    framework,
                    severity,
                    COUNT(*) as count
                FROM compliance_results cr
                JOIN audit_logs al ON cr.resource_id = al.resource_id 
                    AND cr.tenant_id = al.tenant_id
                WHERE cr.tenant_id = :tenant_id
                GROUP BY framework, severity
            ),
            recent_failures AS (
                SELECT 
                    framework,
                    control_id,
                    resource_id,
                    score,
                    updated_at
                FROM compliance_results
                WHERE tenant_id = :tenant_id 
                    AND status = 'NON_COMPLIANT'
                ORDER BY updated_at DESC
                LIMIT 10
            )
            SELECT 
                fs.*,
                COALESCE(sb.severity_data, '{}') as severity_breakdown,
                COALESCE(rf.recent_failures, '[]') as recent_failures
            FROM framework_stats fs
            LEFT JOIN (
                SELECT 
                    framework,
                    json_object_agg(severity, count) as severity_data
                FROM severity_breakdown
                GROUP BY framework
            ) sb ON fs.framework = sb.framework
            LEFT JOIN (
                SELECT 
                    framework,
                    json_agg(json_build_object(
                        'control_id', control_id,
                        'resource_id', resource_id,
                        'score', score,
                        'updated_at', updated_at
                    )) as recent_failures
                FROM recent_failures
                GROUP BY framework
            ) rf ON fs.framework = rf.framework
            ORDER BY fs.avg_score ASC
        """)
        
        try:
            start_time = time.time()
            result = session.execute(optimized_query, {"tenant_id": tenant_id}).fetchall()
            execution_time = time.time() - start_time
            
            # Process and structure the result
            dashboard_data = {
                'compliance_summary': {
                    'total_frameworks': len(result),
                    'overall_score': sum(row.avg_score for row in result) / len(result) if result else 0,
                    'last_updated': max(row.last_assessment for row in result) if result else None
                },
                'frameworks': []
            }
            
            for row in result:
                framework_data = {
                    'name': row.framework,
                    'total_controls': row.total_controls,
                    'compliant_controls': row.compliant_controls,
                    'non_compliant_controls': row.non_compliant_controls,
                    'compliance_percentage': (row.compliant_controls / row.total_controls * 100) if row.total_controls > 0 else 0,
                    'avg_score': row.avg_score,
                    'last_assessment': row.last_assessment,
                    'severity_breakdown': row.severity_breakdown or {},
                    'recent_failures': row.recent_failures or []
                }
                dashboard_data['frameworks'].append(framework_data)
            
            # Cache the result
            self.cache_query_result(cache_key, dashboard_data, ttl=600)  # 10 minutes
            self.cache_misses += 1
            
            logger.info(f"Optimized compliance dashboard query executed in {execution_time:.3f}s")
            return dashboard_data
            
        except Exception as e:
            logger.error(f"Failed to execute optimized compliance dashboard query: {e}")
            return {'compliance_summary': {}, 'frameworks': []}
    
    def optimize_audit_log_queries(self, session: Session, tenant_id: str, 
                                 start_date: Optional[str] = None, 
                                 end_date: Optional[str] = None,
                                 limit: int = 100):
        """Optimize audit log retrieval queries."""
        
        # Build cache key based on parameters
        cache_key = f"audit_logs_{tenant_id}_{start_date}_{end_date}_{limit}"
        cached_result = self.get_cached_query_result(cache_key)
        
        if cached_result is not None:
            self.cache_hits += 1
            return cached_result
        
        # Build optimized query with conditional date filtering
        query_parts = [
            "SELECT al.*, COUNT(*) OVER() as total_count",
            "FROM audit_logs al",
            "WHERE al.tenant_id = :tenant_id"
        ]
        
        params = {"tenant_id": tenant_id}
        
        if start_date:
            query_parts.append("AND al.timestamp >= :start_date")
            params["start_date"] = start_date
        
        if end_date:
            query_parts.append("AND al.timestamp <= :end_date")
            params["end_date"] = end_date
        
        query_parts.extend([
            "ORDER BY al.timestamp DESC",
            f"LIMIT {limit}"
        ])
        
        optimized_query = text(" ".join(query_parts))
        
        try:
            start_time = time.time()
            result = session.execute(optimized_query, params).fetchall()
            execution_time = time.time() - start_time
            
            # Cache the result for 2 minutes (audit logs change frequently)
            self.cache_query_result(cache_key, result, ttl=120)
            self.cache_misses += 1
            
            logger.info(f"Optimized audit log query executed in {execution_time:.3f}s")
            return result
            
        except Exception as e:
            logger.error(f"Failed to execute optimized audit log query: {e}")
            return []
    
    def get_cached_query_result(self, cache_key: str):
        """Get cached query result if valid."""
        with self._lock:
            if cache_key in self.query_cache:
                cache_entry = self.query_cache[cache_key]
                if time.time() < cache_entry['expires_at']:
                    return cache_entry['result']
                else:
                    # Remove expired entry
                    del self.query_cache[cache_key]
        return None
    
    def cache_query_result(self, cache_key: str, result: Any, ttl: int = 300):
        """Cache query result with TTL."""
        with self._lock:
            self.query_cache[cache_key] = {
                'result': result,
                'expires_at': time.time() + ttl,
                'cached_at': time.time()
            }
    
    def clear_cache(self, pattern: Optional[str] = None):
        """Clear query cache, optionally matching a pattern."""
        with self._lock:
            if pattern:
                keys_to_remove = [key for key in self.query_cache.keys() if pattern in key]
                for key in keys_to_remove:
                    del self.query_cache[key]
            else:
                self.query_cache.clear()
    
    def get_query_statistics(self) -> Dict[str, Any]:
        """Get query performance statistics."""
        with self._lock:
            stats = {
                'total_queries': sum(len(query_list) for query_list in self.query_stats.values()),
                'unique_queries': len(self.query_stats),
                'cache_hits': self.cache_hits,
                'cache_misses': self.cache_misses,
                'cache_hit_ratio': self.cache_hits / (self.cache_hits + self.cache_misses) if (self.cache_hits + self.cache_misses) > 0 else 0,
                'slow_queries': [],
                'average_execution_times': {}
            }
            
            # Analyze slow queries
            for query, executions in self.query_stats.items():
                execution_times = [exec['execution_time'] for exec in executions]
                avg_time = sum(execution_times) / len(execution_times)
                
                stats['average_execution_times'][query[:100]] = avg_time
                
                if avg_time > self.slow_query_threshold:
                    stats['slow_queries'].append({
                        'query': query[:200],
                        'average_time': avg_time,
                        'execution_count': len(executions),
                        'slowest_execution': max(execution_times)
                    })
            
            return stats
    
    def optimize_database_connection_pool(self, engine: Engine):
        """Optimize database connection pool settings."""
        pool = engine.pool
        
        # Log current pool statistics
        logger.info(f"Connection pool status - Size: {pool.size()}, "
                   f"Checked in: {pool.checkedin()}, "
                   f"Checked out: {pool.checkedout()}")
        
        # Recommendations for pool optimization
        recommendations = []
        
        if pool.checkedout() / pool.size() > 0.8:
            recommendations.append("Consider increasing pool size - high utilization detected")
        
        if pool.checkedin() / pool.size() < 0.2:
            recommendations.append("Consider decreasing pool size - low utilization detected")
        
        return {
            'current_status': {
                'pool_size': pool.size(),
                'checked_in': pool.checkedin(),
                'checked_out': pool.checkedout(),
                'utilization': pool.checkedout() / pool.size()
            },
            'recommendations': recommendations
        }


def query_performance_decorator(cache_ttl: int = 300):
    """Decorator to add query performance monitoring and caching."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key from function name and arguments
            cache_key = f"{func.__name__}_{hash(str(args) + str(kwargs))}"
            
            # Try to get from cache first
            if hasattr(wrapper, '_query_optimizer'):
                cached_result = wrapper._query_optimizer.get_cached_query_result(cache_key)
                if cached_result is not None:
                    return cached_result
            
            # Execute function and measure time
            start_time = time.time()
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            
            # Cache the result if query optimizer is available
            if hasattr(wrapper, '_query_optimizer'):
                wrapper._query_optimizer.cache_query_result(cache_key, result, cache_ttl)
            
            # Log slow queries
            if execution_time > 0.1:  # 100ms threshold
                logger.warning(f"Slow query in {func.__name__}: {execution_time:.3f}s")
            
            return result
        
        return wrapper
    return decorator


# Global query optimizer instance
query_optimizer = QueryOptimizer()