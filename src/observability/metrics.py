#!/usr/bin/env python3
"""
Prometheus Metrics for AuditHound
Exposes business and technical metrics for monitoring and alerting
"""

import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, field
from collections import defaultdict, deque
from functools import wraps
import psutil
import os
from pathlib import Path

# Try to import prometheus_client, provide fallback if not available
try:
    from prometheus_client import (
        Counter, Gauge, Histogram, Summary, Info, Enum,
        CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST,
        start_http_server, push_to_gateway
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    
    # Mock classes for when prometheus_client is not available
    class Counter:
        def __init__(self, *args, **kwargs):
            self._value = 0
        def inc(self, amount=1):
            self._value += amount
        def _value(self):
            return self._value
    
    class Gauge:
        def __init__(self, *args, **kwargs):
            self._value = 0
        def set(self, value):
            self._value = value
        def inc(self, amount=1):
            self._value += amount
        def dec(self, amount=1):
            self._value -= amount
    
    class Histogram:
        def __init__(self, *args, **kwargs):
            pass
        def observe(self, value):
            pass
        def time(self):
            return self
        def __enter__(self):
            self.start_time = time.time()
            return self
        def __exit__(self, *args):
            pass
    
    class Summary:
        def __init__(self, *args, **kwargs):
            pass
        def observe(self, value):
            pass
        def time(self):
            return self
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
    
    class Info:
        def __init__(self, *args, **kwargs):
            pass
        def info(self, value):
            pass
    
    class Enum:
        def __init__(self, *args, **kwargs):
            pass
        def state(self, value):
            pass
    
    class CollectorRegistry:
        def __init__(self):
            pass
    
    def generate_latest(registry=None):
        return b"# Prometheus metrics not available\n"
    
    CONTENT_TYPE_LATEST = "text/plain; charset=utf-8"
    
    def start_http_server(port, addr='', registry=None):
        pass
    
    def push_to_gateway(gateway, job, registry, grouping_key=None):
        pass

from ..observability.logger import get_logger, LogCategory

logger = get_logger(__name__)

class MetricsCollector:
    """Centralized metrics collector for AuditHound"""
    
    def __init__(self, registry: Optional[CollectorRegistry] = None):
        self.registry = registry or CollectorRegistry()
        self._lock = threading.RLock()
        self._start_time = time.time()
        
        # Initialize all metrics
        self._init_system_metrics()
        self._init_business_metrics()
        self._init_performance_metrics()
        self._init_security_metrics()
        self._init_compliance_metrics()
        
        # Background metrics collection
        self._metrics_thread = None
        self._stop_metrics = threading.Event()
        
        logger.info("Metrics collector initialized", 
                   category=LogCategory.SYSTEM, event_type="metrics_init")
    
    def _init_system_metrics(self):
        """Initialize system-level metrics"""
        
        # Application info
        self.app_info = Info('audithound_app_info', 'AuditHound application information', 
                           registry=self.registry)
        self.app_info.info({
            'version': '1.0.0',
            'build_date': datetime.now().isoformat(),
            'python_version': f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}"
        })
        
        # System resource metrics
        self.cpu_usage = Gauge('audithound_cpu_usage_percent', 'CPU usage percentage', 
                              registry=self.registry)
        self.memory_usage = Gauge('audithound_memory_usage_bytes', 'Memory usage in bytes', 
                                 registry=self.registry)
        self.memory_usage_percent = Gauge('audithound_memory_usage_percent', 'Memory usage percentage', 
                                         registry=self.registry)
        self.disk_usage = Gauge('audithound_disk_usage_bytes', 'Disk usage in bytes', 
                               ['path'], registry=self.registry)
        
        # Process metrics
        self.process_start_time = Gauge('audithound_process_start_time_seconds', 
                                       'Process start time in seconds since epoch', 
                                       registry=self.registry)
        self.process_start_time.set(self._start_time)
        
        # HTTP metrics
        self.http_requests_total = Counter('audithound_http_requests_total', 
                                         'Total HTTP requests', 
                                         ['method', 'endpoint', 'status'], 
                                         registry=self.registry)
        self.http_request_duration = Histogram('audithound_http_request_duration_seconds',
                                             'HTTP request duration',
                                             ['method', 'endpoint'],
                                             registry=self.registry)
        
        # Database metrics
        self.db_connections_active = Gauge('audithound_db_connections_active', 
                                          'Active database connections',
                                          ['database'], registry=self.registry)
        self.db_operations_total = Counter('audithound_db_operations_total',
                                          'Total database operations',
                                          ['operation', 'table', 'status'],
                                          registry=self.registry)
        self.db_operation_duration = Histogram('audithound_db_operation_duration_seconds',
                                              'Database operation duration',
                                              ['operation', 'table'],
                                              registry=self.registry)
    
    def _init_business_metrics(self):
        """Initialize business-specific metrics"""
        
        # Client metrics
        self.clients_total = Gauge('audithound_clients_total', 'Total number of clients',
                                  registry=self.registry)
        self.clients_active = Gauge('audithound_clients_active', 'Number of active clients',
                                   registry=self.registry)
        self.clients_onboarded_total = Counter('audithound_clients_onboarded_total',
                                              'Total clients onboarded',
                                              registry=self.registry)
        
        # Onboarding metrics
        self.onboarding_duration = Histogram('audithound_onboarding_duration_seconds',
                                           'Client onboarding duration',
                                           ['client_type'], registry=self.registry)
        self.onboarding_steps_completed = Counter('audithound_onboarding_steps_completed_total',
                                                 'Onboarding steps completed',
                                                 ['step', 'status'], registry=self.registry)
        
        # Finding metrics
        self.findings_total = Counter('audithound_findings_total', 'Total findings discovered',
                                    ['severity', 'category', 'source'], registry=self.registry)
        self.findings_active = Gauge('audithound_findings_active', 'Currently active findings',
                                   ['severity', 'category'], registry=self.registry)
        self.findings_resolved_total = Counter('audithound_findings_resolved_total',
                                              'Total findings resolved',
                                              ['severity', 'category'], registry=self.registry)
        
        # User activity metrics
        self.user_sessions_active = Gauge('audithound_user_sessions_active', 
                                         'Active user sessions', registry=self.registry)
        self.user_actions_total = Counter('audithound_user_actions_total',
                                         'Total user actions',
                                         ['action', 'user_type'], registry=self.registry)
        
        # Dashboard metrics
        self.dashboard_views_total = Counter('audithound_dashboard_views_total',
                                           'Total dashboard views',
                                           ['dashboard', 'client'], registry=self.registry)
        self.dashboard_load_time = Histogram('audithound_dashboard_load_time_seconds',
                                           'Dashboard load time',
                                           ['dashboard'], registry=self.registry)
        
        # Theme build metrics (CSS compilation time)
        self.theme_build_duration = Histogram('audithound_theme_build_duration_seconds',
                                            'CSS theme build duration',
                                            ['theme', 'client'], registry=self.registry)
        self.theme_builds_total = Counter('audithound_theme_builds_total',
                                        'Total theme builds',
                                        ['theme', 'status'], registry=self.registry)
    
    def _init_performance_metrics(self):
        """Initialize performance metrics"""
        
        # Scan performance
        self.scan_duration = Histogram('audithound_scan_duration_seconds',
                                     'Security scan duration',
                                     ['scan_type', 'target'], registry=self.registry)
        self.scan_items_processed = Counter('audithound_scan_items_processed_total',
                                          'Items processed during scans',
                                          ['scan_type'], registry=self.registry)
        
        # Vector database metrics
        self.vector_operations_total = Counter('audithound_vector_operations_total',
                                             'Vector database operations',
                                             ['operation', 'collection'], registry=self.registry)
        self.vector_operation_duration = Histogram('audithound_vector_operation_duration_seconds',
                                                  'Vector operation duration',
                                                  ['operation'], registry=self.registry)
        self.vector_embeddings_total = Gauge('audithound_vector_embeddings_total',
                                           'Total vector embeddings stored',
                                           ['collection'], registry=self.registry)
        
        # Cache metrics
        self.cache_hits_total = Counter('audithound_cache_hits_total', 'Cache hits',
                                      ['cache_type'], registry=self.registry)
        self.cache_misses_total = Counter('audithound_cache_misses_total', 'Cache misses',
                                        ['cache_type'], registry=self.registry)
        self.cache_size = Gauge('audithound_cache_size_bytes', 'Cache size in bytes',
                              ['cache_type'], registry=self.registry)
        
        # Background job metrics
        self.background_jobs_active = Gauge('audithound_background_jobs_active',
                                          'Active background jobs', ['job_type'], 
                                          registry=self.registry)
        self.background_job_duration = Histogram('audithound_background_job_duration_seconds',
                                                'Background job duration',
                                                ['job_type'], registry=self.registry)
    
    def _init_security_metrics(self):
        """Initialize security-related metrics"""
        
        # Authentication metrics
        self.auth_attempts_total = Counter('audithound_auth_attempts_total',
                                         'Authentication attempts',
                                         ['method', 'status'], registry=self.registry)
        self.auth_failures_total = Counter('audithound_auth_failures_total',
                                          'Authentication failures',
                                          ['method', 'reason'], registry=self.registry)
        
        # Security events
        self.security_events_total = Counter('audithound_security_events_total',
                                           'Security events',
                                           ['event_type', 'severity'], registry=self.registry)
        self.security_alerts_active = Gauge('audithound_security_alerts_active',
                                          'Active security alerts',
                                          ['severity'], registry=self.registry)
        
        # Access control
        self.access_denied_total = Counter('audithound_access_denied_total',
                                         'Access denied events',
                                         ['resource', 'reason'], registry=self.registry)
        self.permissions_checked_total = Counter('audithound_permissions_checked_total',
                                               'Permission checks performed',
                                               ['resource', 'result'], registry=self.registry)
        
        # Encryption metrics
        self.encryption_operations_total = Counter('audithound_encryption_operations_total',
                                                 'Encryption operations',
                                                 ['operation', 'algorithm'], registry=self.registry)
        self.encrypted_data_size_bytes = Counter('audithound_encrypted_data_size_bytes_total',
                                               'Total encrypted data size',
                                               ['data_type'], registry=self.registry)
    
    def _init_compliance_metrics(self):
        """Initialize compliance metrics"""
        
        # Compliance framework metrics
        self.compliance_checks_total = Counter('audithound_compliance_checks_total',
                                             'Compliance checks performed',
                                             ['framework', 'control', 'status'], 
                                             registry=self.registry)
        self.compliance_score = Gauge('audithound_compliance_score',
                                    'Compliance score percentage',
                                    ['framework', 'client'], registry=self.registry)
        
        # Control metrics
        self.controls_implemented = Gauge('audithound_controls_implemented',
                                        'Number of implemented controls',
                                        ['framework'], registry=self.registry)
        self.controls_failed = Gauge('audithound_controls_failed',
                                   'Number of failed controls',
                                   ['framework'], registry=self.registry)
        
        # Audit metrics
        self.audit_events_total = Counter('audithound_audit_events_total',
                                        'Audit events logged',
                                        ['event_type', 'category'], registry=self.registry)
        self.audit_trail_size_bytes = Gauge('audithound_audit_trail_size_bytes',
                                          'Audit trail size in bytes',
                                          registry=self.registry)
        
        # Data protection metrics
        self.gdpr_requests_total = Counter('audithound_gdpr_requests_total',
                                         'GDPR data subject requests',
                                         ['request_type', 'status'], registry=self.registry)
        self.data_retention_actions_total = Counter('audithound_data_retention_actions_total',
                                                   'Data retention actions',
                                                   ['action'], registry=self.registry)
    
    def start_background_collection(self, interval: int = 30):
        """Start background metrics collection"""
        if self._metrics_thread and self._metrics_thread.is_alive():
            return
        
        self._stop_metrics.clear()
        self._metrics_thread = threading.Thread(
            target=self._collect_system_metrics_loop,
            args=(interval,),
            daemon=True
        )
        self._metrics_thread.start()
        
        logger.info("Started background metrics collection", 
                   category=LogCategory.SYSTEM, event_type="metrics_started",
                   data={"interval_seconds": interval})
    
    def stop_background_collection(self):
        """Stop background metrics collection"""
        if self._metrics_thread:
            self._stop_metrics.set()
            self._metrics_thread.join(timeout=5)
            
        logger.info("Stopped background metrics collection",
                   category=LogCategory.SYSTEM, event_type="metrics_stopped")
    
    def _collect_system_metrics_loop(self, interval: int):
        """Background loop for collecting system metrics"""
        while not self._stop_metrics.wait(interval):
            try:
                self._collect_system_metrics()
            except Exception as e:
                logger.error(f"Error collecting system metrics: {e}",
                           category=LogCategory.SYSTEM, event_type="metrics_error",
                           data={"error": str(e)})
    
    def _collect_system_metrics(self):
        """Collect current system metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.cpu_usage.set(cpu_percent)
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.memory_usage.set(memory.used)
            self.memory_usage_percent.set(memory.percent)
            
            # Disk usage for key paths
            for path in ['/', '/tmp', 'logs']:
                try:
                    if os.path.exists(path):
                        disk = psutil.disk_usage(path)
                        self.disk_usage.labels(path=path).set(disk.used)
                except (OSError, PermissionError):
                    pass
                    
        except Exception as e:
            logger.warning(f"Failed to collect some system metrics: {e}",
                         category=LogCategory.SYSTEM)
    
    # Convenience methods for common metrics patterns
    
    def record_http_request(self, method: str, endpoint: str, status_code: int, duration: float):
        """Record HTTP request metrics"""
        self.http_requests_total.labels(method=method, endpoint=endpoint, status=str(status_code)).inc()
        self.http_request_duration.labels(method=method, endpoint=endpoint).observe(duration)
    
    def record_client_onboarded(self, client_type: str = "standard", duration: float = 0):
        """Record client onboarding"""
        self.clients_onboarded_total.inc()
        if duration > 0:
            self.onboarding_duration.labels(client_type=client_type).observe(duration)
    
    def record_finding(self, severity: str, category: str, source: str):
        """Record new finding"""
        self.findings_total.labels(severity=severity, category=category, source=source).inc()
        self.findings_active.labels(severity=severity, category=category).inc()
    
    def record_finding_resolved(self, severity: str, category: str):
        """Record finding resolution"""
        self.findings_resolved_total.labels(severity=severity, category=category).inc()
        self.findings_active.labels(severity=severity, category=category).dec()
    
    def record_theme_build(self, theme: str, client: str, duration: float, success: bool):
        """Record CSS theme build"""
        status = "success" if success else "failure"
        self.theme_builds_total.labels(theme=theme, status=status).inc()
        if success:
            self.theme_build_duration.labels(theme=theme, client=client).observe(duration)
    
    def record_scan(self, scan_type: str, target: str, duration: float, items_processed: int):
        """Record security scan"""
        self.scan_duration.labels(scan_type=scan_type, target=target).observe(duration)
        self.scan_items_processed.labels(scan_type=scan_type).inc(items_processed)
    
    def record_vector_operation(self, operation: str, collection: str, duration: float):
        """Record vector database operation"""
        self.vector_operations_total.labels(operation=operation, collection=collection).inc()
        self.vector_operation_duration.labels(operation=operation).observe(duration)
    
    def record_auth_attempt(self, method: str, success: bool, failure_reason: str = ""):
        """Record authentication attempt"""
        status = "success" if success else "failure"
        self.auth_attempts_total.labels(method=method, status=status).inc()
        if not success and failure_reason:
            self.auth_failures_total.labels(method=method, reason=failure_reason).inc()
    
    def record_compliance_check(self, framework: str, control: str, status: str, score: float = None):
        """Record compliance check"""
        self.compliance_checks_total.labels(framework=framework, control=control, status=status).inc()
        if score is not None:
            # For client-specific scores, we'd need client_id parameter
            self.compliance_score.labels(framework=framework, client="default").set(score)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get current metrics summary"""
        try:
            return {
                'timestamp': datetime.now().isoformat(),
                'uptime_seconds': time.time() - self._start_time,
                'system': {
                    'cpu_percent': psutil.cpu_percent(),
                    'memory_percent': psutil.virtual_memory().percent,
                    'disk_usage_gb': psutil.disk_usage('/').used / (1024**3)
                },
                'clients': {
                    'total': getattr(self.clients_total, '_value', 0),
                    'active': getattr(self.clients_active, '_value', 0)
                },
                'prometheus_available': PROMETHEUS_AVAILABLE
            }
        except Exception as e:
            logger.error(f"Error generating metrics summary: {e}")
            return {'error': str(e)}

# Timing decorator
def timed_metric(metric: Union[Histogram, Summary], labels: Dict[str, str] = None):
    """Decorator to time function execution and record in metric"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                if labels:
                    metric.labels(**labels).observe(duration)
                else:
                    metric.observe(duration)
                return result
            except Exception as e:
                duration = time.time() - start_time
                # Still record the duration even if function failed
                if labels:
                    error_labels = labels.copy()
                    error_labels['status'] = 'error'
                    metric.labels(**error_labels).observe(duration)
                else:
                    metric.observe(duration)
                raise
        return wrapper
    return decorator

# Global metrics collector instance
_metrics_collector: Optional[MetricsCollector] = None
_metrics_lock = threading.Lock()

def get_metrics_collector() -> MetricsCollector:
    """Get global metrics collector instance"""
    global _metrics_collector
    with _metrics_lock:
        if _metrics_collector is None:
            _metrics_collector = MetricsCollector()
            _metrics_collector.start_background_collection()
        return _metrics_collector

# Registry for easy access
metrics_registry = get_metrics_collector()

# HTTP endpoint for metrics
def metrics_endpoint():
    """Get metrics in Prometheus format"""
    collector = get_metrics_collector()
    return generate_latest(collector.registry)

def start_metrics_server(port: int = 8080, addr: str = '0.0.0.0'):
    """Start Prometheus metrics HTTP server"""
    if not PROMETHEUS_AVAILABLE:
        logger.warning("Prometheus client not available, metrics server not started")
        return
    
    collector = get_metrics_collector()
    start_http_server(port, addr, collector.registry)
    logger.info(f"Prometheus metrics server started on {addr}:{port}",
               category=LogCategory.SYSTEM, event_type="metrics_server_started",
               data={"addr": addr, "port": port})

# Example usage and testing
if __name__ == "__main__":
    # Initialize metrics
    collector = get_metrics_collector()
    
    # Test various metrics
    collector.record_client_onboarded("enterprise", 45.2)
    collector.record_finding("high", "security", "vulnerability_scan")
    collector.record_http_request("GET", "/api/clients", 200, 0.245)
    collector.record_theme_build("dark", "client-123", 2.1, True)
    collector.record_scan("vulnerability", "aws-account-123", 125.5, 450)
    collector.record_auth_attempt("oauth", True)
    collector.record_compliance_check("SOC2", "CC6.1", "pass", 85.5)
    
    # Get metrics summary
    summary = collector.get_metrics_summary()
    print("Metrics Summary:", summary)
    
    # Output metrics in Prometheus format
    print("\nPrometheus Metrics:")
    print(metrics_endpoint().decode('utf-8'))
    
    # Stop background collection
    collector.stop_background_collection()