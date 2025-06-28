#!/usr/bin/env python3
"""
Health and Readiness Probes for AuditHound
Provides Kubernetes-compatible health checks for container orchestration
"""

import time
import asyncio
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, asdict
from enum import Enum
import psutil
import os
from pathlib import Path

# Try to import aiohttp for async HTTP server, fallback to basic implementation
try:
    from aiohttp import web, ClientSession
    from aiohttp.web import Request, Response
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    
    # Mock classes for when aiohttp is not available
    class Request:
        pass
    
    class Response:
        def __init__(self, **kwargs):
            pass

from ..observability.logger import get_logger, LogCategory
from ..observability.metrics import get_metrics_collector

logger = get_logger(__name__)

class HealthStatus(Enum):
    """Health check status enumeration"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"

class ComponentType(Enum):
    """Component types for health checks"""
    DATABASE = "database"
    CACHE = "cache"
    EXTERNAL_API = "external_api"
    FILE_SYSTEM = "file_system"
    MEMORY = "memory"
    CPU = "cpu"
    DISK = "disk"
    NETWORK = "network"
    SERVICE = "service"

@dataclass
class HealthCheckResult:
    """Result of a health check"""
    component: str
    component_type: ComponentType
    status: HealthStatus
    message: str
    timestamp: datetime
    duration_ms: float
    details: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = asdict(self)
        result['status'] = self.status.value
        result['component_type'] = self.component_type.value
        result['timestamp'] = self.timestamp.isoformat()
        return result

@dataclass
class HealthSummary:
    """Overall health summary"""
    status: HealthStatus
    timestamp: datetime
    uptime_seconds: float
    total_checks: int
    healthy_checks: int
    degraded_checks: int
    unhealthy_checks: int
    checks: List[HealthCheckResult]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'status': self.status.value,
            'timestamp': self.timestamp.isoformat(),
            'uptime_seconds': self.uptime_seconds,
            'total_checks': self.total_checks,
            'healthy_checks': self.healthy_checks,
            'degraded_checks': self.degraded_checks,
            'unhealthy_checks': self.unhealthy_checks,
            'checks': [check.to_dict() for check in self.checks]
        }

class HealthCheck:
    """Individual health check definition"""
    
    def __init__(self, name: str, component_type: ComponentType, 
                 check_func: Callable[[], Any], 
                 timeout_seconds: float = 5.0,
                 critical: bool = True):
        self.name = name
        self.component_type = component_type
        self.check_func = check_func
        self.timeout_seconds = timeout_seconds
        self.critical = critical
        self.last_result: Optional[HealthCheckResult] = None
        self.failure_count = 0
        self.last_success = datetime.now()
    
    async def execute(self) -> HealthCheckResult:
        """Execute the health check"""
        start_time = time.time()
        
        try:
            # Execute the check with timeout
            if asyncio.iscoroutinefunction(self.check_func):
                result = await asyncio.wait_for(
                    self.check_func(), 
                    timeout=self.timeout_seconds
                )
            else:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, self.check_func
                )
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Determine status based on result
            if result is True:
                status = HealthStatus.HEALTHY
                message = f"{self.name} is healthy"
                self.failure_count = 0
                self.last_success = datetime.now()
            elif isinstance(result, dict):
                status = HealthStatus(result.get('status', 'healthy'))
                message = result.get('message', f"{self.name} check completed")
                if status == HealthStatus.HEALTHY:
                    self.failure_count = 0
                    self.last_success = datetime.now()
                else:
                    self.failure_count += 1
            else:
                status = HealthStatus.DEGRADED
                message = f"{self.name} returned unexpected result: {result}"
                self.failure_count += 1
            
            self.last_result = HealthCheckResult(
                component=self.name,
                component_type=self.component_type,
                status=status,
                message=message,
                timestamp=datetime.now(),
                duration_ms=duration_ms,
                details=result if isinstance(result, dict) else None
            )
            
        except asyncio.TimeoutError:
            duration_ms = self.timeout_seconds * 1000
            self.failure_count += 1
            self.last_result = HealthCheckResult(
                component=self.name,
                component_type=self.component_type,
                status=HealthStatus.UNHEALTHY,
                message=f"{self.name} check timed out after {self.timeout_seconds}s",
                timestamp=datetime.now(),
                duration_ms=duration_ms
            )
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            self.failure_count += 1
            self.last_result = HealthCheckResult(
                component=self.name,
                component_type=self.component_type,
                status=HealthStatus.UNHEALTHY,
                message=f"{self.name} check failed: {str(e)}",
                timestamp=datetime.now(),
                duration_ms=duration_ms,
                details={'error': str(e), 'error_type': type(e).__name__}
            )
        
        return self.last_result

class HealthChecker:
    """Main health checker for AuditHound"""
    
    def __init__(self):
        self.checks: Dict[str, HealthCheck] = {}
        self.start_time = time.time()
        self._lock = asyncio.Lock()
        
        # Register default system checks
        self._register_default_checks()
        
        logger.info("Health checker initialized", 
                   category=LogCategory.SYSTEM, event_type="health_init")
    
    def _register_default_checks(self):
        """Register default system health checks"""
        
        # CPU usage check
        self.register_check(
            "cpu_usage",
            ComponentType.CPU,
            self._check_cpu_usage,
            timeout_seconds=2.0,
            critical=False
        )
        
        # Memory usage check
        self.register_check(
            "memory_usage",
            ComponentType.MEMORY,
            self._check_memory_usage,
            timeout_seconds=2.0,
            critical=True
        )
        
        # Disk space check
        self.register_check(
            "disk_space",
            ComponentType.DISK,
            self._check_disk_space,
            timeout_seconds=3.0,
            critical=True
        )
        
        # Log directory check
        self.register_check(
            "log_directory",
            ComponentType.FILE_SYSTEM,
            self._check_log_directory,
            timeout_seconds=2.0,
            critical=False
        )
        
        # Database connectivity (Weaviate)
        self.register_check(
            "weaviate_connection",
            ComponentType.DATABASE,
            self._check_weaviate_connection,
            timeout_seconds=10.0,
            critical=True
        )
    
    def register_check(self, name: str, component_type: ComponentType,
                      check_func: Callable, timeout_seconds: float = 5.0,
                      critical: bool = True):
        """Register a new health check"""
        self.checks[name] = HealthCheck(
            name, component_type, check_func, timeout_seconds, critical
        )
        logger.debug(f"Registered health check: {name}",
                    category=LogCategory.SYSTEM, event_type="health_check_registered")
    
    def unregister_check(self, name: str):
        """Unregister a health check"""
        if name in self.checks:
            del self.checks[name]
            logger.debug(f"Unregistered health check: {name}",
                        category=LogCategory.SYSTEM, event_type="health_check_unregistered")
    
    async def check_health(self, check_names: Optional[List[str]] = None) -> HealthSummary:
        """Perform health checks and return summary"""
        checks_to_run = check_names or list(self.checks.keys())
        
        async with self._lock:
            # Execute all checks concurrently
            tasks = []
            for name in checks_to_run:
                if name in self.checks:
                    tasks.append(self.checks[name].execute())
            
            if not tasks:
                return HealthSummary(
                    status=HealthStatus.UNKNOWN,
                    timestamp=datetime.now(),
                    uptime_seconds=time.time() - self.start_time,
                    total_checks=0,
                    healthy_checks=0,
                    degraded_checks=0,
                    unhealthy_checks=0,
                    checks=[]
                )
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions and convert to HealthCheckResult
            check_results = []
            for result in results:
                if isinstance(result, HealthCheckResult):
                    check_results.append(result)
                elif isinstance(result, Exception):
                    # Create error result
                    check_results.append(HealthCheckResult(
                        component="unknown",
                        component_type=ComponentType.SERVICE,
                        status=HealthStatus.UNHEALTHY,
                        message=f"Health check exception: {str(result)}",
                        timestamp=datetime.now(),
                        duration_ms=0.0,
                        details={'error': str(result)}
                    ))
        
        # Calculate summary statistics
        total_checks = len(check_results)
        healthy_checks = sum(1 for r in check_results if r.status == HealthStatus.HEALTHY)
        degraded_checks = sum(1 for r in check_results if r.status == HealthStatus.DEGRADED)
        unhealthy_checks = sum(1 for r in check_results if r.status == HealthStatus.UNHEALTHY)
        
        # Determine overall status
        critical_checks = [
            r for r in check_results 
            if r.component in self.checks and self.checks[r.component].critical
        ]
        
        if any(r.status == HealthStatus.UNHEALTHY for r in critical_checks):
            overall_status = HealthStatus.UNHEALTHY
        elif any(r.status == HealthStatus.DEGRADED for r in critical_checks):
            overall_status = HealthStatus.DEGRADED
        elif unhealthy_checks > 0 or degraded_checks > 0:
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.HEALTHY
        
        summary = HealthSummary(
            status=overall_status,
            timestamp=datetime.now(),
            uptime_seconds=time.time() - self.start_time,
            total_checks=total_checks,
            healthy_checks=healthy_checks,
            degraded_checks=degraded_checks,
            unhealthy_checks=unhealthy_checks,
            checks=check_results
        )
        
        # Record metrics
        try:
            metrics = get_metrics_collector()
            # Record overall health status as enum metric
            if hasattr(metrics, 'app_health_status'):
                metrics.app_health_status.state(overall_status.value)
        except Exception:
            pass  # Don't fail health check if metrics recording fails
        
        return summary
    
    async def check_readiness(self) -> HealthSummary:
        """Check if application is ready to serve traffic"""
        # For readiness, we only check critical components
        critical_checks = [
            name for name, check in self.checks.items() 
            if check.critical
        ]
        return await self.check_health(critical_checks)
    
    async def check_liveness(self) -> HealthSummary:
        """Check if application is alive (basic health)"""
        # For liveness, we only check if the process is responsive
        basic_checks = ["memory_usage", "disk_space"]
        return await self.check_health(basic_checks)
    
    # Default health check implementations
    
    def _check_cpu_usage(self) -> Dict[str, Any]:
        """Check CPU usage"""
        cpu_percent = psutil.cpu_percent(interval=1)
        
        if cpu_percent < 80:
            status = "healthy"
        elif cpu_percent < 95:
            status = "degraded"
        else:
            status = "unhealthy"
        
        return {
            'status': status,
            'message': f"CPU usage: {cpu_percent:.1f}%",
            'cpu_percent': cpu_percent,
            'threshold_warning': 80,
            'threshold_critical': 95
        }
    
    def _check_memory_usage(self) -> Dict[str, Any]:
        """Check memory usage"""
        memory = psutil.virtual_memory()
        
        if memory.percent < 85:
            status = "healthy"
        elif memory.percent < 95:
            status = "degraded"
        else:
            status = "unhealthy"
        
        return {
            'status': status,
            'message': f"Memory usage: {memory.percent:.1f}%",
            'memory_percent': memory.percent,
            'memory_available_gb': memory.available / (1024**3),
            'threshold_warning': 85,
            'threshold_critical': 95
        }
    
    def _check_disk_space(self) -> Dict[str, Any]:
        """Check disk space"""
        try:
            disk = psutil.disk_usage('/')
            used_percent = (disk.used / disk.total) * 100
            
            if used_percent < 85:
                status = "healthy"
            elif used_percent < 95:
                status = "degraded"
            else:
                status = "unhealthy"
            
            return {
                'status': status,
                'message': f"Disk usage: {used_percent:.1f}%",
                'disk_used_percent': used_percent,
                'disk_free_gb': disk.free / (1024**3),
                'threshold_warning': 85,
                'threshold_critical': 95
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'message': f"Disk check failed: {str(e)}",
                'error': str(e)
            }
    
    def _check_log_directory(self) -> Dict[str, Any]:
        """Check log directory is writable"""
        log_dir = Path("logs")
        
        try:
            # Ensure directory exists
            log_dir.mkdir(exist_ok=True)
            
            # Test write permissions
            test_file = log_dir / f"health_check_{int(time.time())}.tmp"
            test_file.write_text("health check")
            test_file.unlink()
            
            return {
                'status': 'healthy',
                'message': 'Log directory is writable',
                'log_directory': str(log_dir.absolute())
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'message': f"Log directory check failed: {str(e)}",
                'log_directory': str(log_dir.absolute()),
                'error': str(e)
            }
    
    def _check_weaviate_connection(self) -> Dict[str, Any]:
        """Check Weaviate database connection"""
        try:
            # Try to import and connect to Weaviate
            import requests
            
            weaviate_url = os.getenv('WEAVIATE_URL', 'http://localhost:8080')
            
            # Simple health check endpoint
            response = requests.get(
                f"{weaviate_url}/v1/.well-known/ready",
                timeout=5
            )
            
            if response.status_code == 200:
                return {
                    'status': 'healthy',
                    'message': 'Weaviate is ready',
                    'weaviate_url': weaviate_url,
                    'response_time_ms': response.elapsed.total_seconds() * 1000
                }
            else:
                return {
                    'status': 'degraded',
                    'message': f'Weaviate returned status {response.status_code}',
                    'weaviate_url': weaviate_url,
                    'status_code': response.status_code
                }
                
        except ImportError:
            return {
                'status': 'degraded',
                'message': 'Weaviate client not available (requests module missing)',
                'weaviate_url': os.getenv('WEAVIATE_URL', 'http://localhost:8080')
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'message': f'Weaviate connection failed: {str(e)}',
                'weaviate_url': os.getenv('WEAVIATE_URL', 'http://localhost:8080'),
                'error': str(e)
            }

# Health check HTTP endpoints
class HealthEndpoints:
    """HTTP endpoints for health checks"""
    
    def __init__(self, health_checker: HealthChecker):
        self.health_checker = health_checker
    
    async def health(self, request: Optional[Request] = None) -> Union[Dict[str, Any], Response]:
        """Health endpoint - comprehensive health check"""
        summary = await self.health_checker.check_health()
        
        status_code = 200
        if summary.status == HealthStatus.DEGRADED:
            status_code = 200  # Still serving traffic
        elif summary.status == HealthStatus.UNHEALTHY:
            status_code = 503  # Service unavailable
        
        response_data = summary.to_dict()
        
        if AIOHTTP_AVAILABLE and request:
            return web.json_response(response_data, status=status_code)
        else:
            return response_data
    
    async def ready(self, request: Optional[Request] = None) -> Union[Dict[str, Any], Response]:
        """Readiness endpoint - ready to serve traffic"""
        summary = await self.health_checker.check_readiness()
        
        status_code = 200 if summary.status == HealthStatus.HEALTHY else 503
        response_data = {
            'status': summary.status.value,
            'timestamp': summary.timestamp.isoformat(),
            'ready': summary.status == HealthStatus.HEALTHY,
            'checks': [check.to_dict() for check in summary.checks]
        }
        
        if AIOHTTP_AVAILABLE and request:
            return web.json_response(response_data, status=status_code)
        else:
            return response_data
    
    async def live(self, request: Optional[Request] = None) -> Union[Dict[str, Any], Response]:
        """Liveness endpoint - process is alive"""
        summary = await self.health_checker.check_liveness()
        
        status_code = 200 if summary.status != HealthStatus.UNHEALTHY else 503
        response_data = {
            'status': summary.status.value,
            'timestamp': summary.timestamp.isoformat(),
            'alive': summary.status != HealthStatus.UNHEALTHY,
            'uptime_seconds': summary.uptime_seconds
        }
        
        if AIOHTTP_AVAILABLE and request:
            return web.json_response(response_data, status=status_code)
        else:
            return response_data

async def start_health_server(port: int = 8081, host: str = '0.0.0.0', 
                             health_checker: Optional[HealthChecker] = None):
    """Start health check HTTP server"""
    if not AIOHTTP_AVAILABLE:
        logger.warning("aiohttp not available, health server not started")
        return None
    
    if health_checker is None:
        health_checker = get_health_checker()
    
    endpoints = HealthEndpoints(health_checker)
    
    app = web.Application()
    app.router.add_get('/health', endpoints.health)
    app.router.add_get('/ready', endpoints.ready)
    app.router.add_get('/live', endpoints.live)
    
    # Add simple root endpoint
    async def root(request):
        return web.json_response({
            'service': 'audithound',
            'status': 'running',
            'endpoints': {
                'health': '/health',
                'readiness': '/ready', 
                'liveness': '/live'
            }
        })
    
    app.router.add_get('/', root)
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    
    logger.info(f"Health check server started on {host}:{port}",
               category=LogCategory.SYSTEM, event_type="health_server_started",
               data={"host": host, "port": port})
    
    return runner

# Global health checker instance
_health_checker: Optional[HealthChecker] = None
_health_lock = threading.Lock()

def get_health_checker() -> HealthChecker:
    """Get global health checker instance"""
    global _health_checker
    with _health_lock:
        if _health_checker is None:
            _health_checker = HealthChecker()
        return _health_checker

# Example usage and testing
async def main():
    """Example usage of health checker"""
    print("🔍 AuditHound Health Checker Test")
    print("=" * 40)
    
    # Get health checker
    checker = get_health_checker()
    
    # Add custom health check
    def custom_check():
        return {
            'status': 'healthy',
            'message': 'Custom service is running',
            'custom_metric': 42
        }
    
    checker.register_check(
        "custom_service",
        ComponentType.SERVICE,
        custom_check,
        timeout_seconds=3.0,
        critical=False
    )
    
    # Run health checks
    print("\n🏥 Running health checks...")
    health_summary = await checker.check_health()
    
    print(f"Overall Status: {health_summary.status.value}")
    print(f"Uptime: {health_summary.uptime_seconds:.1f} seconds")
    print(f"Total Checks: {health_summary.total_checks}")
    print(f"Healthy: {health_summary.healthy_checks}")
    print(f"Degraded: {health_summary.degraded_checks}")
    print(f"Unhealthy: {health_summary.unhealthy_checks}")
    
    print("\n📋 Individual Check Results:")
    for check in health_summary.checks:
        status_emoji = {
            HealthStatus.HEALTHY: "✅",
            HealthStatus.DEGRADED: "⚠️",
            HealthStatus.UNHEALTHY: "❌",
            HealthStatus.UNKNOWN: "❓"
        }
        print(f"  {status_emoji.get(check.status, '❓')} {check.component}: {check.message} ({check.duration_ms:.1f}ms)")
    
    # Test readiness and liveness
    print("\n🚀 Testing readiness...")
    readiness = await checker.check_readiness()
    print(f"Ready: {readiness.status.value}")
    
    print("\n💓 Testing liveness...")
    liveness = await checker.check_liveness()
    print(f"Alive: {liveness.status.value}")
    
    # Start health server (if aiohttp available)
    if AIOHTTP_AVAILABLE:
        print("\n🌐 Starting health server on port 8081...")
        runner = await start_health_server(8081, '127.0.0.1', checker)
        
        print("Health endpoints available:")
        print("  http://127.0.0.1:8081/health")
        print("  http://127.0.0.1:8081/ready")
        print("  http://127.0.0.1:8081/live")
        
        # Let it run for a bit
        await asyncio.sleep(2)
        
        if runner:
            await runner.cleanup()

if __name__ == "__main__":
    asyncio.run(main())