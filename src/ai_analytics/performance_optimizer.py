"""
AI Processing Performance Optimizer
Caching, pipeline optimization, and resource management for AI analytics
"""

import asyncio
import json
import logging
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, asdict
from collections import defaultdict
import redis
import pickle
import gc
import psutil
import threading
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import functools
import weakref

logger = logging.getLogger(__name__)

@dataclass
class CacheEntry:
    """Represents a cache entry with metadata"""
    key: str
    value: Any
    created_at: datetime
    expires_at: Optional[datetime]
    access_count: int
    last_accessed: datetime
    size_bytes: int
    cache_type: str

@dataclass
class PerformanceMetrics:
    """Performance metrics for AI processing"""
    operation_name: str
    duration_seconds: float
    memory_usage_mb: float
    cpu_usage_percent: float
    cache_hit: bool
    input_size: int
    output_size: int
    timestamp: datetime

@dataclass
class PipelineOptimization:
    """Pipeline optimization configuration"""
    parallel_execution: bool
    batch_size: int
    memory_limit_mb: int
    cpu_cores: int
    cache_enabled: bool
    prefetch_enabled: bool

class AIProcessingCache:
    """
    Advanced caching system for AI processing results
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.local_cache = {}
        self.redis_client = None
        self.cache_stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "total_size": 0
        }
        self.max_memory_mb = self.config.get("max_memory_mb", 1024)
        self.default_ttl = self.config.get("default_ttl_seconds", 3600)
        self.cleanup_interval = self.config.get("cleanup_interval_seconds", 300)
        self._cleanup_task = None
        
    async def initialize(self):
        """Initialize cache system"""
        try:
            # Initialize Redis if configured
            redis_config = self.config.get("redis", {})
            if redis_config.get("enabled", False):
                self.redis_client = redis.Redis(
                    host=redis_config.get("host", "localhost"),
                    port=redis_config.get("port", 6379),
                    db=redis_config.get("db", 0),
                    decode_responses=False
                )
                await self._test_redis_connection()
            
            # Start cleanup task
            self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
            
            logger.info(f"AI Processing Cache initialized (Redis: {self.redis_client is not None})")
            
        except Exception as e:
            logger.error(f"Failed to initialize cache: {e}")
    
    async def get(self, key: str, cache_type: str = "default") -> Optional[Any]:
        """Get value from cache"""
        try:
            cache_key = self._generate_cache_key(key, cache_type)
            
            # Try local cache first
            if cache_key in self.local_cache:
                entry = self.local_cache[cache_key]
                
                # Check expiration
                if entry.expires_at and datetime.now() > entry.expires_at:
                    await self._evict_key(cache_key)
                    self.cache_stats["misses"] += 1
                    return None
                
                # Update access metrics
                entry.access_count += 1
                entry.last_accessed = datetime.now()
                
                self.cache_stats["hits"] += 1
                return entry.value
            
            # Try Redis if available
            if self.redis_client:
                try:
                    cached_data = self.redis_client.get(cache_key)
                    if cached_data:
                        value = pickle.loads(cached_data)
                        
                        # Store in local cache for faster access
                        await self._store_local(cache_key, value, cache_type)
                        
                        self.cache_stats["hits"] += 1
                        return value
                except Exception as e:
                    logger.warning(f"Redis get failed: {e}")
            
            self.cache_stats["misses"] += 1
            return None
            
        except Exception as e:
            logger.error(f"Cache get failed: {e}")
            self.cache_stats["misses"] += 1
            return None
    
    async def set(
        self, 
        key: str, 
        value: Any, 
        ttl_seconds: Optional[int] = None,
        cache_type: str = "default"
    ):
        """Set value in cache"""
        try:
            cache_key = self._generate_cache_key(key, cache_type)
            ttl = ttl_seconds or self.default_ttl
            
            # Store in local cache
            await self._store_local(cache_key, value, cache_type, ttl)
            
            # Store in Redis if available
            if self.redis_client:
                try:
                    serialized_value = pickle.dumps(value)
                    self.redis_client.setex(cache_key, ttl, serialized_value)
                except Exception as e:
                    logger.warning(f"Redis set failed: {e}")
            
        except Exception as e:
            logger.error(f"Cache set failed: {e}")
    
    async def invalidate(self, key: str, cache_type: str = "default"):
        """Invalidate cache entry"""
        try:
            cache_key = self._generate_cache_key(key, cache_type)
            
            # Remove from local cache
            if cache_key in self.local_cache:
                await self._evict_key(cache_key)
            
            # Remove from Redis
            if self.redis_client:
                try:
                    self.redis_client.delete(cache_key)
                except Exception as e:
                    logger.warning(f"Redis delete failed: {e}")
            
        except Exception as e:
            logger.error(f"Cache invalidation failed: {e}")
    
    async def clear_cache_type(self, cache_type: str):
        """Clear all entries of a specific cache type"""
        try:
            keys_to_remove = [
                key for key, entry in self.local_cache.items()
                if entry.cache_type == cache_type
            ]
            
            for key in keys_to_remove:
                await self._evict_key(key)
            
            logger.info(f"Cleared {len(keys_to_remove)} entries of type {cache_type}")
            
        except Exception as e:
            logger.error(f"Cache type clear failed: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        hit_rate = 0
        total_requests = self.cache_stats["hits"] + self.cache_stats["misses"]
        if total_requests > 0:
            hit_rate = (self.cache_stats["hits"] / total_requests) * 100
        
        return {
            "hit_rate_percent": round(hit_rate, 2),
            "total_entries": len(self.local_cache),
            "total_size_mb": round(self.cache_stats["total_size"] / (1024 * 1024), 2),
            "hits": self.cache_stats["hits"],
            "misses": self.cache_stats["misses"],
            "evictions": self.cache_stats["evictions"],
            "memory_usage_percent": round((self.cache_stats["total_size"] / (1024 * 1024)) / self.max_memory_mb * 100, 2)
        }
    
    def _generate_cache_key(self, key: str, cache_type: str) -> str:
        """Generate cache key with type prefix"""
        key_hash = hashlib.md5(key.encode()).hexdigest()
        return f"{cache_type}:{key_hash}"
    
    async def _store_local(
        self, 
        cache_key: str, 
        value: Any, 
        cache_type: str, 
        ttl_seconds: Optional[int] = None
    ):
        """Store value in local cache"""
        try:
            # Calculate size
            size_bytes = len(pickle.dumps(value))
            
            # Check memory limit
            while self._should_evict_for_space(size_bytes):
                await self._evict_lru()
            
            # Create cache entry
            expires_at = None
            if ttl_seconds:
                expires_at = datetime.now() + timedelta(seconds=ttl_seconds)
            
            entry = CacheEntry(
                key=cache_key,
                value=value,
                created_at=datetime.now(),
                expires_at=expires_at,
                access_count=0,
                last_accessed=datetime.now(),
                size_bytes=size_bytes,
                cache_type=cache_type
            )
            
            self.local_cache[cache_key] = entry
            self.cache_stats["total_size"] += size_bytes
            
        except Exception as e:
            logger.error(f"Local cache store failed: {e}")
    
    def _should_evict_for_space(self, new_item_size: int) -> bool:
        """Check if eviction is needed for space"""
        current_size_mb = self.cache_stats["total_size"] / (1024 * 1024)
        new_item_size_mb = new_item_size / (1024 * 1024)
        
        return (current_size_mb + new_item_size_mb) > self.max_memory_mb
    
    async def _evict_lru(self):
        """Evict least recently used item"""
        if not self.local_cache:
            return
        
        # Find LRU item
        lru_key = min(
            self.local_cache.keys(),
            key=lambda k: self.local_cache[k].last_accessed
        )
        
        await self._evict_key(lru_key)
    
    async def _evict_key(self, cache_key: str):
        """Evict specific key"""
        if cache_key in self.local_cache:
            entry = self.local_cache[cache_key]
            self.cache_stats["total_size"] -= entry.size_bytes
            self.cache_stats["evictions"] += 1
            del self.local_cache[cache_key]
    
    async def _periodic_cleanup(self):
        """Periodic cleanup of expired entries"""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                
                current_time = datetime.now()
                expired_keys = [
                    key for key, entry in self.local_cache.items()
                    if entry.expires_at and current_time > entry.expires_at
                ]
                
                for key in expired_keys:
                    await self._evict_key(key)
                
                if expired_keys:
                    logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
                
            except Exception as e:
                logger.error(f"Cache cleanup failed: {e}")
    
    async def _test_redis_connection(self):
        """Test Redis connection"""
        try:
            self.redis_client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            self.redis_client = None


class PerformanceMonitor:
    """
    Performance monitoring for AI operations
    """
    
    def __init__(self):
        self.metrics = []
        self.current_operations = {}
        self.operation_stats = defaultdict(list)
        
    def start_operation(self, operation_name: str, input_size: int = 0) -> str:
        """Start monitoring an operation"""
        operation_id = f"{operation_name}_{int(time.time() * 1000)}"
        
        self.current_operations[operation_id] = {
            "name": operation_name,
            "start_time": time.time(),
            "input_size": input_size,
            "start_memory": self._get_memory_usage(),
            "start_cpu": self._get_cpu_usage()
        }
        
        return operation_id
    
    def end_operation(
        self, 
        operation_id: str, 
        output_size: int = 0, 
        cache_hit: bool = False
    ):
        """End monitoring an operation"""
        if operation_id not in self.current_operations:
            return
        
        operation_data = self.current_operations[operation_id]
        end_time = time.time()
        
        # Calculate metrics
        duration = end_time - operation_data["start_time"]
        memory_usage = self._get_memory_usage() - operation_data["start_memory"]
        cpu_usage = self._get_cpu_usage()
        
        # Create performance metric
        metric = PerformanceMetrics(
            operation_name=operation_data["name"],
            duration_seconds=duration,
            memory_usage_mb=memory_usage,
            cpu_usage_percent=cpu_usage,
            cache_hit=cache_hit,
            input_size=operation_data["input_size"],
            output_size=output_size,
            timestamp=datetime.now()
        )
        
        # Store metrics
        self.metrics.append(metric)
        self.operation_stats[operation_data["name"]].append(metric)
        
        # Cleanup
        del self.current_operations[operation_id]
        
        # Keep only recent metrics
        self._cleanup_old_metrics()
    
    def get_operation_stats(self, operation_name: str) -> Dict[str, Any]:
        """Get statistics for a specific operation"""
        if operation_name not in self.operation_stats:
            return {}
        
        metrics = self.operation_stats[operation_name]
        
        durations = [m.duration_seconds for m in metrics]
        memory_usage = [m.memory_usage_mb for m in metrics]
        cache_hits = [m.cache_hit for m in metrics]
        
        return {
            "total_executions": len(metrics),
            "avg_duration_seconds": sum(durations) / len(durations),
            "min_duration_seconds": min(durations),
            "max_duration_seconds": max(durations),
            "avg_memory_mb": sum(memory_usage) / len(memory_usage),
            "cache_hit_rate": (sum(cache_hits) / len(cache_hits)) * 100,
            "last_execution": metrics[-1].timestamp.isoformat()
        }
    
    def get_overall_stats(self) -> Dict[str, Any]:
        """Get overall performance statistics"""
        if not self.metrics:
            return {}
        
        total_operations = len(self.metrics)
        avg_duration = sum(m.duration_seconds for m in self.metrics) / total_operations
        avg_memory = sum(m.memory_usage_mb for m in self.metrics) / total_operations
        cache_hit_rate = (sum(1 for m in self.metrics if m.cache_hit) / total_operations) * 100
        
        # Operation breakdown
        operation_counts = defaultdict(int)
        for metric in self.metrics:
            operation_counts[metric.operation_name] += 1
        
        return {
            "total_operations": total_operations,
            "avg_duration_seconds": round(avg_duration, 3),
            "avg_memory_usage_mb": round(avg_memory, 2),
            "overall_cache_hit_rate": round(cache_hit_rate, 2),
            "operation_breakdown": dict(operation_counts),
            "current_active_operations": len(self.current_operations)
        }
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB"""
        try:
            process = psutil.Process()
            return process.memory_info().rss / (1024 * 1024)
        except:
            return 0.0
    
    def _get_cpu_usage(self) -> float:
        """Get current CPU usage percentage"""
        try:
            return psutil.cpu_percent(interval=0.1)
        except:
            return 0.0
    
    def _cleanup_old_metrics(self):
        """Remove metrics older than 24 hours"""
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        self.metrics = [m for m in self.metrics if m.timestamp > cutoff_time]
        
        # Clean operation stats
        for operation_name in list(self.operation_stats.keys()):
            self.operation_stats[operation_name] = [
                m for m in self.operation_stats[operation_name] 
                if m.timestamp > cutoff_time
            ]
            
            if not self.operation_stats[operation_name]:
                del self.operation_stats[operation_name]


class PipelineOptimizer:
    """
    AI processing pipeline optimizer
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.cache = None
        self.monitor = PerformanceMonitor()
        self.executor_pool = None
        self.process_pool = None
        self.optimization_config = PipelineOptimization(
            parallel_execution=self.config.get("parallel_execution", True),
            batch_size=self.config.get("batch_size", 10),
            memory_limit_mb=self.config.get("memory_limit_mb", 2048),
            cpu_cores=self.config.get("cpu_cores", psutil.cpu_count()),
            cache_enabled=self.config.get("cache_enabled", True),
            prefetch_enabled=self.config.get("prefetch_enabled", True)
        )
        
    async def initialize(self):
        """Initialize pipeline optimizer"""
        try:
            # Initialize cache
            if self.optimization_config.cache_enabled:
                self.cache = AIProcessingCache(self.config.get("cache", {}))
                await self.cache.initialize()
            
            # Initialize thread/process pools
            max_workers = min(self.optimization_config.cpu_cores, 8)
            self.executor_pool = ThreadPoolExecutor(max_workers=max_workers)
            self.process_pool = ProcessPoolExecutor(max_workers=max_workers // 2)
            
            logger.info("Pipeline optimizer initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize pipeline optimizer: {e}")
            raise
    
    def cached_operation(
        self, 
        cache_type: str = "default", 
        ttl_seconds: Optional[int] = None
    ):
        """Decorator for caching operation results"""
        def decorator(func: Callable):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                if not self.cache:
                    return await func(*args, **kwargs)
                
                # Generate cache key from function name and arguments
                cache_key = self._generate_function_cache_key(func.__name__, args, kwargs)
                
                # Try to get from cache
                cached_result = await self.cache.get(cache_key, cache_type)
                if cached_result is not None:
                    return cached_result
                
                # Execute function and cache result
                result = await func(*args, **kwargs)
                await self.cache.set(cache_key, result, ttl_seconds, cache_type)
                
                return result
            
            return wrapper
        return decorator
    
    def monitored_operation(self, operation_name: str):
        """Decorator for monitoring operation performance"""
        def decorator(func: Callable):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                # Start monitoring
                input_size = self._estimate_input_size(args, kwargs)
                operation_id = self.monitor.start_operation(operation_name, input_size)
                
                try:
                    # Execute function
                    result = await func(*args, **kwargs)
                    
                    # End monitoring
                    output_size = self._estimate_output_size(result)
                    cache_hit = hasattr(result, '_from_cache') and result._from_cache
                    self.monitor.end_operation(operation_id, output_size, cache_hit)
                    
                    return result
                    
                except Exception as e:
                    # End monitoring even on error
                    self.monitor.end_operation(operation_id, 0, False)
                    raise
            
            return wrapper
        return decorator
    
    async def execute_batch_parallel(
        self,
        operation: Callable,
        items: List[Any],
        batch_size: Optional[int] = None
    ) -> List[Any]:
        """Execute operation on items in parallel batches"""
        try:
            if not self.optimization_config.parallel_execution:
                # Sequential execution
                return [await operation(item) for item in items]
            
            effective_batch_size = batch_size or self.optimization_config.batch_size
            results = []
            
            # Process items in batches
            for i in range(0, len(items), effective_batch_size):
                batch = items[i:i + effective_batch_size]
                
                # Execute batch in parallel
                batch_tasks = [operation(item) for item in batch]
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                # Handle results and exceptions
                for result in batch_results:
                    if isinstance(result, Exception):
                        logger.error(f"Batch operation failed: {result}")
                        results.append(None)
                    else:
                        results.append(result)
                
                # Memory management
                await self._manage_memory()
            
            return results
            
        except Exception as e:
            logger.error(f"Batch parallel execution failed: {e}")
            return [None] * len(items)
    
    async def optimize_memory_usage(self):
        """Optimize memory usage"""
        try:
            # Force garbage collection
            gc.collect()
            
            # Clear cache if memory usage is high
            if self.cache:
                memory_percent = self.cache.get_stats().get("memory_usage_percent", 0)
                if memory_percent > 80:
                    await self.cache.clear_cache_type("temporary")
                    logger.info("Cleared temporary cache due to high memory usage")
            
            # Check system memory
            memory_info = psutil.virtual_memory()
            if memory_info.percent > 85:
                logger.warning(f"High system memory usage: {memory_info.percent}%")
                
                # Aggressive cleanup
                if self.cache:
                    await self.cache.clear_cache_type("analysis_results")
                    
                gc.collect()
            
        except Exception as e:
            logger.error(f"Memory optimization failed: {e}")
    
    async def prefetch_data(self, data_keys: List[str], cache_type: str = "prefetch"):
        """Prefetch data into cache"""
        if not self.optimization_config.prefetch_enabled or not self.cache:
            return
        
        try:
            prefetch_tasks = []
            for key in data_keys:
                # Check if data is already cached
                cached_data = await self.cache.get(key, cache_type)
                if cached_data is None:
                    # Add to prefetch queue
                    prefetch_tasks.append(self._prefetch_single_item(key, cache_type))
            
            if prefetch_tasks:
                await asyncio.gather(*prefetch_tasks, return_exceptions=True)
                logger.debug(f"Prefetched {len(prefetch_tasks)} items")
                
        except Exception as e:
            logger.error(f"Data prefetching failed: {e}")
    
    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get optimization statistics"""
        stats = {
            "configuration": asdict(self.optimization_config),
            "performance_stats": self.monitor.get_overall_stats(),
            "system_resources": {
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent,
                "available_memory_gb": psutil.virtual_memory().available / (1024**3)
            }
        }
        
        if self.cache:
            stats["cache_stats"] = self.cache.get_stats()
        
        return stats
    
    def _generate_function_cache_key(
        self, 
        func_name: str, 
        args: tuple, 
        kwargs: dict
    ) -> str:
        """Generate cache key for function call"""
        # Create a hashable representation
        key_data = {
            "function": func_name,
            "args": str(args),
            "kwargs": str(sorted(kwargs.items()))
        }
        
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _estimate_input_size(self, args: tuple, kwargs: dict) -> int:
        """Estimate input size for monitoring"""
        try:
            total_size = 0
            
            # Estimate args size
            for arg in args:
                if isinstance(arg, (str, bytes)):
                    total_size += len(arg)
                elif isinstance(arg, (list, dict)):
                    total_size += len(str(arg))
                else:
                    total_size += 1
            
            # Estimate kwargs size
            for value in kwargs.values():
                if isinstance(value, (str, bytes)):
                    total_size += len(value)
                elif isinstance(value, (list, dict)):
                    total_size += len(str(value))
                else:
                    total_size += 1
            
            return total_size
            
        except:
            return 0
    
    def _estimate_output_size(self, result: Any) -> int:
        """Estimate output size for monitoring"""
        try:
            if isinstance(result, (str, bytes)):
                return len(result)
            elif isinstance(result, (list, dict)):
                return len(str(result))
            else:
                return 1
        except:
            return 0
    
    async def _manage_memory(self):
        """Manage memory during processing"""
        try:
            memory_info = psutil.virtual_memory()
            
            if memory_info.percent > 75:
                # Trigger garbage collection
                gc.collect()
                
                # Clear temporary cache
                if self.cache:
                    await self.cache.clear_cache_type("temporary")
                
                # Small delay to allow memory cleanup
                await asyncio.sleep(0.1)
                
        except Exception as e:
            logger.error(f"Memory management failed: {e}")
    
    async def _prefetch_single_item(self, key: str, cache_type: str):
        """Prefetch a single item (placeholder implementation)"""
        try:
            # This would typically fetch data from a data source
            # For now, we'll just simulate the prefetch
            await asyncio.sleep(0.01)  # Simulate I/O
            
            # Cache placeholder data
            placeholder_data = f"prefetched_data_for_{key}"
            await self.cache.set(key, placeholder_data, cache_type=cache_type)
            
        except Exception as e:
            logger.error(f"Prefetch failed for key {key}: {e}")
    
    async def cleanup(self):
        """Cleanup resources"""
        try:
            # Shutdown executor pools
            if self.executor_pool:
                self.executor_pool.shutdown(wait=True)
            
            if self.process_pool:
                self.process_pool.shutdown(wait=True)
            
            logger.info("Pipeline optimizer cleanup completed")
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")


# Global performance optimizer instance
_global_optimizer = None

def get_performance_optimizer(config: Optional[Dict[str, Any]] = None) -> PipelineOptimizer:
    """Get global performance optimizer instance"""
    global _global_optimizer
    
    if _global_optimizer is None:
        _global_optimizer = PipelineOptimizer(config)
    
    return _global_optimizer

# Convenience decorators
def cached(cache_type: str = "default", ttl_seconds: Optional[int] = None):
    """Convenience decorator for caching"""
    optimizer = get_performance_optimizer()
    return optimizer.cached_operation(cache_type, ttl_seconds)

def monitored(operation_name: str):
    """Convenience decorator for monitoring"""
    optimizer = get_performance_optimizer()
    return optimizer.monitored_operation(operation_name)