# Advanced caching strategy implementation
import time
import json
import hashlib
import logging
import threading
from typing import Any, Dict, List, Optional, Union, Callable
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
import redis
from functools import wraps
import pickle
import weakref

logger = logging.getLogger(__name__)


class CacheLevel(Enum):
    """Cache level enumeration."""
    L1_MEMORY = "memory"
    L2_REDIS = "redis"
    L3_DISTRIBUTED = "distributed"


@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    value: Any
    created_at: float
    ttl: int
    hit_count: int = 0
    size_bytes: int = 0
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        
        # Estimate size
        if hasattr(self.value, '__sizeof__'):
            self.size_bytes = self.value.__sizeof__()
        else:
            self.size_bytes = len(str(self.value))
    
    @property
    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        return time.time() > (self.created_at + self.ttl)
    
    @property
    def age_seconds(self) -> float:
        """Get age of cache entry in seconds."""
        return time.time() - self.created_at


class CacheBackend(ABC):
    """Abstract cache backend interface."""
    
    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        pass
    
    @abstractmethod
    def set(self, key: str, value: Any, ttl: int = 300) -> bool:
        pass
    
    @abstractmethod
    def delete(self, key: str) -> bool:
        pass
    
    @abstractmethod
    def clear(self) -> bool:
        pass
    
    @abstractmethod
    def exists(self, key: str) -> bool:
        pass
    
    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        pass


class MemoryCache(CacheBackend):
    """In-memory cache backend with LRU eviction."""
    
    def __init__(self, max_size: int = 1000, max_memory_mb: int = 100):
        self.max_size = max_size
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.cache: Dict[str, CacheEntry] = {}
        self.access_order: List[str] = []
        self.total_memory = 0
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self._lock = threading.RLock()
    
    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self.cache:
                entry = self.cache[key]
                if entry.is_expired:
                    self._remove_entry(key)
                    self.misses += 1
                    return None
                
                # Update access order (LRU)
                if key in self.access_order:
                    self.access_order.remove(key)
                self.access_order.append(key)
                
                entry.hit_count += 1
                self.hits += 1
                return entry.value
            
            self.misses += 1
            return None
    
    def set(self, key: str, value: Any, ttl: int = 300) -> bool:
        with self._lock:
            # Remove existing entry if present
            if key in self.cache:
                self._remove_entry(key)
            
            # Create new entry
            entry = CacheEntry(value=value, created_at=time.time(), ttl=ttl)
            
            # Check memory limits
            if (self.total_memory + entry.size_bytes > self.max_memory_bytes or
                len(self.cache) >= self.max_size):
                self._evict_entries()
            
            # Add to cache
            self.cache[key] = entry
            self.access_order.append(key)
            self.total_memory += entry.size_bytes
            
            return True
    
    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self.cache:
                self._remove_entry(key)
                return True
            return False
    
    def clear(self) -> bool:
        with self._lock:
            self.cache.clear()
            self.access_order.clear()
            self.total_memory = 0
            return True
    
    def exists(self, key: str) -> bool:
        with self._lock:
            return key in self.cache and not self.cache[key].is_expired
    
    def _remove_entry(self, key: str):
        """Remove entry and update metadata."""
        if key in self.cache:
            entry = self.cache[key]
            self.total_memory -= entry.size_bytes
            del self.cache[key]
            
            if key in self.access_order:
                self.access_order.remove(key)
    
    def _evict_entries(self):
        """Evict entries using LRU policy."""
        while (len(self.cache) >= self.max_size or 
               self.total_memory > self.max_memory_bytes * 0.8):
            
            if not self.access_order:
                break
            
            # Remove least recently used
            lru_key = self.access_order[0]
            self._remove_entry(lru_key)
            self.evictions += 1
    
    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total_requests = self.hits + self.misses
            hit_ratio = self.hits / total_requests if total_requests > 0 else 0
            
            return {
                'backend': 'memory',
                'entries': len(self.cache),
                'memory_usage_mb': self.total_memory / (1024 * 1024),
                'max_memory_mb': self.max_memory_bytes / (1024 * 1024),
                'hits': self.hits,
                'misses': self.misses,
                'hit_ratio': hit_ratio,
                'evictions': self.evictions,
                'memory_utilization': self.total_memory / self.max_memory_bytes
            }


class RedisCache(CacheBackend):
    """Redis cache backend."""
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        try:
            self.redis_client = redis.from_url(redis_url, decode_responses=False)
            self.redis_client.ping()  # Test connection
            self.hits = 0
            self.misses = 0
            self.errors = 0
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.redis_client = None
    
    def get(self, key: str) -> Optional[Any]:
        if not self.redis_client:
            return None
        
        try:
            data = self.redis_client.get(key)
            if data:
                self.hits += 1
                return pickle.loads(data)
            
            self.misses += 1
            return None
            
        except Exception as e:
            logger.error(f"Redis get error for key {key}: {e}")
            self.errors += 1
            return None
    
    def set(self, key: str, value: Any, ttl: int = 300) -> bool:
        if not self.redis_client:
            return False
        
        try:
            data = pickle.dumps(value)
            return self.redis_client.setex(key, ttl, data)
            
        except Exception as e:
            logger.error(f"Redis set error for key {key}: {e}")
            self.errors += 1
            return False
    
    def delete(self, key: str) -> bool:
        if not self.redis_client:
            return False
        
        try:
            return bool(self.redis_client.delete(key))
            
        except Exception as e:
            logger.error(f"Redis delete error for key {key}: {e}")
            self.errors += 1
            return False
    
    def clear(self) -> bool:
        if not self.redis_client:
            return False
        
        try:
            return self.redis_client.flushdb()
            
        except Exception as e:
            logger.error(f"Redis clear error: {e}")
            self.errors += 1
            return False
    
    def exists(self, key: str) -> bool:
        if not self.redis_client:
            return False
        
        try:
            return bool(self.redis_client.exists(key))
            
        except Exception as e:
            logger.error(f"Redis exists error for key {key}: {e}")
            self.errors += 1
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        stats = {
            'backend': 'redis',
            'hits': self.hits,
            'misses': self.misses,
            'errors': self.errors,
            'connected': self.redis_client is not None
        }
        
        if self.redis_client:
            try:
                info = self.redis_client.info()
                stats.update({
                    'memory_usage_mb': info.get('used_memory', 0) / (1024 * 1024),
                    'connected_clients': info.get('connected_clients', 0),
                    'total_commands_processed': info.get('total_commands_processed', 0),
                    'keyspace_hits': info.get('keyspace_hits', 0),
                    'keyspace_misses': info.get('keyspace_misses', 0)
                })
                
                keyspace_total = stats['keyspace_hits'] + stats['keyspace_misses']
                if keyspace_total > 0:
                    stats['redis_hit_ratio'] = stats['keyspace_hits'] / keyspace_total
                
            except Exception as e:
                logger.error(f"Failed to get Redis info: {e}")
        
        return stats


class MultiLevelCache:
    """Multi-level cache with L1 (memory), L2 (Redis), and intelligent promotion."""
    
    def __init__(self, memory_cache: MemoryCache, redis_cache: RedisCache,
                 promotion_threshold: int = 3):
        self.l1_cache = memory_cache
        self.l2_cache = redis_cache
        self.promotion_threshold = promotion_threshold
        self.access_counts = {}
        self._lock = threading.Lock()
    
    def get(self, key: str) -> Optional[Any]:
        # Try L1 cache first
        value = self.l1_cache.get(key)
        if value is not None:
            return value
        
        # Try L2 cache
        value = self.l2_cache.get(key)
        if value is not None:
            # Track access for potential promotion
            with self._lock:
                self.access_counts[key] = self.access_counts.get(key, 0) + 1
                
                # Promote to L1 if frequently accessed
                if self.access_counts[key] >= self.promotion_threshold:
                    self.l1_cache.set(key, value, ttl=300)  # Shorter TTL for L1
                    del self.access_counts[key]
            
            return value
        
        return None
    
    def set(self, key: str, value: Any, ttl: int = 300, level: CacheLevel = CacheLevel.L2_REDIS):
        if level == CacheLevel.L1_MEMORY:
            return self.l1_cache.set(key, value, ttl)
        elif level == CacheLevel.L2_REDIS:
            # Set in both L2 and potentially L1
            result = self.l2_cache.set(key, value, ttl)
            
            # Also set in L1 for immediate access
            self.l1_cache.set(key, value, min(ttl, 300))
            
            return result
        
        return False
    
    def delete(self, key: str):
        # Delete from all levels
        l1_result = self.l1_cache.delete(key)
        l2_result = self.l2_cache.delete(key)
        
        with self._lock:
            self.access_counts.pop(key, None)
        
        return l1_result or l2_result
    
    def clear(self):
        self.l1_cache.clear()
        self.l2_cache.clear()
        with self._lock:
            self.access_counts.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        l1_stats = self.l1_cache.get_stats()
        l2_stats = self.l2_cache.get_stats()
        
        return {
            'multi_level': True,
            'l1_cache': l1_stats,
            'l2_cache': l2_stats,
            'promotion_threshold': self.promotion_threshold,
            'pending_promotions': len(self.access_counts)
        }


class CacheManager:
    """Main cache manager with intelligent strategies."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.cache_backends = {}
        self.default_ttl = config.get('default_ttl', 300)
        self.cache_tags = {}
        self._setup_backends()
    
    def _setup_backends(self):
        """Setup cache backends based on configuration."""
        
        # Memory cache
        memory_config = self.config.get('memory', {})
        memory_cache = MemoryCache(
            max_size=memory_config.get('max_size', 1000),
            max_memory_mb=memory_config.get('max_memory_mb', 100)
        )
        
        # Redis cache
        redis_config = self.config.get('redis', {})
        redis_cache = RedisCache(
            redis_url=redis_config.get('url', 'redis://localhost:6379/0')
        )
        
        # Multi-level cache
        self.cache = MultiLevelCache(
            memory_cache=memory_cache,
            redis_cache=redis_cache,
            promotion_threshold=self.config.get('promotion_threshold', 3)
        )
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache."""
        value = self.cache.get(key)
        return value if value is not None else default
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None, 
           tags: Optional[List[str]] = None, level: CacheLevel = CacheLevel.L2_REDIS):
        """Set value in cache."""
        ttl = ttl or self.default_ttl
        
        # Store tags for invalidation
        if tags:
            for tag in tags:
                if tag not in self.cache_tags:
                    self.cache_tags[tag] = set()
                self.cache_tags[tag].add(key)
        
        return self.cache.set(key, value, ttl, level)
    
    def delete(self, key: str):
        """Delete key from cache."""
        return self.cache.delete(key)
    
    def invalidate_by_tag(self, tag: str):
        """Invalidate all cache entries with a specific tag."""
        if tag in self.cache_tags:
            keys_to_invalidate = list(self.cache_tags[tag])
            for key in keys_to_invalidate:
                self.cache.delete(key)
            del self.cache_tags[tag]
            
            logger.info(f"Invalidated {len(keys_to_invalidate)} cache entries with tag: {tag}")
    
    def get_or_compute(self, key: str, compute_func: Callable, ttl: Optional[int] = None,
                      tags: Optional[List[str]] = None) -> Any:
        """Get from cache or compute and cache the value."""
        value = self.cache.get(key)
        
        if value is None:
            # Compute the value
            value = compute_func()
            
            # Cache the computed value
            self.set(key, value, ttl, tags)
        
        return value
    
    def cache_decorator(self, ttl: Optional[int] = None, 
                       key_prefix: str = "", 
                       tags: Optional[List[str]] = None):
        """Decorator for caching function results."""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Generate cache key
                key_parts = [key_prefix, func.__name__]
                if args:
                    key_parts.append(hashlib.md5(str(args).encode()).hexdigest()[:8])
                if kwargs:
                    key_parts.append(hashlib.md5(str(sorted(kwargs.items())).encode()).hexdigest()[:8])
                
                cache_key = "_".join(filter(None, key_parts))
                
                # Try to get from cache
                result = self.get(cache_key)
                if result is not None:
                    return result
                
                # Compute and cache
                result = func(*args, **kwargs)
                self.set(cache_key, result, ttl, tags)
                
                return result
            
            return wrapper
        return decorator
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache performance statistics."""
        stats = self.cache.get_stats()
        
        # Add manager-specific stats
        stats.update({
            'total_tags': len(self.cache_tags),
            'tagged_keys': sum(len(keys) for keys in self.cache_tags.values()),
            'config': self.config
        })
        
        return stats
    
    def optimize_cache_settings(self) -> Dict[str, Any]:
        """Analyze performance and suggest optimizations."""
        stats = self.get_performance_stats()
        recommendations = []
        
        # Analyze L1 cache performance
        l1_stats = stats.get('l1_cache', {})
        l1_hit_ratio = l1_stats.get('hit_ratio', 0)
        l1_memory_util = l1_stats.get('memory_utilization', 0)
        
        if l1_hit_ratio < 0.7:
            recommendations.append("Consider increasing L1 cache size - low hit ratio")
        
        if l1_memory_util > 0.9:
            recommendations.append("L1 cache memory utilization high - consider increasing memory limit")
        
        # Analyze L2 cache performance
        l2_stats = stats.get('l2_cache', {})
        if l2_stats.get('connected', False):
            redis_hit_ratio = l2_stats.get('redis_hit_ratio', 0)
            if redis_hit_ratio < 0.8:
                recommendations.append("Consider increasing Redis cache TTL - low hit ratio")
        
        # Analyze promotion effectiveness
        pending_promotions = stats.get('pending_promotions', 0)
        if pending_promotions > 100:
            recommendations.append("Consider lowering promotion threshold - many pending promotions")
        
        return {
            'current_performance': stats,
            'recommendations': recommendations,
            'optimization_score': self._calculate_optimization_score(stats)
        }
    
    def _calculate_optimization_score(self, stats: Dict[str, Any]) -> float:
        """Calculate cache optimization score (0-100)."""
        score = 100.0
        
        # L1 hit ratio impact (40% of score)
        l1_hit_ratio = stats.get('l1_cache', {}).get('hit_ratio', 0)
        score -= (1 - l1_hit_ratio) * 40
        
        # L2 hit ratio impact (30% of score)
        l2_hit_ratio = stats.get('l2_cache', {}).get('redis_hit_ratio', 0)
        score -= (1 - l2_hit_ratio) * 30
        
        # Memory utilization impact (20% of score)
        memory_util = stats.get('l1_cache', {}).get('memory_utilization', 0)
        if memory_util > 0.9:
            score -= (memory_util - 0.9) * 200  # Penalty for high memory usage
        
        # Error rate impact (10% of score)
        errors = stats.get('l2_cache', {}).get('errors', 0)
        total_requests = stats.get('l2_cache', {}).get('hits', 0) + stats.get('l2_cache', {}).get('misses', 0)
        if total_requests > 0:
            error_rate = errors / total_requests
            score -= error_rate * 100
        
        return max(0, min(100, score))


# Global cache manager instance
cache_manager = None


def initialize_cache_manager(config: Dict[str, Any]):
    """Initialize global cache manager."""
    global cache_manager
    cache_manager = CacheManager(config)
    return cache_manager


def get_cache_manager() -> Optional[CacheManager]:
    """Get global cache manager instance."""
    return cache_manager