#!/usr/bin/env python3
"""
Structured JSON Logging for AuditHound
Provides centralized logging with ELK/Loki compatibility
"""

import os
import json
import logging
import logging.handlers
import traceback
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union
from pathlib import Path
import threading
from contextvars import ContextVar
from dataclasses import dataclass, asdict
from enum import Enum

# Context variables for request/session tracking
request_id_context: ContextVar[Optional[str]] = ContextVar('request_id', default=None)
client_id_context: ContextVar[Optional[str]] = ContextVar('client_id', default=None)
user_id_context: ContextVar[Optional[str]] = ContextVar('user_id', default=None)

class LogLevel(Enum):
    """Log levels for structured logging"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class LogCategory(Enum):
    """Log categories for better organization"""
    SECURITY = "security"
    COMPLIANCE = "compliance"
    AUDIT = "audit"
    PERFORMANCE = "performance"
    BUSINESS = "business"
    SYSTEM = "system"
    API = "api"
    DATABASE = "database"
    INTEGRATION = "integration"
    USER_ACTION = "user_action"

@dataclass
class LogContext:
    """Context information for structured logs"""
    request_id: Optional[str] = None
    client_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    component: Optional[str] = None
    function: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def __init__(self, include_context: bool = True):
        super().__init__()
        self.include_context = include_context
        self.hostname = os.uname().nodename if hasattr(os, 'uname') else 'unknown'
        
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        
        # Base log structure
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
            "hostname": self.hostname,
            "process_id": os.getpid(),
            "thread_id": threading.get_ident(),
        }
        
        # Add context variables if available
        if self.include_context:
            context = {
                "request_id": request_id_context.get(),
                "client_id": client_id_context.get(),
                "user_id": user_id_context.get(),
            }
            # Only include non-None context values
            log_entry["context"] = {k: v for k, v in context.items() if v is not None}
        
        # Add module/function information
        if hasattr(record, 'pathname') and record.pathname:
            log_entry["source"] = {
                "file": Path(record.pathname).name,
                "function": record.funcName,
                "line": record.lineno,
                "module": record.module if hasattr(record, 'module') else None
            }
        
        # Add custom fields from extra
        if hasattr(record, 'category'):
            log_entry["category"] = record.category
        
        if hasattr(record, 'event_type'):
            log_entry["event_type"] = record.event_type
            
        if hasattr(record, 'duration_ms'):
            log_entry["duration_ms"] = record.duration_ms
            
        if hasattr(record, 'status_code'):
            log_entry["status_code"] = record.status_code
            
        if hasattr(record, 'user_agent'):
            log_entry["user_agent"] = record.user_agent
            
        if hasattr(record, 'ip_address'):
            log_entry["ip_address"] = record.ip_address
        
        # Add custom data if present
        if hasattr(record, 'data') and record.data:
            log_entry["data"] = record.data
        
        # Handle exceptions
        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": traceback.format_exception(*record.exc_info)
            }
        
        # Add stack info if available
        if record.stack_info:
            log_entry["stack_info"] = record.stack_info
        
        return json.dumps(log_entry, default=str, ensure_ascii=False)

class AuditLogger:
    """Enhanced logger for AuditHound with structured logging capabilities"""
    
    def __init__(self, name: str, level: str = "INFO"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        self._setup_handlers()
        
    def _setup_handlers(self):
        """Setup log handlers based on configuration"""
        
        # Remove existing handlers to avoid duplicates
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Console handler with JSON formatting
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(JSONFormatter())
        self.logger.addHandler(console_handler)
        
        # File handler for persistent logs
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / "audithound.jsonl",
            maxBytes=100 * 1024 * 1024,  # 100MB
            backupCount=10,
            encoding='utf-8'
        )
        file_handler.setFormatter(JSONFormatter())
        self.logger.addHandler(file_handler)
        
        # Separate file for security events
        security_handler = logging.handlers.RotatingFileHandler(
            log_dir / "security.jsonl",
            maxBytes=50 * 1024 * 1024,  # 50MB
            backupCount=20,
            encoding='utf-8'
        )
        security_handler.setFormatter(JSONFormatter())
        security_handler.addFilter(lambda record: getattr(record, 'category', None) == 'security')
        self.logger.addHandler(security_handler)
        
        # Audit events file
        audit_handler = logging.handlers.RotatingFileHandler(
            log_dir / "audit.jsonl",
            maxBytes=50 * 1024 * 1024,  # 50MB
            backupCount=20,
            encoding='utf-8'
        )
        audit_handler.setFormatter(JSONFormatter())
        audit_handler.addFilter(lambda record: getattr(record, 'category', None) == 'audit')
        self.logger.addHandler(audit_handler)
    
    def _log(self, level: str, message: str, category: Optional[LogCategory] = None, 
             event_type: Optional[str] = None, data: Optional[Dict[str, Any]] = None, **kwargs):
        """Internal logging method with structured data"""
        
        extra = {}
        
        if category:
            extra['category'] = category.value if isinstance(category, LogCategory) else category
            
        if event_type:
            extra['event_type'] = event_type
            
        if data:
            extra['data'] = data
            
        # Add any additional keyword arguments
        extra.update(kwargs)
        
        getattr(self.logger, level.lower())(message, extra=extra)
    
    def debug(self, message: str, category: Optional[LogCategory] = None, 
              event_type: Optional[str] = None, data: Optional[Dict[str, Any]] = None, **kwargs):
        """Log debug message"""
        self._log("debug", message, category, event_type, data, **kwargs)
    
    def info(self, message: str, category: Optional[LogCategory] = None, 
             event_type: Optional[str] = None, data: Optional[Dict[str, Any]] = None, **kwargs):
        """Log info message"""
        self._log("info", message, category, event_type, data, **kwargs)
    
    def warning(self, message: str, category: Optional[LogCategory] = None, 
                event_type: Optional[str] = None, data: Optional[Dict[str, Any]] = None, **kwargs):
        """Log warning message"""
        self._log("warning", message, category, event_type, data, **kwargs)
    
    def error(self, message: str, category: Optional[LogCategory] = None, 
              event_type: Optional[str] = None, data: Optional[Dict[str, Any]] = None, **kwargs):
        """Log error message"""
        self._log("error", message, category, event_type, data, **kwargs)
    
    def critical(self, message: str, category: Optional[LogCategory] = None, 
                 event_type: Optional[str] = None, data: Optional[Dict[str, Any]] = None, **kwargs):
        """Log critical message"""
        self._log("critical", message, category, event_type, data, **kwargs)
    
    def security_event(self, event_type: str, message: str, 
                      data: Optional[Dict[str, Any]] = None, **kwargs):
        """Log security-related events"""
        self._log("warning", message, LogCategory.SECURITY, event_type, data, **kwargs)
    
    def audit_event(self, event_type: str, message: str, 
                   data: Optional[Dict[str, Any]] = None, **kwargs):
        """Log audit events"""
        self._log("info", message, LogCategory.AUDIT, event_type, data, **kwargs)
    
    def performance_event(self, event_type: str, message: str, duration_ms: float,
                         data: Optional[Dict[str, Any]] = None, **kwargs):
        """Log performance events"""
        kwargs['duration_ms'] = duration_ms
        self._log("info", message, LogCategory.PERFORMANCE, event_type, data, **kwargs)
    
    def business_event(self, event_type: str, message: str, 
                      data: Optional[Dict[str, Any]] = None, **kwargs):
        """Log business events"""
        self._log("info", message, LogCategory.BUSINESS, event_type, data, **kwargs)
    
    def api_request(self, method: str, path: str, status_code: int, 
                   duration_ms: float, user_agent: Optional[str] = None,
                   ip_address: Optional[str] = None, **kwargs):
        """Log API request"""
        message = f"{method} {path} - {status_code}"
        extra = {
            'status_code': status_code,
            'duration_ms': duration_ms,
            'user_agent': user_agent,
            'ip_address': ip_address
        }
        extra.update(kwargs)
        self._log("info", message, LogCategory.API, "request", None, **extra)
    
    def database_operation(self, operation: str, table: str, duration_ms: float,
                          records_affected: Optional[int] = None, **kwargs):
        """Log database operations"""
        message = f"Database {operation} on {table}"
        data = {
            'operation': operation,
            'table': table,
            'records_affected': records_affected
        }
        self.performance_event("database_operation", message, duration_ms, data, **kwargs)
    
    def user_action(self, action: str, user_id: str, details: Optional[Dict[str, Any]] = None, **kwargs):
        """Log user actions"""
        message = f"User {user_id} performed {action}"
        data = {'action': action, 'user_id': user_id}
        if details:
            data.update(details)
        self._log("info", message, LogCategory.USER_ACTION, action, data, **kwargs)
    
    def compliance_event(self, framework: str, control: str, status: str, 
                        data: Optional[Dict[str, Any]] = None, **kwargs):
        """Log compliance events"""
        message = f"Compliance check: {framework} {control} - {status}"
        event_data = {
            'framework': framework,
            'control': control,
            'status': status
        }
        if data:
            event_data.update(data)
        self._log("info", message, LogCategory.COMPLIANCE, "compliance_check", event_data, **kwargs)

# Global loggers cache
_loggers: Dict[str, AuditLogger] = {}
_loggers_lock = threading.Lock()

def get_logger(name: str, level: str = "INFO") -> AuditLogger:
    """Get or create a logger instance"""
    with _loggers_lock:
        if name not in _loggers:
            _loggers[name] = AuditLogger(name, level)
        return _loggers[name]

def setup_logging(level: str = "INFO", enable_console: bool = True, 
                 enable_file: bool = True, log_dir: str = "logs") -> None:
    """Setup global logging configuration"""
    
    # Create log directory
    Path(log_dir).mkdir(exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    if enable_console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(console_handler)
    
    if enable_file:
        file_handler = logging.handlers.RotatingFileHandler(
            Path(log_dir) / "audithound.jsonl",
            maxBytes=100 * 1024 * 1024,
            backupCount=10,
            encoding='utf-8'
        )
        file_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(file_handler)

class LogContextManager:
    """Context manager for setting log context"""
    
    def __init__(self, request_id: Optional[str] = None, 
                 client_id: Optional[str] = None,
                 user_id: Optional[str] = None):
        self.request_id = request_id
        self.client_id = client_id
        self.user_id = user_id
        self.tokens = []
    
    def __enter__(self):
        if self.request_id:
            self.tokens.append(request_id_context.set(self.request_id))
        if self.client_id:
            self.tokens.append(client_id_context.set(self.client_id))
        if self.user_id:
            self.tokens.append(user_id_context.set(self.user_id))
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        for token in reversed(self.tokens):
            token.var.reset(token)

def with_log_context(request_id: Optional[str] = None,
                    client_id: Optional[str] = None,
                    user_id: Optional[str] = None):
    """Decorator to set log context for a function"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            with LogContextManager(request_id, client_id, user_id):
                return func(*args, **kwargs)
        return wrapper
    return decorator

# Utility functions for common logging patterns
def log_function_entry(logger: AuditLogger, func_name: str, **kwargs):
    """Log function entry"""
    logger.debug(f"Entering {func_name}", event_type="function_entry", data=kwargs)

def log_function_exit(logger: AuditLogger, func_name: str, duration_ms: float, **kwargs):
    """Log function exit with duration"""
    logger.debug(f"Exiting {func_name}", event_type="function_exit", 
                duration_ms=duration_ms, data=kwargs)

def log_exception(logger: AuditLogger, exception: Exception, context: Optional[str] = None):
    """Log an exception with full context"""
    message = f"Exception occurred: {type(exception).__name__}: {str(exception)}"
    if context:
        message = f"{context} - {message}"
    logger.error(message, category=LogCategory.SYSTEM, event_type="exception",
                data={'exception_type': type(exception).__name__}, exc_info=True)

# Example usage and testing
if __name__ == "__main__":
    # Setup logging
    setup_logging(level="DEBUG")
    
    # Get logger
    logger = get_logger("test_module")
    
    # Test different log types
    logger.info("Application starting", category=LogCategory.SYSTEM, 
               event_type="startup", data={"version": "1.0.0"})
    
    # Test with context
    with LogContextManager(request_id="req-123", client_id="client-456", user_id="user-789"):
        logger.audit_event("user_login", "User successfully logged in", 
                          data={"login_method": "oauth", "ip": "192.168.1.1"})
        
        logger.api_request("GET", "/api/findings", 200, 145.5, 
                          user_agent="Mozilla/5.0", ip_address="192.168.1.1")
        
        logger.performance_event("database_query", "Executed complex query", 1250.3,
                                data={"query": "SELECT * FROM findings", "rows": 150})
        
        logger.compliance_event("SOC2", "CC6.1", "pass", 
                               data={"control_description": "Logical access controls"})
    
    # Test error logging
    try:
        raise ValueError("Test exception")
    except Exception as e:
        log_exception(logger, e, "Testing exception logging")
    
    print("Structured logging test completed. Check logs/ directory for output files.")