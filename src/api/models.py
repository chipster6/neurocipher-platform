#!/usr/bin/env python3
"""
Pydantic models for API request/response validation
"""

from typing import Dict, List, Optional, Union
from pydantic import BaseModel, Field, validator
from enum import Enum


class AuditType(str, Enum):
    """Available audit types"""
    COMPREHENSIVE = "comprehensive"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    PERFORMANCE = "performance"


class ReportType(str, Enum):
    """Available report types"""
    COMPLIANCE = "compliance"
    SECURITY = "security"
    EXECUTIVE = "executive"
    DETAILED = "detailed"


class FindingSeverity(str, Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    """Finding status values"""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


# Request Models
class TenantCreateRequest(BaseModel):
    """Request model for creating a tenant"""
    name: str = Field(..., min_length=1, max_length=100, description="Tenant name")
    config: Dict = Field(default_factory=dict, description="Tenant configuration")
    
    @validator('name')
    def validate_name(cls, v):
        if not v.strip():
            raise ValueError('Tenant name cannot be empty')
        return v.strip()


class AuditRequest(BaseModel):
    """Request model for starting an audit"""
    type: AuditType = Field(default=AuditType.COMPREHENSIVE, description="Type of audit to perform")
    targets: List[str] = Field(default_factory=list, description="Target resources to audit")
    config: Dict = Field(default_factory=dict, description="Audit configuration parameters")
    
    @validator('targets')
    def validate_targets(cls, v):
        if v and len(v) > 50:  # Reasonable limit
            raise ValueError('Maximum 50 targets allowed per audit')
        return v


class ReportRequest(BaseModel):
    """Request model for generating reports"""
    type: ReportType = Field(default=ReportType.COMPLIANCE, description="Type of report to generate")
    config: Dict = Field(default_factory=dict, description="Report configuration parameters")
    framework: Optional[str] = Field(None, description="Compliance framework for the report")
    
    @validator('framework')
    def validate_framework(cls, v):
        if v and len(v) > 50:
            raise ValueError('Framework name too long')
        return v


class FindingUpdateRequest(BaseModel):
    """Request model for updating findings"""
    status: Optional[FindingStatus] = Field(None, description="New finding status")
    notes: Optional[str] = Field(None, max_length=1000, description="Update notes")
    assignee: Optional[str] = Field(None, max_length=100, description="Assigned user")
    due_date: Optional[str] = Field(None, description="Due date in ISO format")
    
    @validator('notes')
    def validate_notes(cls, v):
        if v and len(v.strip()) == 0:
            return None
        return v


# Response Models
class TenantResponse(BaseModel):
    """Response model for tenant operations"""
    tenant_id: str
    status: str
    message: Optional[str] = None


class AuditResponse(BaseModel):
    """Response model for audit operations"""
    audit_id: str
    status: str
    message: Optional[str] = None


class ReportResponse(BaseModel):
    """Response model for report operations"""
    report_id: str
    status: str
    message: Optional[str] = None


class HealthResponse(BaseModel):
    """Response model for health checks"""
    status: str
    service: str
    timestamp: Optional[str] = None
    checks: Optional[Dict] = None


class ErrorResponse(BaseModel):
    """Standard error response model"""
    error: str
    message: str
    timestamp: Optional[str] = None