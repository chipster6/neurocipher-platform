#!/usr/bin/env python3
"""
AuditHound API Server
Production-ready FastAPI server with comprehensive endpoints
"""

import asyncio
import argparse
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
import uvicorn
from contextlib import asynccontextmanager
import jwt

# Import Pydantic models for validation
from .models import (
    TenantCreateRequest, TenantResponse,
    AuditRequest, AuditResponse,
    ReportRequest, ReportResponse,
    FindingUpdateRequest, HealthResponse,
    FindingSeverity, FindingStatus
)

# Import authentication
from ..security.auth import (
    get_current_user, require_admin, require_tenant_access, require_permission,
    auth_manager, authz_manager, TokenData, User, UserRole
)

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.observability.logger import get_logger, setup_logging
from src.observability.metrics import MetricsCollector
from src.observability.health import HealthChecker
from src.unified_audit_engine import UnifiedAuditEngine
from src.multi_tenant_manager import MultiTenantManager
from src.unified_models import *
from src.persistence.unified_db_manager import UnifiedDatabaseManager
from src.security.unified_auth_manager import UnifiedAuthManager
from src.ai_analytics import AIAnalyticsManager

# Initialize logging
setup_logging()
logger = get_logger(__name__)

# Global instances
metrics = MetricsCollector()
health_checker = HealthChecker()

# Database and authentication setup
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://audithound:password@localhost:5432/audithound")
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")

db_manager = UnifiedDatabaseManager(DATABASE_URL)
auth_manager = UnifiedAuthManager(SECRET_KEY, db_manager)
ai_analytics = AIAnalyticsManager()

# Legacy components - will be refactored to use unified systems
audit_engine = UnifiedAuditEngine()
tenant_manager = MultiTenantManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    logger.info("Starting AuditHound Unified API server...")
    
    # Initialize unified database and authentication
    await db_manager.initialize()
    
    # Initialize AI analytics
    await ai_analytics.initialize()
    
    # Initialize legacy services (will be refactored)
    await audit_engine.initialize()
    await tenant_manager.initialize()
    
    # Start background metrics collection
    metrics.start_background_collection()
    
    # Start session cleanup task
    asyncio.create_task(periodic_session_cleanup())
    
    yield
    
    # Cleanup
    logger.info("Shutting down AuditHound Unified API server...")
    await ai_analytics.cleanup()
    await db_manager.cleanup()
    await audit_engine.cleanup()
    await tenant_manager.cleanup()

async def periodic_session_cleanup():
    """Periodic cleanup of expired sessions"""
    while True:
        try:
            await auth_manager.cleanup_expired_sessions()
            await asyncio.sleep(300)  # Cleanup every 5 minutes
        except Exception as e:
            logger.error(f"Session cleanup error: {e}")
            await asyncio.sleep(60)  # Retry in 1 minute on error

# Create FastAPI app
app = FastAPI(
    title="AuditHound API",
    description="Enterprise Security Audit and Compliance Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add middleware
# CORS configuration - restrict origins in production
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:8080").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Health endpoints
@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Basic health check"""
    return HealthResponse(status="healthy", service="audithound-api")

@app.get("/health/detailed")
async def detailed_health_check():
    """Detailed health check with dependencies"""
    return await health_checker.check_health()

@app.get("/ready")
async def readiness_check():
    """Readiness check for Kubernetes"""
    result = await health_checker.check_readiness()
    if result.healthy:
        return {"status": "ready", "checks": result.checks}
    else:
        raise HTTPException(status_code=503, detail="Service not ready")

# Metrics endpoint
@app.get("/metrics")
async def get_metrics():
    """Prometheus metrics endpoint"""
    return metrics.generate_prometheus_metrics()

# Authentication endpoints
@app.post("/auth/login")
async def login(username: str, password: str):
    """Authenticate user and return JWT tokens"""
    try:
        # Check account lockout
        is_locked, locked_until = auth_manager.check_account_lockout(username)
        if is_locked:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account locked until {locked_until.isoformat()}"
            )
        
        # In production, this would query a database
        # For now, we'll simulate user lookup
        user = await get_user_by_username(username)
        if not user or not auth_manager.verify_password(password, user.password_hash):
            auth_manager.record_failed_login(username)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        # Check if user is active
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is disabled"
            )
        
        # Reset failed login attempts
        auth_manager.reset_failed_login_attempts(username)
        
        # Create tokens
        access_token = auth_manager.create_access_token(user)
        refresh_token = auth_manager.create_refresh_token(user)
        
        # Update last login
        await update_user_last_login(user.user_id)
        
        logger.info(f"Successful login for user {username}")
        metrics.record_user_login(user.user_id)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": auth_manager.access_token_expire_minutes * 60,
            "user": {
                "user_id": user.user_id,
                "username": user.username,
                "email": user.email,
                "role": user.role.value,
                "tenant_id": user.tenant_id
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error for {username}: {e}")
        raise HTTPException(status_code=500, detail="Authentication failed")


@app.post("/auth/refresh")
async def refresh_token(refresh_token: str):
    """Refresh access token using refresh token"""
    try:
        # Verify refresh token
        payload = jwt.decode(refresh_token, auth_manager.secret_key, algorithms=[auth_manager.algorithm])
        
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        user = await get_user_by_id(payload["user_id"])
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        
        # Create new access token
        access_token = auth_manager.create_access_token(user)
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": auth_manager.access_token_expire_minutes * 60
        }
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(status_code=500, detail="Token refresh failed")


@app.post("/auth/logout")
async def logout(current_user: TokenData = Depends(get_current_user)):
    """Logout user and revoke session"""
    try:
        auth_manager.revoke_session(current_user.session_id)
        logger.info(f"User {current_user.user_id} logged out")
        return {"message": "Successfully logged out"}
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(status_code=500, detail="Logout failed")


@app.post("/auth/change-password")
async def change_password(
    current_password: str,
    new_password: str,
    current_user: TokenData = Depends(get_current_user)
):
    """Change user password"""
    try:
        user = await get_user_by_id(current_user.user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Verify current password
        if not auth_manager.verify_password(current_password, user.password_hash):
            raise HTTPException(status_code=401, detail="Current password is incorrect")
        
        # Validate new password strength
        is_strong, message = auth_manager.is_password_strong(new_password)
        if not is_strong:
            raise HTTPException(status_code=400, detail=message)
        
        # Update password
        new_password_hash = auth_manager.get_password_hash(new_password)
        await update_user_password(user.user_id, new_password_hash)
        
        # Revoke all user sessions to force re-login
        auth_manager.revoke_all_user_sessions(user.user_id)
        
        logger.info(f"Password changed for user {user.user_id}")
        return {"message": "Password changed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change error: {e}")
        raise HTTPException(status_code=500, detail="Password change failed")


# Placeholder functions for user management (implement with your database)
async def get_user_by_username(username: str) -> Optional[User]:
    """Get user by username from database"""
    # TODO: Implement database query
    return None

async def get_user_by_id(user_id: str) -> Optional[User]:
    """Get user by ID from database"""
    # TODO: Implement database query
    return None

async def update_user_last_login(user_id: str):
    """Update user's last login timestamp"""
    # TODO: Implement database update
    pass

async def update_user_password(user_id: str, password_hash: str):
    """Update user's password hash"""
    # TODO: Implement database update
    pass

# Tenant Management Endpoints
@app.post("/tenants", response_model=TenantResponse)
async def create_tenant(
    tenant_data: TenantCreateRequest,
    current_user: TokenData = Depends(require_admin)
):
    """Create a new tenant"""
    try:
        tenant_id = await tenant_manager.create_tenant(
            name=tenant_data.name,
            config=tenant_data.config
        )
        
        metrics.record_tenant_created(tenant_id)
        logger.info(f"Created tenant: {tenant_id}")
        
        return TenantResponse(tenant_id=tenant_id, status="created")
    
    except Exception as e:
        logger.error(f"Failed to create tenant: {e}")
        raise HTTPException(status_code=500, detail="Failed to create tenant")

@app.get("/tenants/{tenant_id}")
async def get_tenant(
    tenant_id: str,
    current_user: TokenData = Depends(get_current_user)
):
    """Get tenant information"""
    try:
        # Check tenant access
        if not authz_manager.check_tenant_access(current_user, tenant_id):
            raise HTTPException(status_code=403, detail="Access to this tenant is forbidden")
        
        tenant_info = await tenant_manager.get_tenant_info(tenant_id)
        return tenant_info
    
    except Exception as e:
        logger.error(f"Failed to get tenant {tenant_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve tenant information")

# Unified AI-Powered Audit Endpoints
@app.post("/tenants/{tenant_id}/audits/comprehensive", response_model=AuditResponse)
async def start_comprehensive_ai_audit(
    tenant_id: str,
    audit_request: AuditRequest,
    background_tasks: BackgroundTasks,
    current_user: TokenData = Depends(get_current_user)
):
    """Start a comprehensive AI-powered security audit with threat intelligence"""
    try:
        # Check tenant access
        if not auth_manager.check_tenant_access(current_user, tenant_id):
            raise HTTPException(status_code=403, detail="Access to this tenant is forbidden")
        
        # Check permissions
        if not auth_manager.check_permission(current_user, "write:tenant"):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        
        # Create scan record in database
        scan_id = await db_manager.create_security_scan(
            tenant_id=tenant_id,
            scan_data={
                "scan_type": "comprehensive_ai",
                "targets": audit_request.targets,
                "config": audit_request.config,
                "created_by": current_user.user_id
            }
        )
        
        # Start AI-powered analysis in background
        background_tasks.add_task(
            process_ai_audit,
            tenant_id,
            scan_id,
            audit_request.targets,
            audit_request.config
        )
        
        metrics.record_audit_started(tenant_id, "comprehensive_ai")
        logger.info(f"Started comprehensive AI audit {scan_id} for tenant {tenant_id}")
        
        return AuditResponse(audit_id=scan_id, status="started")
    
    except Exception as e:
        logger.error(f"Failed to start comprehensive AI audit for tenant {tenant_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to start audit")

async def process_ai_audit(
    tenant_id: str,
    scan_id: str,
    targets: List[str],
    config: Dict[str, Any]
):
    """Process comprehensive AI audit in background"""
    try:
        logger.info(f"Processing AI audit {scan_id}")
        
        # Update scan status
        await db_manager.update_scan_results(scan_id, {"status": "running"}, "running")
        
        # Perform comprehensive AI analysis
        scan_options = {
            "security_groups": config.get("scan_security_groups", True),
            "encryption": config.get("scan_encryption", True),
            "access_controls": config.get("scan_access_controls", True),
            "network_config": config.get("scan_network", True),
            "compliance": config.get("scan_compliance", True)
        }
        
        analysis_result = await ai_analytics.perform_comprehensive_analysis(
            tenant_id=tenant_id,
            scan_targets=targets,
            scan_options=scan_options
        )
        
        # Store findings in database
        if hasattr(analysis_result, 'threat_intelligence') and 'vulnerability_matches' in analysis_result.threat_intelligence:
            findings = []
            for threat in analysis_result.threat_intelligence['vulnerability_matches']:
                findings.append({
                    "title": threat.get("title", "Threat Intelligence Match"),
                    "description": threat.get("description", ""),
                    "severity": threat.get("severity", "Medium"),
                    "category": "threat_intelligence",
                    "provider": "ai_analytics"
                })
            
            if findings:
                await db_manager.store_findings(scan_id, findings)
        
        # Update scan with final results
        final_results = {
            "overall_score": analysis_result.overall_score,
            "risk_assessment": analysis_result.risk_assessment,
            "recommendations": analysis_result.recommendations,
            "correlations_found": len(analysis_result.correlations),
            "threat_matches": len(analysis_result.threat_intelligence.get('vulnerability_matches', [])),
            "ai_analysis": True
        }
        
        await db_manager.update_scan_results(scan_id, final_results, "completed")
        
        logger.info(f"AI audit {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"AI audit {scan_id} failed: {e}")
        await db_manager.update_scan_results(scan_id, {"error": str(e)}, "failed")

# Legacy Audit Endpoints (maintained for backwards compatibility)
@app.post("/tenants/{tenant_id}/audits", response_model=AuditResponse)
async def start_audit(
    tenant_id: str,
    audit_request: AuditRequest,
    background_tasks: BackgroundTasks,
    current_user: TokenData = Depends(require_permission("write:tenant"))
):
    """Start a new security audit"""
    try:
        # Check tenant access
        if not authz_manager.check_tenant_access(current_user, tenant_id):
            raise HTTPException(status_code=403, detail="Access to this tenant is forbidden")
        
        audit_id = await audit_engine.start_audit(
            tenant_id=tenant_id,
            audit_type=audit_request.type.value,
            targets=audit_request.targets,
            config=audit_request.config
        )
        
        # Start background audit processing
        background_tasks.add_task(
            audit_engine.process_audit,
            tenant_id,
            audit_id
        )
        
        metrics.record_audit_started(tenant_id, audit_request.type.value)
        logger.info(f"Started audit {audit_id} for tenant {tenant_id}")
        
        return AuditResponse(audit_id=audit_id, status="started")
    
    except Exception as e:
        logger.error(f"Failed to start audit for tenant {tenant_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to start audit")

@app.get("/tenants/{tenant_id}/audits/{audit_id}")
async def get_audit_status(
    audit_id: str,
    tenant_id: str = Depends(get_current_tenant)
):
    """Get audit status and results"""
    try:
        status = await audit_engine.get_audit_status(tenant_id, audit_id)
        return status
    
    except Exception as e:
        logger.error(f"Failed to get audit status: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve audit status")

@app.get("/tenants/{tenant_id}/audits")
async def list_audits(
    tenant_id: str = Depends(get_current_tenant),
    limit: int = 50,
    offset: int = 0
):
    """List audits for tenant"""
    try:
        audits = await audit_engine.list_audits(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset
        )
        return {"audits": audits, "total": len(audits)}
    
    except Exception as e:
        logger.error(f"Failed to list audits: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve audits")

# Compliance Endpoints
@app.get("/tenants/{tenant_id}/compliance/frameworks")
async def get_compliance_frameworks(tenant_id: str = Depends(get_current_tenant)):
    """Get available compliance frameworks"""
    try:
        frameworks = await audit_engine.get_compliance_frameworks(tenant_id)
        return {"frameworks": frameworks}
    
    except Exception as e:
        logger.error(f"Failed to get compliance frameworks: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve compliance frameworks")

@app.get("/tenants/{tenant_id}/compliance/{framework}/status")
async def get_compliance_status(
    framework: str,
    tenant_id: str = Depends(get_current_tenant)
):
    """Get compliance status for framework"""
    try:
        status = await audit_engine.get_compliance_status(tenant_id, framework)
        return status
    
    except Exception as e:
        logger.error(f"Failed to get compliance status: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve compliance status")

# Findings Endpoints
@app.get("/tenants/{tenant_id}/findings")
async def get_findings(
    tenant_id: str = Depends(get_current_tenant),
    severity: Optional[FindingSeverity] = None,
    status: Optional[FindingStatus] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Get security findings"""
    try:
        findings = await audit_engine.get_findings(
            tenant_id=tenant_id,
            severity=severity.value if severity else None,
            status=status.value if status else None,
            limit=limit,
            offset=offset
        )
        
        metrics.record_findings_retrieved(tenant_id, len(findings))
        return {"findings": findings, "total": len(findings)}
    
    except Exception as e:
        logger.error(f"Failed to get findings: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve findings")

@app.put("/tenants/{tenant_id}/findings/{finding_id}")
async def update_finding(
    finding_id: str,
    update_data: FindingUpdateRequest,
    tenant_id: str = Depends(get_current_tenant)
):
    """Update a finding"""
    try:
        # Convert Pydantic model to dict, excluding None values
        update_dict = update_data.dict(exclude_none=True)
        # Convert enum values to strings
        if 'status' in update_dict and update_dict['status']:
            update_dict['status'] = update_dict['status'].value if hasattr(update_dict['status'], 'value') else update_dict['status']
        
        result = await audit_engine.update_finding(
            tenant_id=tenant_id,
            finding_id=finding_id,
            update_data=update_dict
        )
        
        metrics.record_finding_updated(tenant_id, finding_id)
        logger.info(f"Updated finding {finding_id} for tenant {tenant_id}")
        
        return result
    
    except Exception as e:
        logger.error(f"Failed to update finding: {e}")
        raise HTTPException(status_code=500, detail="Failed to update finding")

# Reports Endpoints
@app.post("/tenants/{tenant_id}/reports", response_model=ReportResponse)
async def generate_report(
    report_request: ReportRequest,
    background_tasks: BackgroundTasks,
    tenant_id: str = Depends(get_current_tenant)
):
    """Generate a compliance report"""
    try:
        report_id = await audit_engine.generate_report(
            tenant_id=tenant_id,
            report_type=report_request.type.value,
            config=report_request.config
        )
        
        # Generate report in background
        background_tasks.add_task(
            audit_engine.process_report,
            tenant_id,
            report_id
        )
        
        metrics.record_report_generated(tenant_id, report_request.type.value)
        logger.info(f"Started report generation {report_id} for tenant {tenant_id}")
        
        return ReportResponse(report_id=report_id, status="generating")
    
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report")

# Error handlers
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler - logs details but returns generic error"""
    import traceback
    
    # Log full exception details internally
    logger.error(f"Unhandled exception on {request.url}: {exc}")
    logger.error(f"Traceback: {traceback.format_exc()}")
    metrics.record_api_error(type(exc).__name__)
    
    # Return generic error to client (no sensitive details)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error", 
            "message": "An unexpected error occurred. Please contact support if the issue persists."
        }
    )

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="AuditHound API Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--workers", type=int, default=1, help="Number of worker processes")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    
    args = parser.parse_args()
    
    # Configure uvicorn
    config = uvicorn.Config(
        app,
        host=args.host,
        port=args.port,
        workers=args.workers if not args.reload else 1,
        reload=args.reload,
        access_log=True,
        log_config=None  # Use our custom logging
    )
    
    server = uvicorn.Server(config)
    server.run()

if __name__ == "__main__":
    main()