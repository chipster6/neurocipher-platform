#!/usr/bin/env python3
"""
Authentication and Authorization Module for AuditHound
JWT-based authentication with proper security controls
"""

import os
import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
import secrets
import time
from dataclasses import dataclass, asdict
from enum import Enum


class UserRole(str, Enum):
    """User roles for authorization"""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    TENANT_ADMIN = "tenant_admin"


@dataclass
class TokenData:
    """Token payload data structure"""
    user_id: str
    tenant_id: str
    role: UserRole
    permissions: list
    issued_at: datetime
    expires_at: datetime
    session_id: str


@dataclass
class User:
    """User data structure"""
    user_id: str
    username: str
    email: str
    tenant_id: str
    role: UserRole
    is_active: bool
    last_login: Optional[datetime] = None
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None
    requires_password_change: bool = False


class AuthenticationManager:
    """Manages authentication and JWT tokens"""
    
    def __init__(self):
        self.secret_key = os.getenv("JWT_SECRET_KEY")
        if not self.secret_key:
            raise ValueError("JWT_SECRET_KEY environment variable is required")
        
        self.algorithm = "HS256"
        self.access_token_expire_minutes = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
        self.refresh_token_expire_days = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
        self.max_login_attempts = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
        self.lockout_duration_minutes = int(os.getenv("LOCKOUT_DURATION_MINUTES", "15"))
        
        # Password hashing
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        # Rate limiting storage (in production, use Redis)
        self.login_attempts = {}
        self.active_sessions = {}
        
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a plain password against hashed password"""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Hash a password"""
        return self.pwd_context.hash(password)
    
    def is_password_strong(self, password: str) -> tuple[bool, str]:
        """Check if password meets security requirements"""
        if len(password) < 12:
            return False, "Password must be at least 12 characters long"
        
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"
        
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            return False, "Password must contain at least one special character"
        
        return True, "Password meets requirements"
    
    def check_account_lockout(self, username: str) -> tuple[bool, Optional[datetime]]:
        """Check if account is locked due to failed login attempts"""
        if username not in self.login_attempts:
            return False, None
        
        attempts_data = self.login_attempts[username]
        if attempts_data["count"] >= self.max_login_attempts:
            lockout_until = attempts_data["locked_until"]
            if lockout_until and datetime.utcnow() < lockout_until:
                return True, lockout_until
            else:
                # Lockout period expired, reset attempts
                del self.login_attempts[username]
                return False, None
        
        return False, None
    
    def record_failed_login(self, username: str):
        """Record a failed login attempt"""
        if username not in self.login_attempts:
            self.login_attempts[username] = {"count": 0, "locked_until": None}
        
        self.login_attempts[username]["count"] += 1
        
        if self.login_attempts[username]["count"] >= self.max_login_attempts:
            lockout_until = datetime.utcnow() + timedelta(minutes=self.lockout_duration_minutes)
            self.login_attempts[username]["locked_until"] = lockout_until
    
    def reset_failed_login_attempts(self, username: str):
        """Reset failed login attempts after successful login"""
        if username in self.login_attempts:
            del self.login_attempts[username]
    
    def create_access_token(self, user: User) -> str:
        """Create JWT access token"""
        session_id = secrets.token_urlsafe(32)
        issued_at = datetime.utcnow()
        expires_at = issued_at + timedelta(minutes=self.access_token_expire_minutes)
        
        # Define permissions based on role
        permissions = self._get_role_permissions(user.role)
        
        token_data = TokenData(
            user_id=user.user_id,
            tenant_id=user.tenant_id,
            role=user.role,
            permissions=permissions,
            issued_at=issued_at,
            expires_at=expires_at,
            session_id=session_id
        )
        
        # Store active session
        self.active_sessions[session_id] = {
            "user_id": user.user_id,
            "tenant_id": user.tenant_id,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "last_activity": issued_at
        }
        
        # Create JWT payload
        payload = {
            "user_id": user.user_id,
            "tenant_id": user.tenant_id,
            "role": user.role.value,
            "permissions": permissions,
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "session_id": session_id,
            "type": "access"
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def create_refresh_token(self, user: User) -> str:
        """Create JWT refresh token"""
        issued_at = datetime.utcnow()
        expires_at = issued_at + timedelta(days=self.refresh_token_expire_days)
        
        payload = {
            "user_id": user.user_id,
            "tenant_id": user.tenant_id,
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "type": "refresh"
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str) -> TokenData:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check token type
            if payload.get("type") != "access":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type"
                )
            
            # Check if session is still active
            session_id = payload.get("session_id")
            if session_id not in self.active_sessions:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session expired or invalid"
                )
            
            # Update last activity
            self.active_sessions[session_id]["last_activity"] = datetime.utcnow()
            
            # Create TokenData object
            token_data = TokenData(
                user_id=payload["user_id"],
                tenant_id=payload["tenant_id"],
                role=UserRole(payload["role"]),
                permissions=payload["permissions"],
                issued_at=datetime.fromtimestamp(payload["iat"]),
                expires_at=datetime.fromtimestamp(payload["exp"]),
                session_id=session_id
            )
            
            return token_data
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
    
    def revoke_session(self, session_id: str):
        """Revoke a specific session"""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
    
    def revoke_all_user_sessions(self, user_id: str):
        """Revoke all sessions for a user"""
        sessions_to_remove = []
        for session_id, session_data in self.active_sessions.items():
            if session_data["user_id"] == user_id:
                sessions_to_remove.append(session_id)
        
        for session_id in sessions_to_remove:
            del self.active_sessions[session_id]
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        current_time = datetime.utcnow()
        expired_sessions = []
        
        for session_id, session_data in self.active_sessions.items():
            if current_time > session_data["expires_at"]:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.active_sessions[session_id]
    
    def _get_role_permissions(self, role: UserRole) -> list:
        """Get permissions for a role"""
        role_permissions = {
            UserRole.ADMIN: [
                "read:all", "write:all", "delete:all", "admin:all"
            ],
            UserRole.TENANT_ADMIN: [
                "read:tenant", "write:tenant", "delete:tenant", "admin:tenant"
            ],
            UserRole.ANALYST: [
                "read:tenant", "write:findings", "read:reports"
            ],
            UserRole.VIEWER: [
                "read:tenant", "read:reports"
            ]
        }
        
        return role_permissions.get(role, [])


class AuthorizationManager:
    """Manages authorization and permission checking"""
    
    def __init__(self):
        pass
    
    def check_permission(self, token_data: TokenData, required_permission: str) -> bool:
        """Check if user has required permission"""
        return required_permission in token_data.permissions
    
    def check_tenant_access(self, token_data: TokenData, tenant_id: str) -> bool:
        """Check if user can access specific tenant"""
        # Admin can access all tenants
        if token_data.role == UserRole.ADMIN:
            return True
        
        # Other users can only access their own tenant
        return token_data.tenant_id == tenant_id
    
    def require_permission(self, permission: str):
        """Decorator factory for permission checking"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                # This would be used with FastAPI dependency injection
                # Implementation depends on how it's integrated with FastAPI
                pass
            return wrapper
        return decorator


# Global instances
auth_manager = AuthenticationManager()
authz_manager = AuthorizationManager()

# FastAPI security scheme
security = HTTPBearer()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> TokenData:
    """FastAPI dependency to get current authenticated user"""
    token = credentials.credentials
    token_data = auth_manager.verify_token(token)
    return token_data


async def require_admin(current_user: TokenData = Depends(get_current_user)) -> TokenData:
    """FastAPI dependency that requires admin role"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


async def require_tenant_access(tenant_id: str, current_user: TokenData = Depends(get_current_user)) -> TokenData:
    """FastAPI dependency that requires access to specific tenant"""
    if not authz_manager.check_tenant_access(current_user, tenant_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access to this tenant is forbidden"
        )
    return current_user


def require_permission(permission: str):
    """FastAPI dependency factory for permission checking"""
    async def permission_checker(current_user: TokenData = Depends(get_current_user)) -> TokenData:
        if not authz_manager.check_permission(current_user, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required"
            )
        return current_user
    return permission_checker