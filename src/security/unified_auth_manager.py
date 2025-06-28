"""
Unified Authentication Manager
Enhanced JWT-based authentication with multi-tenant support and enterprise security features
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import uuid
import hashlib
import secrets
from dataclasses import dataclass
import re
import json

import bcrypt
import jwt
from passlib.context import CryptContext
from sqlalchemy import text

from ..persistence.unified_db_manager import UnifiedDatabaseManager

logger = logging.getLogger(__name__)

@dataclass
class TokenData:
    """Token payload data"""
    user_id: str
    username: str
    tenant_id: str
    role: str
    session_id: str
    permissions: List[str]
    expires_at: datetime

@dataclass
class User:
    """User model"""
    user_id: str
    username: str
    email: str
    tenant_id: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None

class UnifiedAuthManager:
    """
    Unified Authentication Manager
    Provides JWT-based authentication with enterprise security features
    """
    
    def __init__(self, 
                 secret_key: str,
                 db_manager: UnifiedDatabaseManager,
                 algorithm: str = "HS256",
                 access_token_expire_minutes: int = 30,
                 refresh_token_expire_days: int = 7):
        
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self.db_manager = db_manager
        
        # Password hashing
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        # Session management
        self.active_sessions: Dict[str, TokenData] = {}
        self.failed_login_attempts: Dict[str, List[datetime]] = {}
        self.account_lockouts: Dict[str, datetime] = {}
        
        # Security settings
        self.max_failed_attempts = 5
        self.lockout_duration_minutes = 15
        self.password_min_length = 8
        self.require_special_chars = True
        
    # Password Management
    def get_password_hash(self, password: str) -> str:
        """Hash a password using bcrypt"""
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def is_password_strong(self, password: str) -> Tuple[bool, str]:
        """Check if password meets security requirements"""
        if len(password) < self.password_min_length:
            return False, f"Password must be at least {self.password_min_length} characters long"
        
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r"\d", password):
            return False, "Password must contain at least one number"
        
        if self.require_special_chars and not re.search(r"[!@#$%^&*()_+=\-\[\]{};':\"\\|,.<>/?]", password):
            return False, "Password must contain at least one special character"
        
        # Check for common weak patterns
        weak_patterns = ['123', 'abc', 'qwerty', 'password', 'admin']
        password_lower = password.lower()
        for pattern in weak_patterns:
            if pattern in password_lower:
                return False, f"Password contains weak pattern: {pattern}"
        
        return True, "Password meets security requirements"
    
    # Token Management
    def create_access_token(self, user: User, permissions: Optional[List[str]] = None) -> str:
        """Create JWT access token"""
        session_id = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        payload = {
            "user_id": user.user_id,
            "username": user.username,
            "tenant_id": user.tenant_id,
            "role": user.role,
            "session_id": session_id,
            "permissions": permissions or self._get_role_permissions(user.role),
            "exp": expires_at,
            "iat": datetime.utcnow(),
            "type": "access"
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
        # Store session data
        token_data = TokenData(
            user_id=user.user_id,
            username=user.username,
            tenant_id=user.tenant_id,
            role=user.role,
            session_id=session_id,
            permissions=payload["permissions"],
            expires_at=expires_at
        )
        self.active_sessions[session_id] = token_data
        
        return token
    
    def create_refresh_token(self, user: User) -> str:
        """Create JWT refresh token"""
        expires_at = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
        
        payload = {
            "user_id": user.user_id,
            "exp": expires_at,
            "iat": datetime.utcnow(),
            "type": "refresh"
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str) -> Optional[TokenData]:
        """Verify JWT token and return token data"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            if payload.get("type") != "access":
                return None
            
            session_id = payload.get("session_id")
            if not session_id or session_id not in self.active_sessions:
                return None
            
            token_data = self.active_sessions[session_id]
            
            # Check if token is expired
            if datetime.utcnow() > token_data.expires_at:
                self.revoke_session(session_id)
                return None
            
            return token_data
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.JWTError as e:
            logger.warning(f"Invalid token: {e}")
            return None
    
    # Session Management
    def revoke_session(self, session_id: str):
        """Revoke a specific session"""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
            logger.info(f"Session revoked: {session_id}")
    
    def revoke_all_user_sessions(self, user_id: str):
        """Revoke all sessions for a specific user"""
        sessions_to_revoke = [
            session_id for session_id, token_data in self.active_sessions.items()
            if token_data.user_id == user_id
        ]
        
        for session_id in sessions_to_revoke:
            self.revoke_session(session_id)
        
        logger.info(f"All sessions revoked for user: {user_id}")
    
    async def store_session_in_db(self, session_id: str, user_id: str, ip_address: str, user_agent: str):
        """Store session information in database"""
        try:
            expires_at = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
            
            async with self.db_manager.get_session() as session:
                await session.execute(
                    text("""
                        INSERT INTO user_sessions (session_id, user_id, expires_at, ip_address, user_agent)
                        VALUES (:session_id, :user_id, :expires_at, :ip_address, :user_agent)
                    """),
                    {
                        "session_id": session_id,
                        "user_id": user_id,
                        "expires_at": expires_at,
                        "ip_address": ip_address,
                        "user_agent": user_agent
                    }
                )
                await session.commit()
                
        except Exception as e:
            logger.error(f"Failed to store session in database: {e}")
    
    # Account Lockout Management
    def record_failed_login(self, username: str):
        """Record a failed login attempt"""
        now = datetime.utcnow()
        
        if username not in self.failed_login_attempts:
            self.failed_login_attempts[username] = []
        
        # Remove attempts older than 1 hour
        one_hour_ago = now - timedelta(hours=1)
        self.failed_login_attempts[username] = [
            attempt for attempt in self.failed_login_attempts[username]
            if attempt > one_hour_ago
        ]
        
        # Add current attempt
        self.failed_login_attempts[username].append(now)
        
        # Check if account should be locked
        if len(self.failed_login_attempts[username]) >= self.max_failed_attempts:
            lockout_until = now + timedelta(minutes=self.lockout_duration_minutes)
            self.account_lockouts[username] = lockout_until
            logger.warning(f"Account locked due to failed login attempts: {username}")
    
    def reset_failed_login_attempts(self, username: str):
        """Reset failed login attempts for a user"""
        if username in self.failed_login_attempts:
            del self.failed_login_attempts[username]
        if username in self.account_lockouts:
            del self.account_lockouts[username]
    
    def check_account_lockout(self, username: str) -> Tuple[bool, Optional[datetime]]:
        """Check if account is locked out"""
        if username in self.account_lockouts:
            lockout_until = self.account_lockouts[username]
            if datetime.utcnow() < lockout_until:
                return True, lockout_until
            else:
                # Lockout expired
                del self.account_lockouts[username]
        
        return False, None
    
    # User Management
    async def create_user(self, 
                         username: str,
                         email: str,
                         password: str,
                         tenant_id: str,
                         role: str = "user") -> str:
        """Create a new user"""
        try:
            # Validate password strength
            is_strong, message = self.is_password_strong(password)
            if not is_strong:
                raise ValueError(f"Password validation failed: {message}")
            
            # Hash password
            password_hash = self.get_password_hash(password)
            
            # Create user in database
            user_id = str(uuid.uuid4())
            
            async with self.db_manager.get_session() as session:
                await session.execute(
                    text("""
                        INSERT INTO users (user_id, tenant_id, username, email, password_hash, role)
                        VALUES (:user_id, :tenant_id, :username, :email, :password_hash, :role)
                    """),
                    {
                        "user_id": user_id,
                        "tenant_id": tenant_id,
                        "username": username,
                        "email": email,
                        "password_hash": password_hash,
                        "role": role
                    }
                )
                await session.commit()
            
            logger.info(f"User created: {username}")
            return user_id
            
        except Exception as e:
            logger.error(f"Failed to create user: {e}")
            raise
    
    async def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        try:
            async with self.db_manager.get_session() as session:
                result = await session.execute(
                    text("""
                        SELECT user_id, username, email, tenant_id, password_hash, role, 
                               is_active, created_at, last_login
                        FROM users 
                        WHERE username = :username AND is_active = true
                    """),
                    {"username": username}
                )
                
                row = result.fetchone()
                if row:
                    return User(
                        user_id=row[0],
                        username=row[1],
                        email=row[2],
                        tenant_id=row[3],
                        role=row[5],
                        is_active=row[6],
                        created_at=row[7],
                        last_login=row[8]
                    )
                
                return None
                
        except Exception as e:
            logger.error(f"Failed to get user by username: {e}")
            return None
    
    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        try:
            async with self.db_manager.get_session() as session:
                result = await session.execute(
                    text("""
                        SELECT user_id, username, email, tenant_id, role, 
                               is_active, created_at, last_login
                        FROM users 
                        WHERE user_id = :user_id AND is_active = true
                    """),
                    {"user_id": user_id}
                )
                
                row = result.fetchone()
                if row:
                    return User(
                        user_id=row[0],
                        username=row[1],
                        email=row[2],
                        tenant_id=row[3],
                        role=row[4],
                        is_active=row[5],
                        created_at=row[6],
                        last_login=row[7]
                    )
                
                return None
                
        except Exception as e:
            logger.error(f"Failed to get user by ID: {e}")
            return None
    
    async def update_user_last_login(self, user_id: str):
        """Update user's last login timestamp"""
        try:
            async with self.db_manager.get_session() as session:
                await session.execute(
                    text("""
                        UPDATE users 
                        SET last_login = :last_login 
                        WHERE user_id = :user_id
                    """),
                    {
                        "last_login": datetime.utcnow(),
                        "user_id": user_id
                    }
                )
                await session.commit()
                
        except Exception as e:
            logger.error(f"Failed to update last login: {e}")
    
    async def change_password(self, user_id: str, current_password: str, new_password: str) -> bool:
        """Change user password"""
        try:
            # Get current user
            user = await self.get_user_by_id(user_id)
            if not user:
                return False
            
            # Get current password hash
            async with self.db_manager.get_session() as session:
                result = await session.execute(
                    text("SELECT password_hash FROM users WHERE user_id = :user_id"),
                    {"user_id": user_id}
                )
                row = result.fetchone()
                if not row:
                    return False
                
                # Verify current password
                if not self.verify_password(current_password, row[0]):
                    return False
                
                # Validate new password
                is_strong, message = self.is_password_strong(new_password)
                if not is_strong:
                    raise ValueError(f"New password validation failed: {message}")
                
                # Update password
                new_password_hash = self.get_password_hash(new_password)
                await session.execute(
                    text("""
                        UPDATE users 
                        SET password_hash = :password_hash, updated_at = :updated_at
                        WHERE user_id = :user_id
                    """),
                    {
                        "password_hash": new_password_hash,
                        "updated_at": datetime.utcnow(),
                        "user_id": user_id
                    }
                )
                await session.commit()
            
            # Revoke all user sessions to force re-login
            self.revoke_all_user_sessions(user_id)
            
            logger.info(f"Password changed for user: {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to change password: {e}")
            return False
    
    # Permission Management
    def _get_role_permissions(self, role: str) -> List[str]:
        """Get permissions for a role"""
        role_permissions = {
            "admin": [
                "read:all", "write:all", "delete:all",
                "manage:users", "manage:tenants", "manage:system"
            ],
            "tenant_admin": [
                "read:tenant", "write:tenant", "delete:tenant",
                "manage:users"
            ],
            "user": [
                "read:tenant", "write:tenant"
            ],
            "viewer": [
                "read:tenant"
            ]
        }
        
        return role_permissions.get(role, ["read:tenant"])
    
    def check_permission(self, token_data: TokenData, required_permission: str) -> bool:
        """Check if user has required permission"""
        # Admin has all permissions
        if "read:all" in token_data.permissions:
            return True
        
        # Check specific permission
        if required_permission in token_data.permissions:
            return True
        
        # Check wildcard permissions
        permission_parts = required_permission.split(":")
        if len(permission_parts) == 2:
            action, resource = permission_parts
            wildcard_permission = f"{action}:all"
            if wildcard_permission in token_data.permissions:
                return True
        
        return False
    
    def check_tenant_access(self, token_data: TokenData, tenant_id: str) -> bool:
        """Check if user has access to a specific tenant"""
        # Admin can access all tenants
        if "read:all" in token_data.permissions:
            return True
        
        # User can only access their own tenant
        return token_data.tenant_id == tenant_id
    
    # API Key Management
    async def create_api_key(self, 
                            user_id: str,
                            key_name: str,
                            permissions: List[str],
                            expires_at: Optional[datetime] = None) -> Tuple[str, str]:
        """Create API key for user"""
        try:
            key_id = str(uuid.uuid4())
            raw_key = secrets.token_urlsafe(32)
            key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            
            async with self.db_manager.get_session() as session:
                # Get user's tenant_id
                user_result = await session.execute(
                    text("SELECT tenant_id FROM users WHERE user_id = :user_id"),
                    {"user_id": user_id}
                )
                user_row = user_result.fetchone()
                if not user_row:
                    raise ValueError("User not found")
                
                tenant_id = user_row[0]
                
                await session.execute(
                    text("""
                        INSERT INTO api_keys (key_id, tenant_id, user_id, key_name, key_hash, permissions, expires_at)
                        VALUES (:key_id, :tenant_id, :user_id, :key_name, :key_hash, :permissions, :expires_at)
                    """),
                    {
                        "key_id": key_id,
                        "tenant_id": tenant_id,
                        "user_id": user_id,
                        "key_name": key_name,
                        "key_hash": key_hash,
                        "permissions": json.dumps(permissions),
                        "expires_at": expires_at
                    }
                )
                await session.commit()
            
            logger.info(f"API key created: {key_name} for user {user_id}")
            return key_id, raw_key
            
        except Exception as e:
            logger.error(f"Failed to create API key: {e}")
            raise
    
    async def verify_api_key(self, api_key: str) -> Optional[TokenData]:
        """Verify API key and return token data"""
        try:
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            async with self.db_manager.get_session() as session:
                result = await session.execute(
                    text("""
                        SELECT ak.user_id, ak.permissions, ak.expires_at, ak.tenant_id,
                               u.username, u.role, u.is_active
                        FROM api_keys ak
                        JOIN users u ON ak.user_id = u.user_id
                        WHERE ak.key_hash = :key_hash AND ak.is_active = true AND u.is_active = true
                    """),
                    {"key_hash": key_hash}
                )
                
                row = result.fetchone()
                if row:
                    user_id, permissions_json, expires_at, tenant_id, username, role, is_active = row
                    
                    # Check if key is expired
                    if expires_at and datetime.utcnow() > expires_at:
                        return None
                    
                    permissions = json.loads(permissions_json) if permissions_json else []
                    
                    # Update last used timestamp
                    await session.execute(
                        text("""
                            UPDATE api_keys 
                            SET last_used = :last_used 
                            WHERE key_hash = :key_hash
                        """),
                        {
                            "last_used": datetime.utcnow(),
                            "key_hash": key_hash
                        }
                    )
                    await session.commit()
                    
                    return TokenData(
                        user_id=user_id,
                        username=username,
                        tenant_id=tenant_id,
                        role=role,
                        session_id=f"api_key_{key_hash[:8]}",
                        permissions=permissions,
                        expires_at=expires_at or datetime.utcnow() + timedelta(days=365)
                    )
                
                return None
                
        except Exception as e:
            logger.error(f"Failed to verify API key: {e}")
            return None
    
    # Cleanup and Maintenance
    async def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        now = datetime.utcnow()
        expired_sessions = [
            session_id for session_id, token_data in self.active_sessions.items()
            if now > token_data.expires_at
        ]
        
        for session_id in expired_sessions:
            self.revoke_session(session_id)
        
        # Clean up database sessions
        try:
            async with self.db_manager.get_session() as session:
                await session.execute(
                    text("DELETE FROM user_sessions WHERE expires_at < :now"),
                    {"now": now}
                )
                await session.commit()
        except Exception as e:
            logger.error(f"Failed to cleanup database sessions: {e}")
        
        logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
    
    async def get_active_session_count(self) -> int:
        """Get count of active sessions"""
        return len(self.active_sessions)
    
    async def get_user_session_info(self, user_id: str) -> List[Dict[str, Any]]:
        """Get session information for a user"""
        sessions = []
        for session_id, token_data in self.active_sessions.items():
            if token_data.user_id == user_id:
                sessions.append({
                    "session_id": session_id,
                    "expires_at": token_data.expires_at.isoformat(),
                    "permissions": token_data.permissions
                })
        
        return sessions