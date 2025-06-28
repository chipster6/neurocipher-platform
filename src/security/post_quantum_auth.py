"""
Post-Quantum Enhanced Authentication Manager
Extends the unified authentication system with quantum-resistant cryptographic capabilities
Provides secure token generation, encryption, and verification using post-quantum algorithms
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union
import uuid
import hashlib
import secrets
from dataclasses import dataclass, asdict
import json
import os

from .unified_auth_manager import UnifiedAuthManager, TokenData, User
from .post_quantum_crypto import get_pq_suite, pq_encrypt, pq_decrypt, pq_sign_data, pq_verify_data, pq_create_token, pq_verify_token
from ..persistence.unified_db_manager import UnifiedDatabaseManager

logger = logging.getLogger(__name__)

@dataclass
class PostQuantumTokenData(TokenData):
    """Enhanced token data with post-quantum security"""
    pq_encrypted: bool = False
    signature_algorithm: str = "dilithium_5"
    encryption_algorithm: str = "kyber_1024"
    quantum_resistant: bool = True

@dataclass
class SecureSessionData:
    """Post-quantum secure session data"""
    session_id: str
    user_id: str
    tenant_id: str
    encrypted_payload: Dict[str, str]
    signature_info: Dict[str, str]
    expires_at: datetime
    created_at: datetime
    last_activity: datetime
    quantum_secured: bool = True

class PostQuantumAuthManager(UnifiedAuthManager):
    """
    Enhanced Authentication Manager with Post-Quantum Cryptography
    Extends UnifiedAuthManager with quantum-resistant security features
    """
    
    def __init__(self, 
                 secret_key: str,
                 db_manager: UnifiedDatabaseManager,
                 algorithm: str = "HS256",
                 access_token_expire_minutes: int = 30,
                 refresh_token_expire_days: int = 7,
                 enable_pq_crypto: bool = True):
        
        super().__init__(secret_key, db_manager, algorithm, access_token_expire_minutes, refresh_token_expire_days)
        
        self.enable_pq_crypto = enable_pq_crypto
        self.pq_suite = None
        
        # Post-quantum specific settings
        self.pq_token_expire_hours = 24
        self.secure_sessions: Dict[str, SecureSessionData] = {}
        
        # Initialize post-quantum crypto suite
        if self.enable_pq_crypto:
            try:
                self.pq_suite = get_pq_suite()
                self.logger.info("Post-quantum cryptography enabled for authentication")
            except Exception as e:
                self.logger.error(f"Failed to initialize post-quantum crypto: {e}")
                self.enable_pq_crypto = False
        
        # Enhanced security settings for post-quantum era
        self.password_min_length = 16  # Increased for quantum resistance
        self.require_mfa = True
        self.quantum_secure_sessions = True
    
    # ========== Post-Quantum Token Management ==========
    
    def create_pq_access_token(self, user: User, permissions: Optional[List[str]] = None) -> Dict[str, str]:
        """Create quantum-resistant access token"""
        try:
            if not self.enable_pq_crypto or not self.pq_suite:
                # Fallback to regular token
                return {"token": self.create_access_token(user, permissions), "type": "standard"}
            
            session_id = str(uuid.uuid4())
            expires_at = datetime.utcnow() + timedelta(hours=self.pq_token_expire_hours)
            
            # Create enhanced payload with post-quantum security
            payload = {
                "user_id": user.user_id,
                "username": user.username,
                "tenant_id": user.tenant_id,
                "role": user.role,
                "session_id": session_id,
                "permissions": permissions or self._get_role_permissions(user.role),
                "iat": datetime.utcnow().isoformat(),
                "exp": expires_at.isoformat(),
                "type": "pq_access",
                "quantum_secured": True,
                "security_level": 5
            }
            
            # Create quantum-resistant secure token
            pq_token = pq_create_token(payload, self.pq_token_expire_hours)
            
            # Store secure session data
            secure_session = SecureSessionData(
                session_id=session_id,
                user_id=user.user_id,
                tenant_id=user.tenant_id,
                encrypted_payload=pq_token['encrypted_token'],
                signature_info=pq_token['signature'],
                expires_at=expires_at,
                created_at=datetime.utcnow(),
                last_activity=datetime.utcnow(),
                quantum_secured=True
            )
            
            self.secure_sessions[session_id] = secure_session
            
            return {
                "token": json.dumps(pq_token),
                "type": "post_quantum",
                "session_id": session_id,
                "expires_at": expires_at.isoformat(),
                "algorithm": "CRYSTALS-Kyber-1024+CRYSTALS-Dilithium-5"
            }
            
        except Exception as e:
            self.logger.error(f"Failed to create post-quantum token: {e}")
            # Fallback to standard token
            return {"token": self.create_access_token(user, permissions), "type": "standard"}
    
    def verify_pq_token(self, token_str: str) -> Optional[PostQuantumTokenData]:
        """Verify quantum-resistant token"""
        try:
            if not self.enable_pq_crypto or not self.pq_suite:
                return None
            
            # Parse token
            token_package = json.loads(token_str)
            
            # Verify and decrypt token
            payload = pq_verify_token(token_package)
            if not payload:
                return None
            
            # Validate session
            session_id = payload.get("session_id")
            if not session_id or session_id not in self.secure_sessions:
                return None
            
            secure_session = self.secure_sessions[session_id]
            
            # Check expiration
            if datetime.utcnow() > secure_session.expires_at:
                self.revoke_pq_session(session_id)
                return None
            
            # Update last activity
            secure_session.last_activity = datetime.utcnow()
            
            # Create enhanced token data
            token_data = PostQuantumTokenData(
                user_id=payload["user_id"],
                username=payload["username"],
                tenant_id=payload["tenant_id"],
                role=payload["role"],
                session_id=session_id,
                permissions=payload["permissions"],
                expires_at=datetime.fromisoformat(payload["exp"]),
                pq_encrypted=True,
                signature_algorithm="dilithium_5",
                encryption_algorithm="kyber_1024",
                quantum_resistant=True
            )
            
            return token_data
            
        except Exception as e:
            self.logger.error(f"Post-quantum token verification failed: {e}")
            return None
    
    def revoke_pq_session(self, session_id: str):
        """Revoke post-quantum secure session"""
        if session_id in self.secure_sessions:
            del self.secure_sessions[session_id]
            self.logger.info(f"Post-quantum session revoked: {session_id}")
    
    def revoke_all_pq_user_sessions(self, user_id: str):
        """Revoke all post-quantum sessions for a user"""
        sessions_to_revoke = [
            session_id for session_id, session_data in self.secure_sessions.items()
            if session_data.user_id == user_id
        ]
        
        for session_id in sessions_to_revoke:
            self.revoke_pq_session(session_id)
        
        self.logger.info(f"All post-quantum sessions revoked for user: {user_id}")
    
    # ========== Enhanced Password Security ==========
    
    def is_password_quantum_resistant(self, password: str) -> Tuple[bool, str]:
        """Check if password meets quantum-era security requirements"""
        # First check basic requirements
        is_strong, message = self.is_password_strong(password)
        if not is_strong:
            return is_strong, message
        
        # Additional quantum-era requirements
        if len(password) < 16:
            return False, "Password must be at least 16 characters for quantum resistance"
        
        # Check for sufficient entropy
        unique_chars = len(set(password))
        if unique_chars < 10:
            return False, "Password must contain at least 10 unique characters"
        
        # Check for mixed character types
        char_types = 0
        if any(c.isupper() for c in password):
            char_types += 1
        if any(c.islower() for c in password):
            char_types += 1
        if any(c.isdigit() for c in password):
            char_types += 1
        if any(c in "!@#$%^&*()_+=[]{}|;:,.<>?~`" for c in password):
            char_types += 1
        
        if char_types < 4:
            return False, "Password must contain uppercase, lowercase, numbers, and special characters"
        
        return True, "Password meets quantum-resistant security requirements"
    
    async def create_quantum_secure_user(self, 
                                       username: str,
                                       email: str,
                                       password: str,
                                       tenant_id: str,
                                       role: str = "user") -> str:
        """Create user with quantum-resistant password requirements"""
        try:
            # Enhanced password validation
            is_quantum_resistant, message = self.is_password_quantum_resistant(password)
            if not is_quantum_resistant:
                raise ValueError(f"Password validation failed: {message}")
            
            # Use enhanced password hashing with higher cost
            password_hash = self.get_enhanced_password_hash(password)
            
            # Create user in database with quantum-secure flag
            user_id = str(uuid.uuid4())
            
            async with self.db_manager.get_session() as session:
                await session.execute(
                    text("""
                        INSERT INTO users (user_id, tenant_id, username, email, password_hash, role, quantum_secure)
                        VALUES (:user_id, :tenant_id, :username, :email, :password_hash, :role, :quantum_secure)
                    """),
                    {
                        "user_id": user_id,
                        "tenant_id": tenant_id,
                        "username": username,
                        "email": email,
                        "password_hash": password_hash,
                        "role": role,
                        "quantum_secure": True
                    }
                )
                await session.commit()
            
            self.logger.info(f"Quantum-secure user created: {username}")
            return user_id
            
        except Exception as e:
            self.logger.error(f"Failed to create quantum-secure user: {e}")
            raise
    
    def get_enhanced_password_hash(self, password: str) -> str:
        """Enhanced password hashing for quantum resistance"""
        import bcrypt
        # Use higher cost factor for quantum resistance
        cost_factor = 15  # Increased from default 12
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=cost_factor)).decode('utf-8')
    
    # ========== Secure Data Operations ==========
    
    async def encrypt_sensitive_data(self, data: Union[str, Dict[str, Any]], context: str = "user_data") -> Dict[str, str]:
        """Encrypt sensitive data with post-quantum encryption"""
        try:
            if not self.enable_pq_crypto:
                # Fallback to base64 encoding (not recommended for production)
                import base64
                if isinstance(data, dict):
                    data = json.dumps(data)
                return {"data": base64.b64encode(data.encode()).decode(), "encrypted": False}
            
            if isinstance(data, dict):
                data = json.dumps(data)
            
            encrypted_data = pq_encrypt(data, context)
            return {"data": json.dumps(encrypted_data), "encrypted": True}
            
        except Exception as e:
            self.logger.error(f"Data encryption failed: {e}")
            raise
    
    async def decrypt_sensitive_data(self, encrypted_package: Dict[str, str]) -> Union[str, Dict[str, Any]]:
        """Decrypt sensitive data with post-quantum decryption"""
        try:
            if not encrypted_package.get("encrypted", True):
                # Handle unencrypted fallback
                import base64
                return base64.b64decode(encrypted_package["data"]).decode()
            
            encrypted_data = json.loads(encrypted_package["data"])
            decrypted_bytes = pq_decrypt(encrypted_data)
            decrypted_str = decrypted_bytes.decode('utf-8')
            
            # Try to parse as JSON, otherwise return as string
            try:
                return json.loads(decrypted_str)
            except json.JSONDecodeError:
                return decrypted_str
            
        except Exception as e:
            self.logger.error(f"Data decryption failed: {e}")
            raise
    
    # ========== Audit and Compliance ==========
    
    async def log_quantum_security_event(self, event_type: str, user_id: str, details: Dict[str, Any]):
        """Log quantum security events for compliance"""
        try:
            event_data = {
                "event_type": event_type,
                "user_id": user_id,
                "timestamp": datetime.utcnow().isoformat(),
                "quantum_secured": self.enable_pq_crypto,
                "details": details
            }
            
            # Encrypt the audit log entry
            encrypted_event = await self.encrypt_sensitive_data(event_data, "audit_log")
            
            # Sign for integrity
            signature_info = pq_sign_data(json.dumps(event_data), 'dilithium')
            
            async with self.db_manager.get_session() as session:
                await session.execute(
                    text("""
                        INSERT INTO quantum_audit_log (event_id, encrypted_data, signature_info, created_at)
                        VALUES (:event_id, :encrypted_data, :signature_info, :created_at)
                    """),
                    {
                        "event_id": str(uuid.uuid4()),
                        "encrypted_data": encrypted_event["data"],
                        "signature_info": json.dumps(signature_info),
                        "created_at": datetime.utcnow()
                    }
                )
                await session.commit()
            
        except Exception as e:
            self.logger.error(f"Failed to log quantum security event: {e}")
    
    async def get_quantum_readiness_status(self) -> Dict[str, Any]:
        """Get quantum readiness status for compliance reporting"""
        try:
            pq_status = self.pq_suite.get_system_status() if self.pq_suite else {"post_quantum_enabled": False}
            
            # Count quantum-secured users
            async with self.db_manager.get_session() as session:
                result = await session.execute(
                    text("""
                        SELECT 
                            COUNT(*) as total_users,
                            COUNT(CASE WHEN quantum_secure = true THEN 1 END) as quantum_users
                        FROM users WHERE is_active = true
                    """)
                )
                user_stats = result.fetchone()
            
            # Count active quantum sessions
            quantum_sessions = len([s for s in self.secure_sessions.values() if s.quantum_secured])
            
            return {
                "quantum_cryptography": pq_status,
                "authentication": {
                    "post_quantum_enabled": self.enable_pq_crypto,
                    "total_users": user_stats[0] if user_stats else 0,
                    "quantum_secured_users": user_stats[1] if user_stats else 0,
                    "active_quantum_sessions": quantum_sessions,
                    "quantum_session_coverage": f"{(quantum_sessions / max(len(self.secure_sessions), 1)) * 100:.1f}%"
                },
                "compliance": {
                    "nist_post_quantum_ready": self.enable_pq_crypto,
                    "quantum_resistant_algorithms": ["CRYSTALS-Kyber-1024", "CRYSTALS-Dilithium-5", "FALCON-1024", "SPHINCS+-256s"],
                    "security_level": 5,
                    "audit_trail_encrypted": True
                },
                "recommendations": self._generate_quantum_recommendations(),
                "assessment_date": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get quantum readiness status: {e}")
            return {"error": str(e), "post_quantum_enabled": False}
    
    def _generate_quantum_recommendations(self) -> List[str]:
        """Generate quantum security recommendations"""
        recommendations = []
        
        if not self.enable_pq_crypto:
            recommendations.append("Enable post-quantum cryptography for quantum resistance")
        
        # Check user quantum coverage
        try:
            quantum_user_ratio = 0  # This would be calculated from actual data
            if quantum_user_ratio < 0.8:
                recommendations.append("Migrate more users to quantum-resistant authentication")
        except:
            pass
        
        # Check session security
        if len(self.secure_sessions) == 0 and len(self.active_sessions) > 0:
            recommendations.append("Upgrade active sessions to quantum-resistant tokens")
        
        # Password policy recommendations
        if self.password_min_length < 16:
            recommendations.append("Increase minimum password length to 16 characters for quantum resistance")
        
        if not recommendations:
            recommendations.append("All quantum security recommendations are implemented")
        
        return recommendations
    
    # ========== Session Management Override ==========
    
    async def cleanup_expired_sessions(self):
        """Clean up both standard and quantum sessions"""
        # Clean up standard sessions
        await super().cleanup_expired_sessions()
        
        # Clean up post-quantum sessions
        now = datetime.utcnow()
        expired_pq_sessions = [
            session_id for session_id, session_data in self.secure_sessions.items()
            if now > session_data.expires_at
        ]
        
        for session_id in expired_pq_sessions:
            self.revoke_pq_session(session_id)
        
        self.logger.info(f"Cleaned up {len(expired_pq_sessions)} expired quantum sessions")
    
    async def get_comprehensive_session_info(self, user_id: str) -> Dict[str, Any]:
        """Get comprehensive session information including quantum sessions"""
        standard_sessions = await self.get_user_session_info(user_id)
        
        quantum_sessions = []
        for session_id, session_data in self.secure_sessions.items():
            if session_data.user_id == user_id:
                quantum_sessions.append({
                    "session_id": session_id,
                    "expires_at": session_data.expires_at.isoformat(),
                    "created_at": session_data.created_at.isoformat(),
                    "last_activity": session_data.last_activity.isoformat(),
                    "quantum_secured": session_data.quantum_secured,
                    "type": "post_quantum"
                })
        
        return {
            "standard_sessions": standard_sessions,
            "quantum_sessions": quantum_sessions,
            "total_sessions": len(standard_sessions) + len(quantum_sessions),
            "quantum_coverage": f"{(len(quantum_sessions) / max(len(standard_sessions) + len(quantum_sessions), 1)) * 100:.1f}%"
        }


# Global instance management
_pq_auth_manager = None

def get_pq_auth_manager(secret_key: str, db_manager: UnifiedDatabaseManager) -> PostQuantumAuthManager:
    """Get or create global post-quantum auth manager instance"""
    global _pq_auth_manager
    if _pq_auth_manager is None:
        _pq_auth_manager = PostQuantumAuthManager(
            secret_key=secret_key,
            db_manager=db_manager,
            enable_pq_crypto=True
        )
    return _pq_auth_manager