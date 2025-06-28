"""
Security Module for AuditHound Unified Platform
Enhanced with Post-Quantum Cryptography capabilities
"""

# Import core security components
from .auth import AuthenticationManager, AuthorizationManager, UserRole, TokenData, User
from .unified_auth_manager import UnifiedAuthManager
from .config_manager import ConfigManager
from .secrets_manager import SecretsManager

# Import post-quantum security components
from .post_quantum_crypto import (
    PostQuantumCryptoSuite, 
    get_pq_suite, 
    pq_encrypt, 
    pq_decrypt, 
    pq_sign_data, 
    pq_verify_data,
    pq_create_token,
    pq_verify_token
)
from .post_quantum_auth import PostQuantumAuthManager, get_pq_auth_manager
from .post_quantum_config import PostQuantumConfigManager, get_pq_config_manager, SecurityLevel, AlgorithmFamily

__all__ = [
    # Core authentication
    'AuthenticationManager',
    'AuthorizationManager', 
    'UnifiedAuthManager',
    'UserRole',
    'TokenData',
    'User',
    
    # Configuration and secrets
    'ConfigManager',
    'SecretsManager',
    
    # Post-quantum cryptography
    'PostQuantumCryptoSuite',
    'get_pq_suite',
    'pq_encrypt',
    'pq_decrypt', 
    'pq_sign_data',
    'pq_verify_data',
    'pq_create_token',
    'pq_verify_token',
    
    # Post-quantum authentication
    'PostQuantumAuthManager',
    'get_pq_auth_manager',
    
    # Post-quantum configuration
    'PostQuantumConfigManager',
    'get_pq_config_manager',
    'SecurityLevel',
    'AlgorithmFamily'
]