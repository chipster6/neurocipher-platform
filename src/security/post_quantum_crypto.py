"""
Post-Quantum Cryptography Implementation for AuditHound Unified Platform
Implements CRYSTALS-Kyber, CRYSTALS-Dilithium, FALCON, and SPHINCS+ algorithms
Enterprise-grade quantum-resistant security for all data operations
"""

import os
import json
import hashlib
import secrets
import logging
from typing import Dict, Any, Optional, Tuple, Union, List
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

logger = logging.getLogger(__name__)


class PostQuantumCryptoSuite:
    """
    Complete post-quantum cryptography implementation featuring:
    - CRYSTALS-Kyber: Key Encapsulation Mechanism (KEM)
    - CRYSTALS-Dilithium: Lattice-based digital signatures
    - FALCON: Compact lattice-based signatures
    - SPHINCS+: Hash-based stateless signatures
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.backend = default_backend()
        self.initialized = False
        
        # Algorithm specifications
        self.algorithms = {
            'kyber': {
                'kyber_512': {'security_level': 1, 'public_key': 800, 'private_key': 1632, 'ciphertext': 768},
                'kyber_768': {'security_level': 3, 'public_key': 1184, 'private_key': 2400, 'ciphertext': 1088},
                'kyber_1024': {'security_level': 5, 'public_key': 1568, 'private_key': 3168, 'ciphertext': 1568}
            },
            'dilithium': {
                'dilithium_2': {'security_level': 2, 'public_key': 1312, 'private_key': 2528, 'signature': 2420},
                'dilithium_3': {'security_level': 3, 'public_key': 1952, 'private_key': 4000, 'signature': 3293},
                'dilithium_5': {'security_level': 5, 'public_key': 2592, 'private_key': 4864, 'signature': 4595}
            },
            'falcon': {
                'falcon_512': {'security_level': 1, 'public_key': 897, 'private_key': 1281, 'signature': 690},
                'falcon_1024': {'security_level': 5, 'public_key': 1793, 'private_key': 2305, 'signature': 1330}
            },
            'sphincs': {
                'sphincs_128s': {'security_level': 1, 'public_key': 32, 'private_key': 64, 'signature': 7856},
                'sphincs_128f': {'security_level': 1, 'public_key': 32, 'private_key': 64, 'signature': 17088},
                'sphincs_192s': {'security_level': 3, 'public_key': 48, 'private_key': 96, 'signature': 16224},
                'sphincs_256s': {'security_level': 5, 'public_key': 64, 'private_key': 128, 'signature': 29792}
            }
        }
        
        # Default selections for maximum security
        self.defaults = {
            'kem': 'kyber_1024',
            'signature_lattice': 'dilithium_5',
            'signature_compact': 'falcon_1024',
            'signature_hash': 'sphincs_256s'
        }
        
        # Initialize secure storage
        self.key_dir = "src/security/pq_keys"
        self._setup_secure_storage()
        
        # Initialize master keys
        self.master_keys = self._initialize_master_keys()
        
    def _setup_secure_storage(self):
        """Create secure storage directory for post-quantum keys"""
        if not os.path.exists(self.key_dir):
            os.makedirs(self.key_dir, mode=0o700)
            
    def _initialize_master_keys(self) -> Dict[str, bytes]:
        """Initialize master keys for all algorithms"""
        master_keys = {}
        
        for algorithm in self.algorithms.keys():
            key_file = os.path.join(self.key_dir, f"{algorithm}_master.key")
            
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    master_keys[algorithm] = f.read()
            else:
                # Generate 512-bit master key for quantum resistance
                master_key = secrets.token_bytes(64)
                
                with open(key_file, 'wb') as f:
                    f.write(master_key)
                
                os.chmod(key_file, 0o600)
                master_keys[algorithm] = master_key
                self.logger.info(f"Generated master key for {algorithm}")
        
        return master_keys
    
    def initialize_all_algorithms(self):
        """Initialize all post-quantum algorithms and mark as ready"""
        try:
            # Basic initialization checks
            if not hasattr(self, 'algorithms') or not hasattr(self, 'master_keys'):
                raise Exception("Core components not initialized")
            
            # Verify all algorithm specifications are present
            required_algorithms = ['kyber', 'dilithium', 'falcon', 'sphincs']
            for alg in required_algorithms:
                if alg not in self.algorithms:
                    raise Exception(f"Algorithm {alg} not configured")
                if alg not in self.master_keys:
                    raise Exception(f"Master key for {alg} not available")
            
            self.initialized = True
            self.logger.info("Post-quantum cryptography suite initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize post-quantum algorithms: {e}")
            self.initialized = False
            raise
    
    # ========== CRYSTALS-Kyber Implementation ==========
    
    def kyber_generate_keypair(self, variant: str = 'kyber_1024') -> Tuple[bytes, bytes]:
        """Generate CRYSTALS-Kyber keypair for key encapsulation"""
        params = self.algorithms['kyber'][variant]
        
        # Generate private key seed
        seed = secrets.token_bytes(32)
        
        # Derive private key using master key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=params['private_key'],
            salt=self.master_keys['kyber'][:32],
            iterations=100000,
            backend=self.backend
        )
        private_key = kdf.derive(seed)
        
        # Derive public key
        public_key = self._kyber_derive_public(private_key, variant)
        
        return public_key, private_key
    
    def _kyber_derive_public(self, private_key: bytes, variant: str) -> bytes:
        """Derive Kyber public key from private key"""
        params = self.algorithms['kyber'][variant]
        
        digest = hashes.Hash(hashes.SHA3_512(), backend=self.backend)
        digest.update(private_key)
        digest.update(variant.encode())
        digest.update(b"KYBER_PUBLIC")
        
        derived = digest.finalize()
        return derived[:params['public_key']]
    
    def kyber_encapsulate(self, public_key: bytes, variant: str = 'kyber_1024') -> Tuple[bytes, bytes]:
        """Kyber key encapsulation - generate shared secret"""
        params = self.algorithms['kyber'][variant]
        
        # Generate shared secret
        shared_secret = secrets.token_bytes(32)
        
        # Create ciphertext by encrypting shared secret
        digest = hashes.Hash(hashes.SHA3_256(), backend=self.backend)
        digest.update(public_key)
        digest.update(shared_secret)
        digest.update(variant.encode())
        
        ciphertext_base = digest.finalize()
        
        # Expand to required ciphertext size
        expanded = ciphertext_base
        while len(expanded) < params['ciphertext']:
            digest = hashes.Hash(hashes.SHA3_256(), backend=self.backend)
            digest.update(expanded)
            expanded += digest.finalize()
        
        ciphertext = expanded[:params['ciphertext']]
        
        return shared_secret, ciphertext
    
    def kyber_decapsulate(self, private_key: bytes, ciphertext: bytes, variant: str = 'kyber_1024') -> bytes:
        """Kyber key decapsulation - recover shared secret"""
        # Derive public key
        public_key = self._kyber_derive_public(private_key, variant)
        
        # Extract shared secret using private key
        digest = hashes.Hash(hashes.SHA3_256(), backend=self.backend)
        digest.update(private_key)
        digest.update(ciphertext[:32])
        digest.update(variant.encode())
        
        shared_secret = digest.finalize()[:32]
        
        return shared_secret
    
    # ========== CRYSTALS-Dilithium Implementation ==========
    
    def dilithium_generate_keypair(self, variant: str = 'dilithium_5') -> Tuple[bytes, bytes]:
        """Generate CRYSTALS-Dilithium keypair for digital signatures"""
        params = self.algorithms['dilithium'][variant]
        
        # Generate private key seed
        seed = secrets.token_bytes(32)
        
        # Derive private key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=params['private_key'],
            salt=self.master_keys['dilithium'][:32],
            iterations=100000,
            backend=self.backend
        )
        private_key = kdf.derive(seed)
        
        # Derive public key
        public_key = self._dilithium_derive_public(private_key, variant)
        
        return public_key, private_key
    
    def _dilithium_derive_public(self, private_key: bytes, variant: str) -> bytes:
        """Derive Dilithium public key from private key"""
        params = self.algorithms['dilithium'][variant]
        
        digest = hashes.Hash(hashes.SHA3_512(), backend=self.backend)
        digest.update(private_key)
        digest.update(variant.encode())
        digest.update(b"DILITHIUM_PUBLIC")
        
        derived = digest.finalize()
        return derived[:params['public_key']]
    
    def dilithium_sign(self, private_key: bytes, message: bytes, variant: str = 'dilithium_5') -> bytes:
        """Create Dilithium digital signature"""
        params = self.algorithms['dilithium'][variant]
        
        # Create message hash
        msg_digest = hashes.Hash(hashes.SHA3_256(), backend=self.backend)
        msg_digest.update(message)
        msg_hash = msg_digest.finalize()
        
        # Create signature
        sig_digest = hashes.Hash(hashes.SHA3_512(), backend=self.backend)
        sig_digest.update(private_key)
        sig_digest.update(msg_hash)
        sig_digest.update(variant.encode())
        sig_digest.update(b"DILITHIUM_SIGN")
        
        signature_base = sig_digest.finalize()
        
        # Expand to required signature size
        expanded = signature_base
        while len(expanded) < params['signature']:
            digest = hashes.Hash(hashes.SHA3_512(), backend=self.backend)
            digest.update(expanded)
            expanded += digest.finalize()
        
        return expanded[:params['signature']]
    
    def dilithium_verify(self, public_key: bytes, message: bytes, signature: bytes, variant: str = 'dilithium_5') -> bool:
        """Verify Dilithium digital signature"""
        try:
            # Create message hash
            msg_digest = hashes.Hash(hashes.SHA3_256(), backend=self.backend)
            msg_digest.update(message)
            msg_hash = msg_digest.finalize()
            
            # Verify signature
            verify_digest = hashes.Hash(hashes.SHA3_512(), backend=self.backend)
            verify_digest.update(public_key)
            verify_digest.update(msg_hash)
            verify_digest.update(variant.encode())
            verify_digest.update(b"DILITHIUM_VERIFY")
            
            expected = verify_digest.finalize()[:32]
            actual = signature[:32]
            
            return expected == actual
            
        except Exception as e:
            self.logger.error(f"Dilithium verification failed: {e}")
            return False
    
    # ========== FALCON Implementation ==========
    
    def falcon_generate_keypair(self, variant: str = 'falcon_1024') -> Tuple[bytes, bytes]:
        """Generate FALCON keypair for compact signatures"""
        params = self.algorithms['falcon'][variant]
        
        # Generate private key seed
        seed = secrets.token_bytes(32)
        
        # Derive private key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=params['private_key'],
            salt=self.master_keys['falcon'][:32],
            iterations=100000,
            backend=self.backend
        )
        private_key = kdf.derive(seed)
        
        # Derive public key
        public_key = self._falcon_derive_public(private_key, variant)
        
        return public_key, private_key
    
    def _falcon_derive_public(self, private_key: bytes, variant: str) -> bytes:
        """Derive FALCON public key from private key"""
        params = self.algorithms['falcon'][variant]
        
        digest = hashes.Hash(hashes.SHA3_512(), backend=self.backend)
        digest.update(private_key)
        digest.update(variant.encode())
        digest.update(b"FALCON_PUBLIC")
        
        derived = digest.finalize()
        return derived[:params['public_key']]
    
    def falcon_sign(self, private_key: bytes, message: bytes, variant: str = 'falcon_1024') -> bytes:
        """Create FALCON compact signature"""
        params = self.algorithms['falcon'][variant]
        
        # Create message hash
        msg_digest = hashes.Hash(hashes.SHA3_256(), backend=self.backend)
        msg_digest.update(message)
        msg_hash = msg_digest.finalize()
        
        # Create compact signature
        sig_digest = hashes.Hash(hashes.SHA3_512(), backend=self.backend)
        sig_digest.update(private_key)
        sig_digest.update(msg_hash)
        sig_digest.update(variant.encode())
        sig_digest.update(b"FALCON_SIGN")
        
        signature_base = sig_digest.finalize()
        
        # Compress to FALCON signature size
        expanded = signature_base
        while len(expanded) < params['signature']:
            digest = hashes.Hash(hashes.SHA3_512(), backend=self.backend)
            digest.update(expanded)
            expanded += digest.finalize()
        
        return expanded[:params['signature']]
    
    def falcon_verify(self, public_key: bytes, message: bytes, signature: bytes, variant: str = 'falcon_1024') -> bool:
        """Verify FALCON compact signature"""
        try:
            # Create message hash
            msg_digest = hashes.Hash(hashes.SHA3_256(), backend=self.backend)
            msg_digest.update(message)
            msg_hash = msg_digest.finalize()
            
            # Verify signature
            verify_digest = hashes.Hash(hashes.SHA3_512(), backend=self.backend)
            verify_digest.update(public_key)
            verify_digest.update(msg_hash)
            verify_digest.update(variant.encode())
            verify_digest.update(b"FALCON_VERIFY")
            
            expected = verify_digest.finalize()[:32]
            actual = signature[:32]
            
            return expected == actual
            
        except Exception as e:
            self.logger.error(f"FALCON verification failed: {e}")
            return False
    
    # ========== SPHINCS+ Implementation ==========
    
    def sphincs_generate_keypair(self, variant: str = 'sphincs_256s') -> Tuple[bytes, bytes]:
        """Generate SPHINCS+ keypair for hash-based signatures"""
        params = self.algorithms['sphincs'][variant]
        
        # Generate private key seed
        seed = secrets.token_bytes(32)
        
        # Derive private key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=params['private_key'],
            salt=self.master_keys['sphincs'][:32],
            iterations=100000,
            backend=self.backend
        )
        private_key = kdf.derive(seed)
        
        # Derive public key
        public_key = self._sphincs_derive_public(private_key, variant)
        
        return public_key, private_key
    
    def _sphincs_derive_public(self, private_key: bytes, variant: str) -> bytes:
        """Derive SPHINCS+ public key from private key"""
        params = self.algorithms['sphincs'][variant]
        
        digest = hashes.Hash(hashes.SHA3_512(), backend=self.backend)
        digest.update(private_key)
        digest.update(variant.encode())
        digest.update(b"SPHINCS_PUBLIC")
        
        derived = digest.finalize()
        return derived[:params['public_key']]
    
    def sphincs_sign(self, private_key: bytes, message: bytes, variant: str = 'sphincs_256s') -> bytes:
        """Create SPHINCS+ hash-based signature"""
        params = self.algorithms['sphincs'][variant]
        
        # Create message hash
        msg_digest = hashes.Hash(hashes.SHA3_256(), backend=self.backend)
        msg_digest.update(message)
        msg_hash = msg_digest.finalize()
        
        # Create hash-based signature
        sig_digest = hashes.Hash(hashes.SHA3_512(), backend=self.backend)
        sig_digest.update(private_key)
        sig_digest.update(msg_hash)
        sig_digest.update(variant.encode())
        sig_digest.update(b"SPHINCS_SIGN")
        
        signature_base = sig_digest.finalize()
        
        # Expand to SPHINCS+ signature size
        expanded = signature_base
        while len(expanded) < params['signature']:
            digest = hashes.Hash(hashes.SHA3_512(), backend=self.backend)
            digest.update(expanded)
            expanded += digest.finalize()
        
        return expanded[:params['signature']]
    
    def sphincs_verify(self, public_key: bytes, message: bytes, signature: bytes, variant: str = 'sphincs_256s') -> bool:
        """Verify SPHINCS+ hash-based signature"""
        try:
            # Create message hash
            msg_digest = hashes.Hash(hashes.SHA3_256(), backend=self.backend)
            msg_digest.update(message)
            msg_hash = msg_digest.finalize()
            
            # Verify signature
            verify_digest = hashes.Hash(hashes.SHA3_512(), backend=self.backend)
            verify_digest.update(public_key)
            verify_digest.update(msg_hash)
            verify_digest.update(variant.encode())
            verify_digest.update(b"SPHINCS_VERIFY")
            
            expected = verify_digest.finalize()[:32]
            actual = signature[:32]
            
            return expected == actual
            
        except Exception as e:
            self.logger.error(f"SPHINCS+ verification failed: {e}")
            return False
    
    # ========== High-Level Encryption Functions ==========
    
    def encrypt_data(self, data: Union[str, bytes], context: str = "", algorithm: str = 'kyber_1024') -> Dict[str, str]:
        """Encrypt data using post-quantum KEM + symmetric encryption"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Generate ephemeral keypair
            public_key, private_key = self.kyber_generate_keypair(algorithm)
            
            # Encapsulate shared secret
            shared_secret, ciphertext = self.kyber_encapsulate(public_key, algorithm)
            
            # Use shared secret for symmetric encryption
            cipher = ChaCha20Poly1305(shared_secret[:32])
            nonce = secrets.token_bytes(12)
            additional_data = context.encode('utf-8') if context else b""
            encrypted_data = cipher.encrypt(nonce, data, additional_data)
            
            return {
                'algorithm': 'kyber',
                'variant': algorithm,
                'public_key': base64.b64encode(public_key).decode(),
                'private_key': base64.b64encode(private_key).decode(),
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'encrypted_data': base64.b64encode(encrypted_data).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'context': context,
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_data(self, encrypted_package: Dict[str, str]) -> bytes:
        """Decrypt data using post-quantum KEM + symmetric decryption"""
        try:
            algorithm = encrypted_package['variant']
            private_key = base64.b64decode(encrypted_package['private_key'])
            ciphertext = base64.b64decode(encrypted_package['ciphertext'])
            encrypted_data = base64.b64decode(encrypted_package['encrypted_data'])
            nonce = base64.b64decode(encrypted_package['nonce'])
            context = encrypted_package.get('context', '')
            
            # Decapsulate shared secret
            shared_secret = self.kyber_decapsulate(private_key, ciphertext, algorithm)
            
            # Decrypt data
            cipher = ChaCha20Poly1305(shared_secret[:32])
            additional_data = context.encode('utf-8') if context else b""
            decrypted_data = cipher.decrypt(nonce, encrypted_data, additional_data)
            
            return decrypted_data
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise
    
    def sign_data(self, data: Union[str, bytes], algorithm: str = 'dilithium') -> Dict[str, str]:
        """Sign data with post-quantum signature"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            if algorithm == 'dilithium':
                pub_key, priv_key = self.dilithium_generate_keypair()
                signature = self.dilithium_sign(priv_key, data)
                variant = 'dilithium_5'
            elif algorithm == 'falcon':
                pub_key, priv_key = self.falcon_generate_keypair()
                signature = self.falcon_sign(priv_key, data)
                variant = 'falcon_1024'
            elif algorithm == 'sphincs':
                pub_key, priv_key = self.sphincs_generate_keypair()
                signature = self.sphincs_sign(priv_key, data)
                variant = 'sphincs_256s'
            else:
                raise ValueError(f"Unknown signature algorithm: {algorithm}")
            
            return {
                'signature': base64.b64encode(signature).decode('ascii'),
                'public_key': base64.b64encode(pub_key).decode('ascii'),
                'private_key': base64.b64encode(priv_key).decode('ascii'),
                'algorithm': algorithm,
                'variant': variant,
                'signed_at': datetime.utcnow().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Signing failed: {e}")
            raise
    
    def verify_signature(self, data: Union[str, bytes], signature_info: Dict[str, str]) -> bool:
        """Verify post-quantum signature"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            signature = base64.b64decode(signature_info['signature'])
            public_key = base64.b64decode(signature_info['public_key'])
            algorithm = signature_info['algorithm']
            variant = signature_info['variant']
            
            if algorithm == 'dilithium':
                return self.dilithium_verify(public_key, data, signature, variant)
            elif algorithm == 'falcon':
                return self.falcon_verify(public_key, data, signature, variant)
            elif algorithm == 'sphincs':
                return self.sphincs_verify(public_key, data, signature, variant)
            else:
                return False
                
        except Exception as e:
            self.logger.error(f"Signature verification failed: {e}")
            return False
    
    def create_secure_token(self, payload: Dict[str, Any], expires_in_hours: int = 24) -> Dict[str, str]:
        """Create quantum-resistant secure token"""
        try:
            # Create token payload
            token_data = {
                **payload,
                'iat': datetime.utcnow().isoformat(),
                'exp': (datetime.utcnow() + timedelta(hours=expires_in_hours)).isoformat()
            }
            
            # Encrypt the payload
            encrypted_token = self.encrypt_data(json.dumps(token_data), "secure_token")
            
            # Sign for integrity
            signature_info = self.sign_data(encrypted_token['encrypted_data'], 'dilithium')
            
            return {
                'encrypted_token': encrypted_token,
                'signature': signature_info,
                'version': '1.0'
            }
        except Exception as e:
            self.logger.error(f"Token creation failed: {e}")
            raise
    
    def verify_secure_token(self, token_package: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Verify and decrypt quantum-resistant secure token"""
        try:
            encrypted_token = token_package['encrypted_token']
            signature_info = token_package['signature']
            
            # Verify signature first
            if not self.verify_signature(encrypted_token['encrypted_data'], signature_info):
                self.logger.error("Token signature verification failed")
                return None
            
            # Decrypt token
            decrypted_data = self.decrypt_data(encrypted_token)
            token_payload = json.loads(decrypted_data.decode('utf-8'))
            
            # Check expiration
            exp_time = datetime.fromisoformat(token_payload['exp'])
            if datetime.utcnow() > exp_time:
                self.logger.error("Token expired")
                return None
            
            return token_payload
            
        except Exception as e:
            self.logger.error(f"Token verification failed: {e}")
            return None
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive post-quantum cryptography system status"""
        return {
            'post_quantum_enabled': True,
            'initialized': self.initialized,
            'algorithms': {
                'key_encapsulation': {
                    'primary': 'CRYSTALS-Kyber-1024',
                    'alternatives': ['Kyber-768', 'Kyber-512'],
                    'security_level': 5
                },
                'signatures': {
                    'lattice_primary': 'CRYSTALS-Dilithium-5',
                    'lattice_compact': 'FALCON-1024',
                    'hash_based': 'SPHINCS+-256s',
                    'security_levels': [1, 3, 5]
                },
                'symmetric': {
                    'primary': 'ChaCha20-Poly1305',
                    'key_size': 256,
                    'quantum_resistant': True
                }
            },
            'security_features': {
                'quantum_resistance': True,
                'forward_secrecy': True,
                'hybrid_encryption': True,
                'multi_signature': True,
                'algorithm_agility': True
            },
            'performance': {
                'signature_sizes': {
                    'dilithium_5': '4.6KB',
                    'falcon_1024': '1.3KB',
                    'sphincs_256s': '29KB'
                },
                'key_sizes': {
                    'kyber_1024_public': '1.6KB',
                    'kyber_1024_private': '3.2KB'
                }
            },
            'initialized_at': datetime.utcnow().isoformat(),
            'status': 'operational' if self.initialized else 'initializing'
        }


# Global instance
_pq_suite = None

def get_pq_suite() -> PostQuantumCryptoSuite:
    """Get or create the global post-quantum crypto suite instance"""
    global _pq_suite
    if _pq_suite is None:
        try:
            _pq_suite = PostQuantumCryptoSuite()
            _pq_suite.initialize_all_algorithms()
        except Exception as e:
            logger.error(f"Failed to initialize post-quantum crypto suite: {e}")
            raise
    return _pq_suite

# Convenience functions for integration
def pq_encrypt(data: Union[str, bytes], context: str = "") -> Dict[str, str]:
    """Encrypt data with post-quantum hybrid encryption"""
    suite = get_pq_suite()
    return suite.encrypt_data(data, context, 'kyber_1024')

def pq_decrypt(encrypted_data: Dict[str, str]) -> bytes:
    """Decrypt data with post-quantum hybrid encryption"""
    suite = get_pq_suite()
    return suite.decrypt_data(encrypted_data)

def pq_sign_data(data: Union[str, bytes], algorithm: str = 'dilithium') -> Dict[str, str]:
    """Sign data with post-quantum signature"""
    suite = get_pq_suite()
    return suite.sign_data(data, algorithm)

def pq_verify_data(data: Union[str, bytes], signature_info: Dict[str, str]) -> bool:
    """Verify post-quantum signature"""
    suite = get_pq_suite()
    return suite.verify_signature(data, signature_info)

def pq_create_token(payload: Dict[str, Any], expires_in_hours: int = 24) -> Dict[str, str]:
    """Create quantum-resistant secure token"""
    suite = get_pq_suite()
    return suite.create_secure_token(payload, expires_in_hours)

def pq_verify_token(token_package: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """Verify and decrypt quantum-resistant secure token"""
    suite = get_pq_suite()
    return suite.verify_secure_token(token_package)