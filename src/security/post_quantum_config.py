"""
Post-Quantum Configuration Management
Centralized configuration management for post-quantum cryptographic settings
Handles algorithm selection, security levels, and encryption parameters
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)

class SecurityLevel(int, Enum):
    """NIST security levels for post-quantum algorithms"""
    LEVEL_1 = 1  # Equivalent to AES-128
    LEVEL_3 = 3  # Equivalent to AES-192
    LEVEL_5 = 5  # Equivalent to AES-256

class AlgorithmFamily(str, Enum):
    """Post-quantum algorithm families"""
    KYBER = "kyber"
    DILITHIUM = "dilithium"
    FALCON = "falcon"
    SPHINCS = "sphincs"

@dataclass
class AlgorithmConfig:
    """Configuration for individual algorithm"""
    name: str
    family: AlgorithmFamily
    variant: str
    security_level: SecurityLevel
    enabled: bool
    default_for_family: bool
    nist_standardized: bool
    key_sizes: Dict[str, int]
    performance_profile: str
    use_cases: List[str]

@dataclass
class PostQuantumConfig:
    """Main post-quantum configuration"""
    enabled: bool
    security_level: SecurityLevel
    algorithms: Dict[str, AlgorithmConfig]
    default_kem: str
    default_signature: str
    default_compact_signature: str
    default_hash_signature: str
    hybrid_mode: bool
    key_rotation_days: int
    master_key_size: int
    symmetric_algorithm: str
    kdf_algorithm: str
    signature_verification_timeout: int
    encryption_context_separator: str
    max_ciphertext_age_hours: int
    enable_algorithm_agility: bool
    compliance_frameworks: List[str]
    audit_logging: bool
    performance_monitoring: bool


class PostQuantumConfigManager:
    """
    Post-Quantum Configuration Manager
    Handles all configuration aspects of post-quantum cryptography
    """
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or os.getenv('PQ_CONFIG_FILE', 'src/security/pq_config.json')
        self.config: Optional[PostQuantumConfig] = None
        
        # Default algorithm configurations
        self.default_algorithms = self._init_default_algorithms()
        
        # Load configuration
        self.load_configuration()
    
    def _init_default_algorithms(self) -> Dict[str, AlgorithmConfig]:
        """Initialize default algorithm configurations"""
        algorithms = {}
        
        # CRYSTALS-Kyber variants
        algorithms['kyber_512'] = AlgorithmConfig(
            name='CRYSTALS-Kyber-512',
            family=AlgorithmFamily.KYBER,
            variant='kyber_512',
            security_level=SecurityLevel.LEVEL_1,
            enabled=True,
            default_for_family=False,
            nist_standardized=True,
            key_sizes={'public': 800, 'private': 1632, 'ciphertext': 768},
            performance_profile='fast',
            use_cases=['low_latency', 'embedded_systems']
        )
        
        algorithms['kyber_768'] = AlgorithmConfig(
            name='CRYSTALS-Kyber-768',
            family=AlgorithmFamily.KYBER,
            variant='kyber_768',
            security_level=SecurityLevel.LEVEL_3,
            enabled=True,
            default_for_family=False,
            nist_standardized=True,
            key_sizes={'public': 1184, 'private': 2400, 'ciphertext': 1088},
            performance_profile='balanced',
            use_cases=['general_purpose', 'web_services']
        )
        
        algorithms['kyber_1024'] = AlgorithmConfig(
            name='CRYSTALS-Kyber-1024',
            family=AlgorithmFamily.KYBER,
            variant='kyber_1024',
            security_level=SecurityLevel.LEVEL_5,
            enabled=True,
            default_for_family=True,
            nist_standardized=True,
            key_sizes={'public': 1568, 'private': 3168, 'ciphertext': 1568},
            performance_profile='secure',
            use_cases=['high_security', 'long_term_protection', 'enterprise']
        )
        
        # CRYSTALS-Dilithium variants
        algorithms['dilithium_2'] = AlgorithmConfig(
            name='CRYSTALS-Dilithium-2',
            family=AlgorithmFamily.DILITHIUM,
            variant='dilithium_2',
            security_level=SecurityLevel.LEVEL_1,
            enabled=True,
            default_for_family=False,
            nist_standardized=True,
            key_sizes={'public': 1312, 'private': 2528, 'signature': 2420},
            performance_profile='fast',
            use_cases=['low_latency', 'high_throughput']
        )
        
        algorithms['dilithium_3'] = AlgorithmConfig(
            name='CRYSTALS-Dilithium-3',
            family=AlgorithmFamily.DILITHIUM,
            variant='dilithium_3',
            security_level=SecurityLevel.LEVEL_3,
            enabled=True,
            default_for_family=False,
            nist_standardized=True,
            key_sizes={'public': 1952, 'private': 4000, 'signature': 3293},
            performance_profile='balanced',
            use_cases=['general_purpose', 'web_applications']
        )
        
        algorithms['dilithium_5'] = AlgorithmConfig(
            name='CRYSTALS-Dilithium-5',
            family=AlgorithmFamily.DILITHIUM,
            variant='dilithium_5',
            security_level=SecurityLevel.LEVEL_5,
            enabled=True,
            default_for_family=True,
            nist_standardized=True,
            key_sizes={'public': 2592, 'private': 4864, 'signature': 4595},
            performance_profile='secure',
            use_cases=['high_security', 'long_term_signatures', 'compliance']
        )
        
        # FALCON variants
        algorithms['falcon_512'] = AlgorithmConfig(
            name='FALCON-512',
            family=AlgorithmFamily.FALCON,
            variant='falcon_512',
            security_level=SecurityLevel.LEVEL_1,
            enabled=True,
            default_for_family=False,
            nist_standardized=True,
            key_sizes={'public': 897, 'private': 1281, 'signature': 690},
            performance_profile='compact',
            use_cases=['bandwidth_limited', 'mobile_devices']
        )
        
        algorithms['falcon_1024'] = AlgorithmConfig(
            name='FALCON-1024',
            family=AlgorithmFamily.FALCON,
            variant='falcon_1024',
            security_level=SecurityLevel.LEVEL_5,
            enabled=True,
            default_for_family=True,
            nist_standardized=True,
            key_sizes={'public': 1793, 'private': 2305, 'signature': 1330},
            performance_profile='compact_secure',
            use_cases=['compact_signatures', 'constrained_environments']
        )
        
        # SPHINCS+ variants
        algorithms['sphincs_128s'] = AlgorithmConfig(
            name='SPHINCS+-128s',
            family=AlgorithmFamily.SPHINCS,
            variant='sphincs_128s',
            security_level=SecurityLevel.LEVEL_1,
            enabled=True,
            default_for_family=False,
            nist_standardized=True,
            key_sizes={'public': 32, 'private': 64, 'signature': 7856},
            performance_profile='small_keys',
            use_cases=['small_keys', 'stateless_signatures']
        )
        
        algorithms['sphincs_256s'] = AlgorithmConfig(
            name='SPHINCS+-256s',
            family=AlgorithmFamily.SPHINCS,
            variant='sphincs_256s',
            security_level=SecurityLevel.LEVEL_5,
            enabled=True,
            default_for_family=True,
            nist_standardized=True,
            key_sizes={'public': 64, 'private': 128, 'signature': 29792},
            performance_profile='stateless_secure',
            use_cases=['stateless_signatures', 'hash_based_security', 'long_term_verification']
        )
        
        return algorithms
    
    def load_configuration(self):
        """Load configuration from file or create default"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                self.config = self._parse_config_data(config_data)
                logger.info(f"Post-quantum configuration loaded from {self.config_file}")
            else:
                self.config = self._create_default_config()
                self.save_configuration()
                logger.info("Created default post-quantum configuration")
                
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            self.config = self._create_default_config()
    
    def _parse_config_data(self, config_data: Dict[str, Any]) -> PostQuantumConfig:
        """Parse configuration data from file"""
        # Parse algorithms
        algorithms = {}
        for alg_name, alg_data in config_data.get('algorithms', {}).items():
            algorithms[alg_name] = AlgorithmConfig(
                name=alg_data['name'],
                family=AlgorithmFamily(alg_data['family']),
                variant=alg_data['variant'],
                security_level=SecurityLevel(alg_data['security_level']),
                enabled=alg_data.get('enabled', True),
                default_for_family=alg_data.get('default_for_family', False),
                nist_standardized=alg_data.get('nist_standardized', True),
                key_sizes=alg_data.get('key_sizes', {}),
                performance_profile=alg_data.get('performance_profile', 'balanced'),
                use_cases=alg_data.get('use_cases', [])
            )
        
        return PostQuantumConfig(
            enabled=config_data.get('enabled', True),
            security_level=SecurityLevel(config_data.get('security_level', 5)),
            algorithms=algorithms,
            default_kem=config_data.get('default_kem', 'kyber_1024'),
            default_signature=config_data.get('default_signature', 'dilithium_5'),
            default_compact_signature=config_data.get('default_compact_signature', 'falcon_1024'),
            default_hash_signature=config_data.get('default_hash_signature', 'sphincs_256s'),
            hybrid_mode=config_data.get('hybrid_mode', False),
            key_rotation_days=config_data.get('key_rotation_days', 90),
            master_key_size=config_data.get('master_key_size', 64),
            symmetric_algorithm=config_data.get('symmetric_algorithm', 'ChaCha20-Poly1305'),
            kdf_algorithm=config_data.get('kdf_algorithm', 'PBKDF2-SHA256'),
            signature_verification_timeout=config_data.get('signature_verification_timeout', 5000),
            encryption_context_separator=config_data.get('encryption_context_separator', '::'),
            max_ciphertext_age_hours=config_data.get('max_ciphertext_age_hours', 24),
            enable_algorithm_agility=config_data.get('enable_algorithm_agility', True),
            compliance_frameworks=config_data.get('compliance_frameworks', ['nist_csf', 'iso27001']),
            audit_logging=config_data.get('audit_logging', True),
            performance_monitoring=config_data.get('performance_monitoring', True)
        )
    
    def _create_default_config(self) -> PostQuantumConfig:
        """Create default configuration"""
        return PostQuantumConfig(
            enabled=True,
            security_level=SecurityLevel.LEVEL_5,
            algorithms=self.default_algorithms,
            default_kem='kyber_1024',
            default_signature='dilithium_5',
            default_compact_signature='falcon_1024',
            default_hash_signature='sphincs_256s',
            hybrid_mode=False,
            key_rotation_days=90,
            master_key_size=64,
            symmetric_algorithm='ChaCha20-Poly1305',
            kdf_algorithm='PBKDF2-SHA256',
            signature_verification_timeout=5000,
            encryption_context_separator='::',
            max_ciphertext_age_hours=24,
            enable_algorithm_agility=True,
            compliance_frameworks=['nist_csf', 'iso27001', 'soc2'],
            audit_logging=True,
            performance_monitoring=True
        )
    
    def save_configuration(self):
        """Save configuration to file"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            
            # Convert to serializable format
            config_data = {
                'enabled': self.config.enabled,
                'security_level': self.config.security_level.value,
                'algorithms': {
                    name: {
                        'name': alg.name,
                        'family': alg.family.value,
                        'variant': alg.variant,
                        'security_level': alg.security_level.value,
                        'enabled': alg.enabled,
                        'default_for_family': alg.default_for_family,
                        'nist_standardized': alg.nist_standardized,
                        'key_sizes': alg.key_sizes,
                        'performance_profile': alg.performance_profile,
                        'use_cases': alg.use_cases
                    }
                    for name, alg in self.config.algorithms.items()
                },
                'default_kem': self.config.default_kem,
                'default_signature': self.config.default_signature,
                'default_compact_signature': self.config.default_compact_signature,
                'default_hash_signature': self.config.default_hash_signature,
                'hybrid_mode': self.config.hybrid_mode,
                'key_rotation_days': self.config.key_rotation_days,
                'master_key_size': self.config.master_key_size,
                'symmetric_algorithm': self.config.symmetric_algorithm,
                'kdf_algorithm': self.config.kdf_algorithm,
                'signature_verification_timeout': self.config.signature_verification_timeout,
                'encryption_context_separator': self.config.encryption_context_separator,
                'max_ciphertext_age_hours': self.config.max_ciphertext_age_hours,
                'enable_algorithm_agility': self.config.enable_algorithm_agility,
                'compliance_frameworks': self.config.compliance_frameworks,
                'audit_logging': self.config.audit_logging,
                'performance_monitoring': self.config.performance_monitoring,
                'last_updated': datetime.utcnow().isoformat()
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            logger.info(f"Configuration saved to {self.config_file}")
            
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            raise
    
    # ========== Configuration Getters ==========
    
    def get_kem_algorithm(self, variant: Optional[str] = None) -> AlgorithmConfig:
        """Get KEM algorithm configuration"""
        algorithm_name = variant or self.config.default_kem
        if algorithm_name not in self.config.algorithms:
            raise ValueError(f"Unknown KEM algorithm: {algorithm_name}")
        return self.config.algorithms[algorithm_name]
    
    def get_signature_algorithm(self, variant: Optional[str] = None, 
                              compact: bool = False, 
                              stateless: bool = False) -> AlgorithmConfig:
        """Get signature algorithm configuration"""
        if stateless:
            algorithm_name = variant or self.config.default_hash_signature
        elif compact:
            algorithm_name = variant or self.config.default_compact_signature
        else:
            algorithm_name = variant or self.config.default_signature
        
        if algorithm_name not in self.config.algorithms:
            raise ValueError(f"Unknown signature algorithm: {algorithm_name}")
        return self.config.algorithms[algorithm_name]
    
    def get_enabled_algorithms(self) -> Dict[str, AlgorithmConfig]:
        """Get all enabled algorithms"""
        return {
            name: alg for name, alg in self.config.algorithms.items() 
            if alg.enabled
        }
    
    def get_algorithms_by_family(self, family: AlgorithmFamily) -> Dict[str, AlgorithmConfig]:
        """Get algorithms by family"""
        return {
            name: alg for name, alg in self.config.algorithms.items()
            if alg.family == family and alg.enabled
        }
    
    def get_algorithms_by_security_level(self, level: SecurityLevel) -> Dict[str, AlgorithmConfig]:
        """Get algorithms by security level"""
        return {
            name: alg for name, alg in self.config.algorithms.items()
            if alg.security_level == level and alg.enabled
        }
    
    # ========== Configuration Setters ==========
    
    def set_security_level(self, level: SecurityLevel):
        """Set global security level and update defaults"""
        self.config.security_level = level
        
        # Update defaults based on security level
        for family in AlgorithmFamily:
            # Find highest security level algorithm for each family
            family_algorithms = self.get_algorithms_by_family(family)
            if family_algorithms:
                best_alg = max(
                    family_algorithms.values(),
                    key=lambda alg: (alg.security_level.value, alg.nist_standardized)
                )
                
                if family == AlgorithmFamily.KYBER:
                    self.config.default_kem = best_alg.variant
                elif family == AlgorithmFamily.DILITHIUM:
                    self.config.default_signature = best_alg.variant
                elif family == AlgorithmFamily.FALCON:
                    self.config.default_compact_signature = best_alg.variant
                elif family == AlgorithmFamily.SPHINCS:
                    self.config.default_hash_signature = best_alg.variant
        
        logger.info(f"Security level updated to {level.value}")
    
    def enable_algorithm(self, algorithm_name: str):
        """Enable specific algorithm"""
        if algorithm_name in self.config.algorithms:
            self.config.algorithms[algorithm_name].enabled = True
            logger.info(f"Algorithm enabled: {algorithm_name}")
        else:
            raise ValueError(f"Unknown algorithm: {algorithm_name}")
    
    def disable_algorithm(self, algorithm_name: str):
        """Disable specific algorithm"""
        if algorithm_name in self.config.algorithms:
            alg = self.config.algorithms[algorithm_name]
            
            # Check if this is a default algorithm
            if (algorithm_name == self.config.default_kem or 
                algorithm_name == self.config.default_signature or
                algorithm_name == self.config.default_compact_signature or
                algorithm_name == self.config.default_hash_signature):
                
                # Find alternative algorithm from same family
                alternatives = [
                    name for name, alt_alg in self.config.algorithms.items()
                    if (alt_alg.family == alg.family and 
                        alt_alg.enabled and 
                        name != algorithm_name)
                ]
                
                if not alternatives:
                    raise ValueError(f"Cannot disable {algorithm_name} - no alternatives available")
                
                # Update default to best alternative
                best_alternative = max(alternatives, key=lambda name: self.config.algorithms[name].security_level.value)
                
                if algorithm_name == self.config.default_kem:
                    self.config.default_kem = best_alternative
                elif algorithm_name == self.config.default_signature:
                    self.config.default_signature = best_alternative
                elif algorithm_name == self.config.default_compact_signature:
                    self.config.default_compact_signature = best_alternative
                elif algorithm_name == self.config.default_hash_signature:
                    self.config.default_hash_signature = best_alternative
            
            alg.enabled = False
            logger.info(f"Algorithm disabled: {algorithm_name}")
        else:
            raise ValueError(f"Unknown algorithm: {algorithm_name}")
    
    def set_hybrid_mode(self, enabled: bool):
        """Enable/disable hybrid cryptography mode"""
        self.config.hybrid_mode = enabled
        logger.info(f"Hybrid mode {'enabled' if enabled else 'disabled'}")
    
    # ========== Validation and Status ==========
    
    def validate_configuration(self) -> Dict[str, Any]:
        """Validate current configuration"""
        issues = []
        warnings = []
        
        # Check that at least one algorithm is enabled for each family
        for family in AlgorithmFamily:
            family_algorithms = self.get_algorithms_by_family(family)
            if not family_algorithms:
                issues.append(f"No enabled algorithms for {family.value} family")
        
        # Check default algorithms are enabled
        defaults = [
            self.config.default_kem,
            self.config.default_signature,
            self.config.default_compact_signature,
            self.config.default_hash_signature
        ]
        
        for default in defaults:
            if default not in self.config.algorithms:
                issues.append(f"Default algorithm not found: {default}")
            elif not self.config.algorithms[default].enabled:
                issues.append(f"Default algorithm is disabled: {default}")
        
        # Check security level consistency
        min_security_level = min(
            alg.security_level.value for alg in self.config.algorithms.values() 
            if alg.enabled
        )
        
        if min_security_level < self.config.security_level.value:
            warnings.append(f"Some enabled algorithms have lower security level than configured ({min_security_level} < {self.config.security_level.value})")
        
        # Check NIST standardization
        non_nist = [
            name for name, alg in self.config.algorithms.items()
            if alg.enabled and not alg.nist_standardized
        ]
        
        if non_nist:
            warnings.append(f"Non-NIST standardized algorithms enabled: {non_nist}")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'warnings': warnings,
            'total_algorithms': len(self.config.algorithms),
            'enabled_algorithms': len(self.get_enabled_algorithms()),
            'security_level': self.config.security_level.value,
            'nist_compliant': all(alg.nist_standardized for alg in self.get_enabled_algorithms().values())
        }
    
    def get_configuration_summary(self) -> Dict[str, Any]:
        """Get configuration summary"""
        enabled_algs = self.get_enabled_algorithms()
        
        return {
            'enabled': self.config.enabled,
            'security_level': self.config.security_level.value,
            'total_algorithms': len(self.config.algorithms),
            'enabled_algorithms': len(enabled_algs),
            'defaults': {
                'kem': self.config.default_kem,
                'signature': self.config.default_signature,
                'compact_signature': self.config.default_compact_signature,
                'hash_signature': self.config.default_hash_signature
            },
            'algorithm_families': {
                family.value: len(self.get_algorithms_by_family(family))
                for family in AlgorithmFamily
            },
            'nist_standardized': sum(1 for alg in enabled_algs.values() if alg.nist_standardized),
            'hybrid_mode': self.config.hybrid_mode,
            'compliance_frameworks': self.config.compliance_frameworks,
            'last_updated': datetime.utcnow().isoformat()
        }


# Global instance
_pq_config_manager = None

def get_pq_config_manager(config_file: Optional[str] = None) -> PostQuantumConfigManager:
    """Get or create global post-quantum configuration manager"""
    global _pq_config_manager
    if _pq_config_manager is None:
        _pq_config_manager = PostQuantumConfigManager(config_file)
    return _pq_config_manager