"""
Comprehensive Tests for Post-Quantum Cryptography Implementation
Tests all post-quantum algorithms, encryption/decryption, signatures, and integration
"""

import pytest
import asyncio
import json
import tempfile
import os
from datetime import datetime, timedelta
from typing import Dict, Any

# Import post-quantum modules
import sys
sys.path.append('/Users/cody/audithound-unified/src')

from security.post_quantum_crypto import (
    PostQuantumCryptoSuite, get_pq_suite, 
    pq_encrypt, pq_decrypt, pq_sign_data, pq_verify_data,
    pq_create_token, pq_verify_token
)
from security.post_quantum_config import (
    PostQuantumConfigManager, SecurityLevel, AlgorithmFamily
)
from compliance.post_quantum_compliance import (
    PostQuantumComplianceFramework, ComplianceStatus
)


class TestPostQuantumCryptoSuite:
    """Test the core post-quantum cryptography suite"""
    
    @pytest.fixture
    def pq_suite(self):
        """Create a post-quantum crypto suite for testing"""
        suite = PostQuantumCryptoSuite()
        suite.initialize_all_algorithms()
        return suite
    
    def test_suite_initialization(self, pq_suite):
        """Test that the crypto suite initializes correctly"""
        assert pq_suite.initialized
        assert hasattr(pq_suite, 'algorithms')
        assert hasattr(pq_suite, 'master_keys')
        
        # Check that all required algorithms are present
        required_families = ['kyber', 'dilithium', 'falcon', 'sphincs']
        for family in required_families:
            assert family in pq_suite.algorithms
            assert family in pq_suite.master_keys
    
    def test_kyber_key_generation(self, pq_suite):
        """Test CRYSTALS-Kyber key generation"""
        variants = ['kyber_512', 'kyber_768', 'kyber_1024']
        
        for variant in variants:
            public_key, private_key = pq_suite.kyber_generate_keypair(variant)
            
            # Check key sizes
            params = pq_suite.algorithms['kyber'][variant]
            assert len(public_key) == params['public_key']
            assert len(private_key) == params['private_key']
            
            # Keys should be different
            assert public_key != private_key
    
    def test_kyber_encapsulation_decapsulation(self, pq_suite):
        """Test CRYSTALS-Kyber key encapsulation and decapsulation"""
        public_key, private_key = pq_suite.kyber_generate_keypair('kyber_1024')
        
        # Encapsulate
        shared_secret1, ciphertext = pq_suite.kyber_encapsulate(public_key, 'kyber_1024')
        
        # Decapsulate
        shared_secret2 = pq_suite.kyber_decapsulate(private_key, ciphertext, 'kyber_1024')
        
        # Shared secrets should match
        assert shared_secret1 == shared_secret2
        assert len(shared_secret1) == 32  # 256-bit shared secret
    
    def test_dilithium_signature_generation_verification(self, pq_suite):
        """Test CRYSTALS-Dilithium signature generation and verification"""
        message = b"Test message for Dilithium signature"
        
        variants = ['dilithium_2', 'dilithium_3', 'dilithium_5']
        
        for variant in variants:
            public_key, private_key = pq_suite.dilithium_generate_keypair(variant)
            
            # Sign message
            signature = pq_suite.dilithium_sign(private_key, message, variant)
            
            # Verify signature
            is_valid = pq_suite.dilithium_verify(public_key, message, signature, variant)
            assert is_valid
            
            # Test with wrong message
            wrong_message = b"Wrong message"
            is_invalid = pq_suite.dilithium_verify(public_key, wrong_message, signature, variant)
            assert not is_invalid
    
    def test_falcon_signature_generation_verification(self, pq_suite):
        """Test FALCON signature generation and verification"""
        message = b"Test message for FALCON signature"
        
        variants = ['falcon_512', 'falcon_1024']
        
        for variant in variants:
            public_key, private_key = pq_suite.falcon_generate_keypair(variant)
            
            # Sign message
            signature = pq_suite.falcon_sign(private_key, message, variant)
            
            # Verify signature
            is_valid = pq_suite.falcon_verify(public_key, message, signature, variant)
            assert is_valid
            
            # Check signature size
            params = pq_suite.algorithms['falcon'][variant]
            assert len(signature) == params['signature']
    
    def test_sphincs_signature_generation_verification(self, pq_suite):
        """Test SPHINCS+ signature generation and verification"""
        message = b"Test message for SPHINCS+ signature"
        
        variants = ['sphincs_128s', 'sphincs_256s']
        
        for variant in variants:
            public_key, private_key = pq_suite.sphincs_generate_keypair(variant)
            
            # Sign message
            signature = pq_suite.sphincs_sign(private_key, message, variant)
            
            # Verify signature
            is_valid = pq_suite.sphincs_verify(public_key, message, signature, variant)
            assert is_valid
    
    def test_data_encryption_decryption(self, pq_suite):
        """Test data encryption and decryption"""
        test_data = "This is sensitive data that needs quantum-resistant protection"
        context = "test_encryption"
        
        # Test with string data
        encrypted_package = pq_suite.encrypt_data(test_data, context)
        
        # Check encrypted package structure
        required_keys = ['algorithm', 'variant', 'public_key', 'private_key', 
                        'ciphertext', 'encrypted_data', 'nonce', 'context']
        for key in required_keys:
            assert key in encrypted_package
        
        # Decrypt data
        decrypted_data = pq_suite.decrypt_data(encrypted_package)
        assert decrypted_data.decode('utf-8') == test_data
        
        # Test with bytes data
        byte_data = test_data.encode('utf-8')
        encrypted_package2 = pq_suite.encrypt_data(byte_data, context)
        decrypted_data2 = pq_suite.decrypt_data(encrypted_package2)
        assert decrypted_data2 == byte_data
    
    def test_data_signing_verification(self, pq_suite):
        """Test data signing and verification"""
        test_data = "Important data that needs integrity protection"
        
        algorithms = ['dilithium', 'falcon', 'sphincs']
        
        for algorithm in algorithms:
            # Sign data
            signature_info = pq_suite.sign_data(test_data, algorithm)
            
            # Check signature info structure
            required_keys = ['signature', 'public_key', 'private_key', 'algorithm', 'variant', 'signed_at']
            for key in required_keys:
                assert key in signature_info
            
            # Verify signature
            is_valid = pq_suite.verify_signature(test_data, signature_info)
            assert is_valid
            
            # Test with tampered data
            tampered_data = test_data + " tampered"
            is_invalid = pq_suite.verify_signature(tampered_data, signature_info)
            assert not is_invalid
    
    def test_secure_token_creation_verification(self, pq_suite):
        """Test quantum-resistant secure token creation and verification"""
        payload = {
            "user_id": "test_user",
            "role": "admin",
            "permissions": ["read", "write"]
        }
        
        # Create token
        token_package = pq_suite.create_secure_token(payload, expires_in_hours=1)
        
        # Check token structure
        assert 'encrypted_token' in token_package
        assert 'signature' in token_package
        assert 'version' in token_package
        
        # Verify token
        verified_payload = pq_suite.verify_secure_token(token_package)
        assert verified_payload is not None
        assert verified_payload['user_id'] == payload['user_id']
        assert verified_payload['role'] == payload['role']
        assert verified_payload['permissions'] == payload['permissions']
    
    def test_system_status(self, pq_suite):
        """Test system status reporting"""
        status = pq_suite.get_system_status()
        
        # Check status structure
        required_keys = ['post_quantum_enabled', 'initialized', 'algorithms', 
                        'security_features', 'performance', 'status']
        for key in required_keys:
            assert key in status
        
        assert status['post_quantum_enabled']
        assert status['initialized']
        assert status['status'] == 'operational'


class TestConvenienceFunctions:
    """Test convenience functions for post-quantum operations"""
    
    def test_pq_encrypt_decrypt(self):
        """Test convenience encryption/decryption functions"""
        test_data = "Test data for convenience functions"
        context = "test_context"
        
        # Encrypt
        encrypted_data = pq_encrypt(test_data, context)
        assert isinstance(encrypted_data, dict)
        
        # Decrypt
        decrypted_data = pq_decrypt(encrypted_data)
        assert decrypted_data.decode('utf-8') == test_data
    
    def test_pq_sign_verify_data(self):
        """Test convenience signing/verification functions"""
        test_data = "Test data for convenience signing"
        
        algorithms = ['dilithium', 'falcon', 'sphincs']
        
        for algorithm in algorithms:
            # Sign
            signature_info = pq_sign_data(test_data, algorithm)
            assert isinstance(signature_info, dict)
            
            # Verify
            is_valid = pq_verify_data(test_data, signature_info)
            assert is_valid
    
    def test_pq_token_functions(self):
        """Test convenience token functions"""
        payload = {"test": "data"}
        
        # Create token
        token_package = pq_create_token(payload)
        assert isinstance(token_package, dict)
        
        # Verify token
        verified_payload = pq_verify_token(token_package)
        assert verified_payload is not None
        assert verified_payload['test'] == payload['test']


class TestPostQuantumConfig:
    """Test post-quantum configuration management"""
    
    @pytest.fixture
    def config_manager(self):
        """Create config manager with temporary file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_file = f.name
        
        manager = PostQuantumConfigManager(config_file)
        yield manager
        
        # Cleanup
        os.unlink(config_file)
    
    def test_config_initialization(self, config_manager):
        """Test configuration initialization"""
        assert config_manager.config is not None
        assert config_manager.config.enabled
        assert len(config_manager.config.algorithms) > 0
    
    def test_algorithm_configuration(self, config_manager):
        """Test algorithm configuration"""
        # Test KEM algorithm
        kem_alg = config_manager.get_kem_algorithm()
        assert kem_alg.family == AlgorithmFamily.KYBER
        assert kem_alg.enabled
        
        # Test signature algorithms
        sig_alg = config_manager.get_signature_algorithm()
        assert sig_alg.family == AlgorithmFamily.DILITHIUM
        
        compact_sig = config_manager.get_signature_algorithm(compact=True)
        assert compact_sig.family == AlgorithmFamily.FALCON
        
        stateless_sig = config_manager.get_signature_algorithm(stateless=True)
        assert stateless_sig.family == AlgorithmFamily.SPHINCS
    
    def test_security_level_management(self, config_manager):
        """Test security level management"""
        # Set security level
        config_manager.set_security_level(SecurityLevel.LEVEL_5)
        assert config_manager.config.security_level == SecurityLevel.LEVEL_5
        
        # Check that defaults are updated to highest security
        kem_alg = config_manager.get_kem_algorithm()
        assert kem_alg.security_level == SecurityLevel.LEVEL_5
    
    def test_algorithm_enable_disable(self, config_manager):
        """Test enabling/disabling algorithms"""
        # Disable an algorithm
        config_manager.disable_algorithm('kyber_512')
        kyber_512 = config_manager.config.algorithms['kyber_512']
        assert not kyber_512.enabled
        
        # Re-enable it
        config_manager.enable_algorithm('kyber_512')
        assert kyber_512.enabled
    
    def test_configuration_validation(self, config_manager):
        """Test configuration validation"""
        validation = config_manager.validate_configuration()
        
        assert isinstance(validation, dict)
        assert 'valid' in validation
        assert 'issues' in validation
        assert 'warnings' in validation
    
    def test_configuration_summary(self, config_manager):
        """Test configuration summary"""
        summary = config_manager.get_configuration_summary()
        
        required_keys = ['enabled', 'security_level', 'total_algorithms', 
                        'enabled_algorithms', 'defaults', 'algorithm_families']
        for key in required_keys:
            assert key in summary
    
    def test_save_load_configuration(self, config_manager):
        """Test saving and loading configuration"""
        # Modify configuration
        original_level = config_manager.config.security_level
        config_manager.set_security_level(SecurityLevel.LEVEL_3)
        
        # Save configuration
        config_manager.save_configuration()
        
        # Create new manager with same file
        new_manager = PostQuantumConfigManager(config_manager.config_file)
        
        # Check that changes were persisted
        assert new_manager.config.security_level == SecurityLevel.LEVEL_3
        assert new_manager.config.security_level != original_level


class TestPostQuantumCompliance:
    """Test post-quantum compliance framework"""
    
    @pytest.fixture
    def compliance_framework(self):
        """Create compliance framework for testing"""
        return PostQuantumComplianceFramework()
    
    def test_framework_initialization(self, compliance_framework):
        """Test compliance framework initialization"""
        assert hasattr(compliance_framework, 'frameworks')
        
        # Check that all required frameworks are present
        required_frameworks = ['nist_csf', 'iso27001', 'soc2', 'fedramp', 'nist_pqc']
        for framework in required_frameworks:
            assert framework in compliance_framework.frameworks
    
    def test_get_framework_controls(self, compliance_framework):
        """Test getting framework controls"""
        for framework_name in compliance_framework.get_available_frameworks():
            controls = compliance_framework.get_framework_controls(framework_name)
            assert isinstance(controls, list)
            assert len(controls) > 0
            
            # Check control structure
            for control in controls:
                required_keys = ['control_id', 'title', 'description', 'requirement', 'quantum_considerations']
                for key in required_keys:
                    assert key in control
    
    @pytest.mark.asyncio
    async def test_quantum_readiness_assessment(self, compliance_framework):
        """Test quantum readiness assessment"""
        assessment = await compliance_framework.conduct_quantum_readiness_assessment(
            tenant_id="test_tenant",
            framework="nist_pqc",
            assessor="test_assessor"
        )
        
        assert assessment.tenant_id == "test_tenant"
        assert assessment.framework == "nist_pqc"
        assert assessment.assessor == "test_assessor"
        assert assessment.total_controls > 0
        assert len(assessment.controls) == assessment.total_controls
        assert 0 <= assessment.quantum_ready_percentage <= 100
    
    def test_compliance_report_generation(self, compliance_framework):
        """Test compliance report generation"""
        # Create a mock assessment
        from compliance.post_quantum_compliance import ComplianceAssessment, ComplianceControl
        
        mock_controls = [
            ComplianceControl(
                control_id="TEST-1",
                framework="nist_pqc",
                title="Test Control",
                description="Test Description",
                requirement="Test Requirement",
                current_implementation="Test Implementation",
                quantum_considerations="Test Considerations",
                status=ComplianceStatus.COMPLIANT,
                evidence=["Test Evidence"],
                remediation_steps=[],
                last_assessed=datetime.utcnow(),
                next_review=datetime.utcnow() + timedelta(days=90),
                risk_level="Low",
                quantum_ready=True
            )
        ]
        
        mock_assessment = ComplianceAssessment(
            assessment_id="test_assessment",
            tenant_id="test_tenant",
            framework="nist_pqc",
            assessment_date=datetime.utcnow(),
            assessor="test_assessor",
            overall_status=ComplianceStatus.COMPLIANT,
            total_controls=1,
            compliant_controls=1,
            partially_compliant_controls=0,
            non_compliant_controls=0,
            quantum_ready_percentage=100.0,
            controls=mock_controls,
            recommendations=[],
            next_assessment_date=datetime.utcnow() + timedelta(days=90)
        )
        
        # Generate report
        report = compliance_framework.generate_compliance_report(mock_assessment)
        
        # Check report structure
        required_sections = ['report_metadata', 'executive_summary', 'control_details', 
                           'risk_assessment', 'recommendations', 'implementation_roadmap']
        for section in required_sections:
            assert section in report
    
    def test_quantum_readiness_scorecard(self, compliance_framework):
        """Test quantum readiness scorecard generation"""
        # Create mock assessments
        from compliance.post_quantum_compliance import ComplianceAssessment
        
        mock_assessments = [
            ComplianceAssessment(
                assessment_id="test1",
                tenant_id="test_tenant",
                framework="nist_pqc",
                assessment_date=datetime.utcnow(),
                assessor="test_assessor",
                overall_status=ComplianceStatus.COMPLIANT,
                total_controls=10,
                compliant_controls=9,
                partially_compliant_controls=1,
                non_compliant_controls=0,
                quantum_ready_percentage=90.0,
                controls=[],
                recommendations=[],
                next_assessment_date=datetime.utcnow() + timedelta(days=90)
            )
        ]
        
        scorecard = compliance_framework.generate_quantum_readiness_scorecard(mock_assessments)
        
        # Check scorecard structure
        required_keys = ['overall_score', 'readiness_level', 'readiness_description',
                        'framework_scores', 'algorithm_implementation']
        for key in required_keys:
            assert key in scorecard
        
        assert scorecard['overall_score'] == 90.0
        assert scorecard['readiness_level'] in ['Excellent', 'Good', 'Fair', 'Poor']


class TestIntegration:
    """Integration tests for complete post-quantum system"""
    
    @pytest.mark.asyncio
    async def test_end_to_end_encryption_workflow(self):
        """Test complete encryption workflow"""
        # Initialize components
        pq_suite = get_pq_suite()
        
        # Test data
        sensitive_data = {
            "user_id": "12345",
            "account_info": "Sensitive account information",
            "transaction_data": ["tx1", "tx2", "tx3"]
        }
        
        # 1. Encrypt data
        encrypted_package = pq_encrypt(json.dumps(sensitive_data), "integration_test")
        
        # 2. Sign encrypted data for integrity
        signature_info = pq_sign_data(encrypted_package['encrypted_data'], 'dilithium')
        
        # 3. Verify signature
        signature_valid = pq_verify_data(encrypted_package['encrypted_data'], signature_info)
        assert signature_valid
        
        # 4. Decrypt data
        decrypted_bytes = pq_decrypt(encrypted_package)
        decrypted_data = json.loads(decrypted_bytes.decode('utf-8'))
        
        # 5. Verify data integrity
        assert decrypted_data == sensitive_data
    
    def test_algorithm_interoperability(self):
        """Test that different algorithms work together"""
        pq_suite = get_pq_suite()
        test_message = b"Interoperability test message"
        
        # Generate keys for all signature algorithms
        dilithium_pub, dilithium_priv = pq_suite.dilithium_generate_keypair()
        falcon_pub, falcon_priv = pq_suite.falcon_generate_keypair()
        sphincs_pub, sphincs_priv = pq_suite.sphincs_generate_keypair()
        
        # Sign with all algorithms
        dilithium_sig = pq_suite.dilithium_sign(dilithium_priv, test_message)
        falcon_sig = pq_suite.falcon_sign(falcon_priv, test_message)
        sphincs_sig = pq_suite.sphincs_sign(sphincs_priv, test_message)
        
        # Verify all signatures
        assert pq_suite.dilithium_verify(dilithium_pub, test_message, dilithium_sig)
        assert pq_suite.falcon_verify(falcon_pub, test_message, falcon_sig)
        assert pq_suite.sphincs_verify(sphincs_pub, test_message, sphincs_sig)
        
        # Cross-verification should fail
        assert not pq_suite.dilithium_verify(dilithium_pub, test_message, falcon_sig)
        assert not pq_suite.falcon_verify(falcon_pub, test_message, sphincs_sig)
    
    def test_performance_baseline(self):
        """Test basic performance characteristics"""
        pq_suite = get_pq_suite()
        test_data = b"Performance test data" * 100  # 2KB of data
        
        import time
        
        # Test encryption performance
        start_time = time.time()
        for _ in range(10):
            encrypted = pq_suite.encrypt_data(test_data, "performance_test")
            decrypted = pq_suite.decrypt_data(encrypted)
        encryption_time = time.time() - start_time
        
        # Test signing performance
        start_time = time.time()
        for _ in range(10):
            signature_info = pq_suite.sign_data(test_data, 'dilithium')
            is_valid = pq_suite.verify_signature(test_data, signature_info)
        signing_time = time.time() - start_time
        
        # Basic performance checks (these are quite lenient)
        assert encryption_time < 10.0  # 10 operations should take less than 10 seconds
        assert signing_time < 10.0
        
        print(f"Encryption/Decryption: {encryption_time:.2f}s for 10 operations")
        print(f"Signing/Verification: {signing_time:.2f}s for 10 operations")


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])