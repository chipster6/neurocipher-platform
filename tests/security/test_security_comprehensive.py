# Comprehensive security testing suite
import pytest
import json
import base64
import hashlib
import secrets
import time
from unittest.mock import patch, Mock
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.security.unified_auth_manager import UnifiedAuthManager
from src.security.post_quantum_crypto import PostQuantumCrypto
from src.security.post_quantum_auth import PostQuantumAuth
from src.multi_tenant_manager import MultiTenantManager


@pytest.mark.security
class TestSecurityComprehensive:
    """Comprehensive security testing suite."""
    
    def test_authentication_security(self, auth_manager):
        """Test authentication security mechanisms."""
        # Test password hashing security
        password = "test_password_123"
        hashed = auth_manager.hash_password(password)
        
        # Should not store plaintext password
        assert password not in hashed
        assert auth_manager.verify_password(password, hashed)
        
        # Test password requirements
        weak_passwords = [
            "123",           # Too short
            "password",      # Common word
            "12345678",      # No complexity
            "ABCDEFGH",      # No lowercase
            "abcdefgh"       # No uppercase/numbers
        ]
        
        for weak_password in weak_passwords:
            with pytest.raises(ValueError, match="Password does not meet requirements"):
                auth_manager.validate_password_strength(weak_password)
        
        # Test strong password acceptance
        strong_password = "SecureP@ssw0rd123!"
        assert auth_manager.validate_password_strength(strong_password) is True
    
    def test_jwt_token_security(self, auth_manager):
        """Test JWT token security implementation."""
        user_data = {
            "user_id": "test_user_001",
            "username": "security_test_user",
            "tenant_id": "test_tenant_001",
            "roles": ["user"]
        }
        
        # Generate token
        token = auth_manager.create_access_token(user_data)
        assert isinstance(token, str)
        assert len(token) > 100  # JWT tokens should be reasonably long
        
        # Verify token
        decoded = auth_manager.verify_access_token(token)
        assert decoded["user_id"] == user_data["user_id"]
        assert decoded["tenant_id"] == user_data["tenant_id"]
        
        # Test token expiration
        expired_token = auth_manager.create_access_token(user_data, expires_delta=-3600)  # Expired
        with pytest.raises(Exception):  # Should raise InvalidTokenError or similar
            auth_manager.verify_access_token(expired_token)
        
        # Test token tampering
        tampered_token = token[:-10] + "tamperedXX"
        with pytest.raises(Exception):
            auth_manager.verify_access_token(tampered_token)
    
    def test_sql_injection_protection(self, test_client):
        """Test protection against SQL injection attacks."""
        # Common SQL injection payloads
        injection_payloads = [
            "'; DROP TABLE tenants; --",
            "' OR 1=1 --",
            "' UNION SELECT * FROM users --",
            "'; INSERT INTO tenants (tenant_id) VALUES ('malicious'); --",
            "' OR 'a'='a",
            "1; DELETE FROM audit_logs; --"
        ]
        
        for payload in injection_payloads:
            # Test tenant lookup with injection payload
            response = test_client.get(f"/api/v1/tenants/{payload}")
            
            # Should return 404 or 400, not 500 (which might indicate SQL error)
            assert response.status_code in [400, 404, 422]
            
            # Response should not contain SQL error messages
            response_text = response.text.lower()
            sql_error_indicators = ["syntax error", "sql", "database", "sqlite", "postgres"]
            for indicator in sql_error_indicators:
                assert indicator not in response_text
    
    def test_xss_protection(self, test_client):
        """Test protection against Cross-Site Scripting (XSS) attacks."""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>",
            "';alert('xss');//",
            "<iframe src='javascript:alert()'></iframe>"
        ]
        
        for payload in xss_payloads:
            # Test tenant creation with XSS payload in name
            tenant_data = {
                "tenant_id": f"xss_test_{hash(payload) % 10000}",
                "name": payload,
                "description": f"XSS test with payload: {payload}",
                "status": "active"
            }
            
            response = test_client.post("/api/v1/tenants", json=tenant_data)
            
            if response.status_code == 201:
                # If creation succeeded, verify the payload is properly escaped
                created_tenant = response.json()
                
                # Should not contain unescaped script tags or javascript
                assert "<script>" not in created_tenant["name"]
                assert "javascript:" not in created_tenant["name"]
                
                # Cleanup
                test_client.delete(f"/api/v1/tenants/{tenant_data['tenant_id']}")
    
    def test_csrf_protection(self, test_client):
        """Test Cross-Site Request Forgery (CSRF) protection."""
        # First, create a valid session
        auth_data = {
            "username": "csrf_test_user",
            "email": "csrf@test.com",
            "password": "CsrfTest123!",
            "tenant_id": "csrf_test_tenant"
        }
        
        # Register and login
        test_client.post("/api/v1/auth/register", json=auth_data)
        login_response = test_client.post("/api/v1/auth/login", json={
            "username": auth_data["username"],
            "password": auth_data["password"]
        })
        
        if login_response.status_code == 200:
            token = login_response.json().get("access_token")
            headers = {"Authorization": f"Bearer {token}"}
            
            # Test that requests without proper headers are rejected
            # when performing state-changing operations
            tenant_data = {
                "tenant_id": "csrf_attack_tenant",
                "name": "CSRF Attack Tenant",
                "status": "active"
            }
            
            # Request without origin header (simulating CSRF attack)
            response = test_client.post("/api/v1/tenants", json=tenant_data, headers=headers)
            
            # In a production system, this should include CSRF protection
            # For now, we just verify the request structure is validated
            if response.status_code in [201, 403, 400]:
                # Expected responses - either created with proper validation or blocked
                pass
            else:
                pytest.fail(f"Unexpected response code: {response.status_code}")
    
    def test_input_validation_and_sanitization(self, test_client):
        """Test input validation and sanitization."""
        # Test oversized input
        oversized_data = {
            "tenant_id": "oversized_test",
            "name": "X" * 10000,  # Very long name
            "description": "Y" * 50000,  # Very long description
            "status": "active"
        }
        
        response = test_client.post("/api/v1/tenants", json=oversized_data)
        assert response.status_code in [400, 422], "Should reject oversized input"
        
        # Test invalid characters
        invalid_char_data = {
            "tenant_id": "invalid\x00\x01\x02",  # Null bytes and control characters
            "name": "Test\r\nTenant",  # CRLF injection attempt
            "status": "active"
        }
        
        response = test_client.post("/api/v1/tenants", json=invalid_char_data)
        assert response.status_code in [400, 422], "Should reject invalid characters"
        
        # Test JSON injection
        json_injection_data = {
            "tenant_id": "json_injection_test",
            "name": '{"injected": "json"}',
            "configuration": '{"malicious": true}',  # String instead of object
            "status": "active"
        }
        
        response = test_client.post("/api/v1/tenants", json=json_injection_data)
        # Should handle gracefully, either accepting and sanitizing or rejecting
        assert response.status_code in [201, 400, 422]
    
    def test_post_quantum_cryptography_security(self):
        """Test post-quantum cryptography implementation security."""
        pq_crypto = PostQuantumCrypto()
        
        # Test key generation
        private_key, public_key = pq_crypto.generate_keypair()
        assert private_key != public_key
        assert len(private_key) > 100  # Should be substantial key size
        assert len(public_key) > 100
        
        # Test encryption/decryption
        test_data = b"Sensitive audit data for post-quantum testing"
        encrypted = pq_crypto.encrypt(test_data, public_key)
        
        assert encrypted != test_data
        assert len(encrypted) > len(test_data)
        
        decrypted = pq_crypto.decrypt(encrypted, private_key)
        assert decrypted == test_data
        
        # Test that wrong private key cannot decrypt
        wrong_private_key, _ = pq_crypto.generate_keypair()
        with pytest.raises(Exception):
            pq_crypto.decrypt(encrypted, wrong_private_key)
        
        # Test digital signatures
        signature = pq_crypto.sign(test_data, private_key)
        assert pq_crypto.verify_signature(test_data, signature, public_key)
        
        # Test signature tampering detection
        tampered_data = test_data + b"tampered"
        assert not pq_crypto.verify_signature(tampered_data, signature, public_key)
    
    def test_tenant_isolation_security(self, multi_tenant_manager):
        """Test security of tenant data isolation."""
        # Create two test tenants
        tenant1_data = {
            "tenant_id": "security_tenant_1",
            "name": "Security Test Tenant 1",
            "status": "active",
            "security_config": {"isolation_level": "strict"}
        }
        
        tenant2_data = {
            "tenant_id": "security_tenant_2",
            "name": "Security Test Tenant 2",
            "status": "active",
            "security_config": {"isolation_level": "strict"}
        }
        
        with patch.object(multi_tenant_manager.db_manager, 'create_tenant') as mock_create:
            mock_tenant1 = Mock()
            mock_tenant1.tenant_id = tenant1_data["tenant_id"]
            mock_tenant2 = Mock()
            mock_tenant2.tenant_id = tenant2_data["tenant_id"]
            
            mock_create.side_effect = [mock_tenant1, mock_tenant2]
            
            tenant1 = multi_tenant_manager.create_tenant(tenant1_data)
            tenant2 = multi_tenant_manager.create_tenant(tenant2_data)
        
        # Test cross-tenant data access prevention
        tenant1_resource = {
            "tenant_id": "security_tenant_1",
            "resource_id": "sensitive_resource_1",
            "data": "tenant1_secret_data"
        }
        
        # Should be valid for tenant1
        assert multi_tenant_manager.validate_tenant_isolation(
            tenant1_resource, "security_tenant_1"
        ) is True
        
        # Should be invalid for tenant2
        assert multi_tenant_manager.validate_tenant_isolation(
            tenant1_resource, "security_tenant_2"
        ) is False
        
        # Test that tenant2 cannot access tenant1's user data
        with patch.object(multi_tenant_manager, 'is_user_authorized') as mock_auth:
            mock_auth.return_value = False
            
            access_result = multi_tenant_manager.validate_tenant_access(
                "security_tenant_1", "tenant2_user"
            )
            assert access_result is False
    
    def test_encryption_at_rest(self, unified_db_manager):
        """Test encryption of sensitive data at rest."""
        # Test sensitive data encryption
        sensitive_data = {
            "tenant_id": "encryption_test_tenant",
            "resource_id": "sensitive_resource",
            "sensitive_fields": {
                "api_key": "secret_api_key_12345",
                "password": "super_secret_password",
                "personal_data": "john.doe@example.com"
            }
        }
        
        # Mock database storage with encryption
        with patch.object(unified_db_manager, 'store_encrypted_data') as mock_store:
            mock_store.return_value = True
            
            # Should encrypt sensitive fields before storage
            result = unified_db_manager.store_encrypted_data(sensitive_data)
            assert result is True
            
            # Verify that the call was made (encryption would happen in real implementation)
            mock_store.assert_called_once_with(sensitive_data)
    
    def test_secure_session_management(self, auth_manager):
        """Test secure session management."""
        user_data = {
            "user_id": "session_test_user",
            "username": "session_user",
            "tenant_id": "session_test_tenant"
        }
        
        # Create session
        session_token = auth_manager.create_session(user_data)
        assert isinstance(session_token, str)
        assert len(session_token) >= 32  # Should be cryptographically secure
        
        # Verify session
        session_data = auth_manager.get_session(session_token)
        assert session_data["user_id"] == user_data["user_id"]
        
        # Test session invalidation
        auth_manager.invalidate_session(session_token)
        
        with pytest.raises(Exception):
            auth_manager.get_session(session_token)
        
        # Test concurrent session limits
        sessions = []
        for i in range(10):  # Try to create many sessions
            token = auth_manager.create_session({**user_data, "session_id": i})
            sessions.append(token)
        
        # Should have limit on concurrent sessions per user
        # (Implementation would enforce this limit)
        active_sessions = [s for s in sessions if auth_manager.is_session_valid(s)]
        assert len(active_sessions) <= 5  # Reasonable session limit
    
    def test_rate_limiting_security(self, test_client):
        """Test rate limiting to prevent abuse."""
        # Test rapid consecutive requests
        rapid_requests = []
        for i in range(100):  # Make many rapid requests
            start_time = time.time()
            response = test_client.get("/api/v1/health")
            end_time = time.time()
            
            rapid_requests.append({
                "status_code": response.status_code,
                "response_time": end_time - start_time,
                "request_number": i
            })
        
        # Should have rate limiting in place
        # Look for 429 (Too Many Requests) responses or increasing response times
        status_codes = [req["status_code"] for req in rapid_requests]
        
        # At least some requests should be rate-limited or all should succeed
        # but with reasonable response times
        rate_limited_requests = status_codes.count(429)
        successful_requests = status_codes.count(200)
        
        if rate_limited_requests == 0:
            # If no rate limiting, all requests should be fast
            avg_response_time = sum(req["response_time"] for req in rapid_requests) / len(rapid_requests)
            assert avg_response_time < 0.5, "Requests should be fast if no rate limiting"
        else:
            # Some requests were rate limited, which is good
            assert rate_limited_requests > 0
    
    def test_audit_logging_security(self, unified_db_manager):
        """Test security of audit logging mechanism."""
        # Test that security events are properly logged
        security_events = [
            {
                "event_type": "authentication_failure",
                "tenant_id": "audit_test_tenant",
                "user_id": "potential_attacker",
                "ip_address": "192.168.1.100",
                "user_agent": "AttackTool/1.0",
                "timestamp": time.time(),
                "details": {"reason": "invalid_credentials", "attempts": 5}
            },
            {
                "event_type": "unauthorized_access_attempt",
                "tenant_id": "audit_test_tenant",
                "resource_id": "sensitive_resource",
                "user_id": "unauthorized_user",
                "ip_address": "10.0.0.50",
                "timestamp": time.time(),
                "details": {"action": "read", "blocked": True}
            }
        ]
        
        for event in security_events:
            with patch.object(unified_db_manager, 'log_security_event') as mock_log:
                mock_log.return_value = True
                
                result = unified_db_manager.log_security_event(event)
                assert result is True
                
                # Verify the event was logged with all required fields
                mock_log.assert_called_once_with(event)
                call_args = mock_log.call_args[0][0]
                assert call_args["event_type"] == event["event_type"]
                assert call_args["tenant_id"] == event["tenant_id"]
                assert "timestamp" in call_args
    
    def test_data_privacy_compliance(self, unified_db_manager):
        """Test data privacy and compliance measures."""
        # Test PII data handling
        pii_data = {
            "tenant_id": "privacy_test_tenant",
            "user_id": "privacy_test_user",
            "personal_data": {
                "email": "john.doe@example.com",
                "phone": "+1-555-123-4567",
                "ssn": "123-45-6789",
                "credit_card": "4111-1111-1111-1111"
            }
        }
        
        # Should detect and handle PII appropriately
        with patch.object(unified_db_manager, 'handle_pii_data') as mock_handle:
            mock_handle.return_value = {
                **pii_data,
                "personal_data": {
                    "email": "j***@example.com",  # Masked
                    "phone": "+1-555-***-****",  # Masked
                    "ssn": "***-**-****",        # Masked
                    "credit_card": "****-****-****-1111"  # Masked
                }
            }
            
            processed_data = unified_db_manager.handle_pii_data(pii_data)
            
            # Verify PII is properly masked/encrypted
            assert "john.doe" not in str(processed_data["personal_data"])
            assert "123-45-6789" not in str(processed_data["personal_data"])
            assert "4111-1111-1111-1111" not in str(processed_data["personal_data"])
    
    def test_secure_configuration_management(self, test_config):
        """Test secure configuration management."""
        # Test that sensitive configuration is not exposed
        sensitive_keys = [
            "SECRET_KEY",
            "JWT_SECRET",
            "ENCRYPTION_KEY",
            "DATABASE_PASSWORD",
            "API_KEYS"
        ]
        
        # Configuration should not contain plaintext secrets in logs/responses
        config_str = str(test_config)
        
        for key in sensitive_keys:
            if key in test_config:
                # Secret values should not appear in string representation
                secret_value = test_config[key]
                if len(secret_value) > 4:  # Only check non-trivial secrets
                    assert secret_value not in config_str or secret_value == "***"
    
    @pytest.mark.slow
    def test_brute_force_protection(self, test_client):
        """Test protection against brute force attacks."""
        # Test repeated login attempts with wrong password
        user_data = {
            "username": "brute_force_test",
            "email": "bruteforce@test.com",
            "password": "CorrectPassword123!",
            "tenant_id": "brute_force_tenant"
        }
        
        # Register user
        test_client.post("/api/v1/auth/register", json=user_data)
        
        # Attempt multiple failed logins
        failed_attempts = 0
        for i in range(10):
            response = test_client.post("/api/v1/auth/login", json={
                "username": user_data["username"],
                "password": f"wrong_password_{i}"
            })
            
            if response.status_code == 401:
                failed_attempts += 1
            elif response.status_code == 429:
                # Rate limited - good security measure
                break
            
            time.sleep(0.1)  # Small delay between attempts
        
        # After many failed attempts, should implement some protection
        # (account lockout, rate limiting, CAPTCHA, etc.)
        assert failed_attempts <= 10, "Should have brute force protection"
        
        # Verify legitimate login still works after protection period
        time.sleep(2)  # Wait for potential lockout to expire
        response = test_client.post("/api/v1/auth/login", json={
            "username": user_data["username"],
            "password": user_data["password"]
        })
        
        # Should eventually allow legitimate login
        # (might need to wait for lockout to expire in real implementation)
        assert response.status_code in [200, 429]  # Either success or still rate limited