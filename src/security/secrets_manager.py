#!/usr/bin/env python3
"""
AuditHound Secrets Management System
Comprehensive secrets management with HashiCorp Vault, AWS Secrets Manager, and environment variables
"""

import os
import json
import logging
import hashlib
import base64
from typing import Dict, Optional, Any, List
from dataclasses import dataclass, field
from pathlib import Path
import time
from enum import Enum

# Optional imports for different secret stores
try:
    import hvac  # HashiCorp Vault client
    VAULT_AVAILABLE = True
except ImportError:
    VAULT_AVAILABLE = False

try:
    import boto3
    from botocore.exceptions import ClientError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

logger = logging.getLogger(__name__)

class SecretStore(Enum):
    """Available secret store backends"""
    ENVIRONMENT = "environment"
    VAULT = "vault"
    AWS_SECRETS_MANAGER = "aws_secrets_manager"
    FILE_SYSTEM = "file_system"  # For development only

class SecretType(Enum):
    """Types of secrets"""
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    CERTIFICATE = "certificate"
    DATABASE_URL = "database_url"
    ENCRYPTION_KEY = "encryption_key"
    WEBHOOK_SECRET = "webhook_secret"

@dataclass
class SecretMetadata:
    """Metadata for a secret"""
    name: str
    secret_type: SecretType
    description: str = ""
    tags: List[str] = field(default_factory=list)
    rotation_enabled: bool = False
    rotation_interval_days: int = 90
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0

class SecretsManager:
    """
    Comprehensive secrets management system supporting multiple backends
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize secrets manager with configuration"""
        self.config = config or {}
        self.primary_store = SecretStore(self.config.get("primary_store", "environment"))
        self.fallback_stores = [SecretStore(s) for s in self.config.get("fallback_stores", [])]
        
        # Initialize store clients
        self.vault_client = None
        self.aws_client = None
        self.secret_metadata: Dict[str, SecretMetadata] = {}
        
        # Security settings
        self.encryption_key = self._get_encryption_key()
        self.audit_log_path = Path(self.config.get("audit_log_path", "logs/secrets_audit.log"))
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._initialize_stores()
        self._load_metadata()
        
        logger.info(f"Secrets manager initialized with primary store: {self.primary_store.value}")
    
    def _get_encryption_key(self) -> bytes:
        """Get or generate encryption key for local secret encryption"""
        key_env = os.getenv("AUDITHOUND_ENCRYPTION_KEY")
        if key_env:
            return base64.b64decode(key_env)
        
        # Generate new key if not exists
        key_path = Path(".audithound_key")
        if key_path.exists():
            with open(key_path, "rb") as f:
                return f.read()
        
        # Generate new encryption key
        import secrets
        key = secrets.token_bytes(32)
        with open(key_path, "wb") as f:
            f.write(key)
        key_path.chmod(0o600)
        
        logger.warning("Generated new encryption key. Set AUDITHOUND_ENCRYPTION_KEY environment variable.")
        return key
    
    def _initialize_stores(self):
        """Initialize secret store clients"""
        # Initialize Vault client
        if self.primary_store == SecretStore.VAULT or SecretStore.VAULT in self.fallback_stores:
            if VAULT_AVAILABLE:
                vault_url = self.config.get("vault_url") or os.getenv("VAULT_ADDR", "http://localhost:8200")
                vault_token = self.config.get("vault_token") or os.getenv("VAULT_TOKEN")
                
                if vault_token:
                    self.vault_client = hvac.Client(url=vault_url, token=vault_token)
                    try:
                        if self.vault_client.is_authenticated():
                            logger.info("Successfully authenticated with HashiCorp Vault")
                        else:
                            logger.error("Failed to authenticate with HashiCorp Vault")
                            self.vault_client = None
                    except Exception as e:
                        logger.error(f"Vault connection failed: {e}")
                        self.vault_client = None
                else:
                    logger.warning("Vault token not provided")
            else:
                logger.warning("Vault client not available. Install with: pip install hvac")
        
        # Initialize AWS Secrets Manager client
        if self.primary_store == SecretStore.AWS_SECRETS_MANAGER or SecretStore.AWS_SECRETS_MANAGER in self.fallback_stores:
            if AWS_AVAILABLE:
                try:
                    self.aws_client = boto3.client('secretsmanager')
                    # Test connection
                    self.aws_client.list_secrets(MaxResults=1)
                    logger.info("Successfully connected to AWS Secrets Manager")
                except Exception as e:
                    logger.error(f"AWS Secrets Manager connection failed: {e}")
                    self.aws_client = None
            else:
                logger.warning("AWS client not available. Install with: pip install boto3")
    
    def _load_metadata(self):
        """Load secret metadata"""
        metadata_path = Path(".audithound_secrets_metadata.json")
        if metadata_path.exists():
            try:
                with open(metadata_path, 'r') as f:
                    data = json.load(f)
                
                for name, meta_dict in data.items():
                    meta_dict['secret_type'] = SecretType(meta_dict['secret_type'])
                    self.secret_metadata[name] = SecretMetadata(**meta_dict)
                
                logger.info(f"Loaded metadata for {len(self.secret_metadata)} secrets")
            except Exception as e:
                logger.error(f"Failed to load secret metadata: {e}")
    
    def _save_metadata(self):
        """Save secret metadata"""
        metadata_path = Path(".audithound_secrets_metadata.json")
        try:
            data = {}
            for name, meta in self.secret_metadata.items():
                meta_dict = {
                    'name': meta.name,
                    'secret_type': meta.secret_type.value,
                    'description': meta.description,
                    'tags': meta.tags,
                    'rotation_enabled': meta.rotation_enabled,
                    'rotation_interval_days': meta.rotation_interval_days,
                    'created_at': meta.created_at,
                    'last_accessed': meta.last_accessed,
                    'access_count': meta.access_count
                }
                data[name] = meta_dict
            
            with open(metadata_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            metadata_path.chmod(0o600)
        except Exception as e:
            logger.error(f"Failed to save secret metadata: {e}")
    
    def _audit_log(self, action: str, secret_name: str, details: Dict[str, Any] = None):
        """Log secret access for audit purposes"""
        try:
            log_entry = {
                "timestamp": time.time(),
                "action": action,
                "secret_name": secret_name,
                "details": details or {}
            }
            
            with open(self.audit_log_path, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
    
    def store_secret(self, name: str, value: str, secret_type: SecretType, 
                    description: str = "", tags: List[str] = None) -> bool:
        """Store a secret in the configured backend"""
        try:
            # Create metadata
            metadata = SecretMetadata(
                name=name,
                secret_type=secret_type,
                description=description,
                tags=tags or []
            )
            
            success = False
            
            # Try primary store first
            if self.primary_store == SecretStore.ENVIRONMENT:
                success = self._store_in_environment(name, value)
            elif self.primary_store == SecretStore.VAULT and self.vault_client:
                success = self._store_in_vault(name, value, metadata)
            elif self.primary_store == SecretStore.AWS_SECRETS_MANAGER and self.aws_client:
                success = self._store_in_aws(name, value, metadata)
            elif self.primary_store == SecretStore.FILE_SYSTEM:
                success = self._store_in_filesystem(name, value, metadata)
            
            # Try fallback stores if primary fails
            if not success:
                for store in self.fallback_stores:
                    if store == SecretStore.ENVIRONMENT:
                        success = self._store_in_environment(name, value)
                    elif store == SecretStore.VAULT and self.vault_client:
                        success = self._store_in_vault(name, value, metadata)
                    elif store == SecretStore.AWS_SECRETS_MANAGER and self.aws_client:
                        success = self._store_in_aws(name, value, metadata)
                    elif store == SecretStore.FILE_SYSTEM:
                        success = self._store_in_filesystem(name, value, metadata)
                    
                    if success:
                        break
            
            if success:
                self.secret_metadata[name] = metadata
                self._save_metadata()
                self._audit_log("store", name, {"secret_type": secret_type.value})
                logger.info(f"Successfully stored secret: {name}")
            else:
                logger.error(f"Failed to store secret: {name}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error storing secret {name}: {e}")
            return False
    
    def get_secret(self, name: str) -> Optional[str]:
        """Retrieve a secret from the configured backend"""
        try:
            value = None
            
            # Try primary store first
            if self.primary_store == SecretStore.ENVIRONMENT:
                value = self._get_from_environment(name)
            elif self.primary_store == SecretStore.VAULT and self.vault_client:
                value = self._get_from_vault(name)
            elif self.primary_store == SecretStore.AWS_SECRETS_MANAGER and self.aws_client:
                value = self._get_from_aws(name)
            elif self.primary_store == SecretStore.FILE_SYSTEM:
                value = self._get_from_filesystem(name)
            
            # Try fallback stores if primary fails
            if value is None:
                for store in self.fallback_stores:
                    if store == SecretStore.ENVIRONMENT:
                        value = self._get_from_environment(name)
                    elif store == SecretStore.VAULT and self.vault_client:
                        value = self._get_from_vault(name)
                    elif store == SecretStore.AWS_SECRETS_MANAGER and self.aws_client:
                        value = self._get_from_aws(name)
                    elif store == SecretStore.FILE_SYSTEM:
                        value = self._get_from_filesystem(name)
                    
                    if value is not None:
                        break
            
            # Update access metadata
            if value is not None and name in self.secret_metadata:
                self.secret_metadata[name].last_accessed = time.time()
                self.secret_metadata[name].access_count += 1
                self._save_metadata()
                self._audit_log("retrieve", name)
            
            return value
            
        except Exception as e:
            logger.error(f"Error retrieving secret {name}: {e}")
            return None
    
    def _store_in_environment(self, name: str, value: str) -> bool:
        """Store secret as environment variable"""
        try:
            os.environ[name.upper()] = value
            return True
        except Exception as e:
            logger.error(f"Failed to store in environment: {e}")
            return False
    
    def _get_from_environment(self, name: str) -> Optional[str]:
        """Get secret from environment variables"""
        return os.getenv(name.upper()) or os.getenv(name)
    
    def _store_in_vault(self, name: str, value: str, metadata: SecretMetadata) -> bool:
        """Store secret in HashiCorp Vault"""
        if not self.vault_client:
            return False
        
        try:
            secret_data = {
                'value': value,
                'type': metadata.secret_type.value,
                'description': metadata.description,
                'tags': metadata.tags
            }
            
            response = self.vault_client.secrets.kv.v2.create_or_update_secret(
                path=f"audithound/{name}",
                secret=secret_data
            )
            
            return response is not None
        except Exception as e:
            logger.error(f"Failed to store in Vault: {e}")
            return False
    
    def _get_from_vault(self, name: str) -> Optional[str]:
        """Get secret from HashiCorp Vault"""
        if not self.vault_client:
            return None
        
        try:
            response = self.vault_client.secrets.kv.v2.read_secret_version(
                path=f"audithound/{name}"
            )
            
            if response and 'data' in response and 'data' in response['data']:
                return response['data']['data'].get('value')
            
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve from Vault: {e}")
            return None
    
    def _store_in_aws(self, name: str, value: str, metadata: SecretMetadata) -> bool:
        """Store secret in AWS Secrets Manager"""
        if not self.aws_client:
            return False
        
        try:
            secret_name = f"audithound/{name}"
            
            secret_data = {
                'value': value,
                'type': metadata.secret_type.value,
                'description': metadata.description,
                'tags': metadata.tags
            }
            
            try:
                # Try to update existing secret
                self.aws_client.update_secret(
                    SecretId=secret_name,
                    SecretString=json.dumps(secret_data)
                )
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    # Create new secret
                    self.aws_client.create_secret(
                        Name=secret_name,
                        SecretString=json.dumps(secret_data),
                        Description=metadata.description
                    )
                else:
                    raise
            
            return True
        except Exception as e:
            logger.error(f"Failed to store in AWS Secrets Manager: {e}")
            return False
    
    def _get_from_aws(self, name: str) -> Optional[str]:
        """Get secret from AWS Secrets Manager"""
        if not self.aws_client:
            return None
        
        try:
            secret_name = f"audithound/{name}"
            response = self.aws_client.get_secret_value(SecretId=secret_name)
            
            if 'SecretString' in response:
                secret_data = json.loads(response['SecretString'])
                return secret_data.get('value')
            
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve from AWS Secrets Manager: {e}")
            return None
    
    def _store_in_filesystem(self, name: str, value: str, metadata: SecretMetadata) -> bool:
        """Store secret in encrypted file (development only)"""
        try:
            secrets_dir = Path(".audithound_secrets")
            secrets_dir.mkdir(exist_ok=True)
            secrets_dir.chmod(0o700)
            
            # Simple encryption (for development only)
            encrypted_value = self._encrypt_value(value)
            
            secret_file = secrets_dir / f"{name}.secret"
            with open(secret_file, 'w') as f:
                json.dump({
                    'encrypted_value': encrypted_value,
                    'type': metadata.secret_type.value,
                    'description': metadata.description
                }, f)
            
            secret_file.chmod(0o600)
            return True
        except Exception as e:
            logger.error(f"Failed to store in filesystem: {e}")
            return False
    
    def _get_from_filesystem(self, name: str) -> Optional[str]:
        """Get secret from encrypted file"""
        try:
            secrets_dir = Path(".audithound_secrets")
            secret_file = secrets_dir / f"{name}.secret"
            
            if not secret_file.exists():
                return None
            
            with open(secret_file, 'r') as f:
                data = json.load(f)
            
            encrypted_value = data.get('encrypted_value')
            if encrypted_value:
                return self._decrypt_value(encrypted_value)
            
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve from filesystem: {e}")
            return None
    
    def _encrypt_value(self, value: str) -> str:
        """Simple encryption for filesystem storage"""
        try:
            from cryptography.fernet import Fernet
            key = base64.urlsafe_b64encode(self.encryption_key)
            fernet = Fernet(key)
            encrypted = fernet.encrypt(value.encode())
            return base64.b64encode(encrypted).decode()
        except ImportError:
            # Fallback to simple base64 (not secure, for development only)
            logger.warning("cryptography library not available, using base64 encoding")
            return base64.b64encode(value.encode()).decode()
    
    def _decrypt_value(self, encrypted_value: str) -> str:
        """Simple decryption for filesystem storage"""
        try:
            from cryptography.fernet import Fernet
            key = base64.urlsafe_b64encode(self.encryption_key)
            fernet = Fernet(key)
            encrypted_bytes = base64.b64decode(encrypted_value.encode())
            decrypted = fernet.decrypt(encrypted_bytes)
            return decrypted.decode()
        except ImportError:
            # Fallback to simple base64
            return base64.b64decode(encrypted_value.encode()).decode()
    
    def list_secrets(self) -> List[str]:
        """List all stored secrets"""
        return list(self.secret_metadata.keys())
    
    def delete_secret(self, name: str) -> bool:
        """Delete a secret from all stores"""
        success = True
        
        try:
            # Remove from primary store
            if self.primary_store == SecretStore.ENVIRONMENT:
                if name.upper() in os.environ:
                    del os.environ[name.upper()]
            elif self.primary_store == SecretStore.VAULT and self.vault_client:
                try:
                    self.vault_client.secrets.kv.v2.delete_metadata_and_all_versions(
                        path=f"audithound/{name}"
                    )
                except Exception:
                    pass
            elif self.primary_store == SecretStore.AWS_SECRETS_MANAGER and self.aws_client:
                try:
                    self.aws_client.delete_secret(
                        SecretId=f"audithound/{name}",
                        ForceDeleteWithoutRecovery=True
                    )
                except Exception:
                    pass
            elif self.primary_store == SecretStore.FILE_SYSTEM:
                secret_file = Path(".audithound_secrets") / f"{name}.secret"
                if secret_file.exists():
                    secret_file.unlink()
            
            # Remove metadata
            if name in self.secret_metadata:
                del self.secret_metadata[name]
                self._save_metadata()
            
            self._audit_log("delete", name)
            logger.info(f"Deleted secret: {name}")
            
        except Exception as e:
            logger.error(f"Error deleting secret {name}: {e}")
            success = False
        
        return success
    
    def rotate_secret(self, name: str, new_value: str) -> bool:
        """Rotate a secret value"""
        if name not in self.secret_metadata:
            logger.error(f"Secret {name} not found for rotation")
            return False
        
        metadata = self.secret_metadata[name]
        success = self.store_secret(name, new_value, metadata.secret_type, 
                                   metadata.description, metadata.tags)
        
        if success:
            self._audit_log("rotate", name)
            logger.info(f"Rotated secret: {name}")
        
        return success
    
    def get_secrets_health(self) -> Dict[str, Any]:
        """Get health status of secrets and stores"""
        health = {
            "primary_store": self.primary_store.value,
            "vault_available": self.vault_client is not None,
            "aws_available": self.aws_client is not None,
            "total_secrets": len(self.secret_metadata),
            "secrets_requiring_rotation": [],
            "store_connectivity": {}
        }
        
        # Check store connectivity
        if self.vault_client:
            try:
                health["store_connectivity"]["vault"] = self.vault_client.is_authenticated()
            except:
                health["store_connectivity"]["vault"] = False
        
        if self.aws_client:
            try:
                self.aws_client.list_secrets(MaxResults=1)
                health["store_connectivity"]["aws"] = True
            except:
                health["store_connectivity"]["aws"] = False
        
        # Check secrets requiring rotation
        current_time = time.time()
        for name, metadata in self.secret_metadata.items():
            if metadata.rotation_enabled:
                days_since_creation = (current_time - metadata.created_at) / 86400
                if days_since_creation > metadata.rotation_interval_days:
                    health["secrets_requiring_rotation"].append(name)
        
        return health

# Factory function
def create_secrets_manager(config: Dict[str, Any] = None) -> SecretsManager:
    """Create a secrets manager instance"""
    return SecretsManager(config)

# Global instance for easy access
_global_secrets_manager = None

def get_secret(name: str) -> Optional[str]:
    """Global function to get a secret"""
    global _global_secrets_manager
    if _global_secrets_manager is None:
        _global_secrets_manager = create_secrets_manager()
    return _global_secrets_manager.get_secret(name)

def store_secret(name: str, value: str, secret_type: SecretType = SecretType.API_KEY) -> bool:
    """Global function to store a secret"""
    global _global_secrets_manager
    if _global_secrets_manager is None:
        _global_secrets_manager = create_secrets_manager()
    return _global_secrets_manager.store_secret(name, value, secret_type)