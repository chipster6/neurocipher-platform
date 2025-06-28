#!/usr/bin/env python3
"""
AuditHound Configuration Management
12-factor app compliant configuration management with environment variables
"""

import os
import json
import logging
from typing import Dict, Any, Optional, Union, List
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum

from .secrets_manager import SecretsManager, SecretType, get_secret

logger = logging.getLogger(__name__)

class ConfigSource(Enum):
    """Configuration sources in order of precedence"""
    ENVIRONMENT = "environment"
    SECRETS_MANAGER = "secrets_manager"
    CONFIG_FILE = "config_file"
    DEFAULT = "default"

@dataclass
class ConfigValue:
    """Configuration value with metadata"""
    key: str
    value: Any
    source: ConfigSource
    sensitive: bool = False
    required: bool = False
    description: str = ""
    validation_regex: Optional[str] = None

class ConfigManager:
    """
    12-factor app compliant configuration manager
    """
    
    def __init__(self, app_name: str = "audithound", config_file: Optional[str] = None):
        """Initialize configuration manager"""
        self.app_name = app_name.upper()
        self.config_file = config_file
        self.secrets_manager = SecretsManager()
        
        # Configuration registry
        self.config_values: Dict[str, ConfigValue] = {}
        self.config_schema: Dict[str, Dict[str, Any]] = {}
        
        # Load configuration
        self._load_schema()
        self._load_configuration()
        
        logger.info(f"Configuration manager initialized for {app_name}")
    
    def _load_schema(self):
        """Load configuration schema defining all possible config values"""
        self.config_schema = {
            # Database Configuration
            "database": {
                "weaviate_url": {
                    "default": "http://localhost:8080",
                    "required": True,
                    "description": "Weaviate database URL",
                    "env_var": "WEAVIATE_URL"
                },
                "weaviate_api_key": {
                    "default": None,
                    "required": False,
                    "sensitive": True,
                    "description": "Weaviate API key for authentication",
                    "env_var": "WEAVIATE_API_KEY",
                    "secret_name": "weaviate_api_key"
                },
                "postgres_url": {
                    "default": None,
                    "required": False,
                    "sensitive": True,
                    "description": "PostgreSQL connection URL",
                    "env_var": "POSTGRES_URL",
                    "secret_name": "postgres_url"
                }
            },
            
            # Cloud Provider Configuration
            "aws": {
                "access_key_id": {
                    "default": None,
                    "required": False,
                    "sensitive": True,
                    "description": "AWS Access Key ID",
                    "env_var": "AWS_ACCESS_KEY_ID",
                    "secret_name": "aws_access_key_id"
                },
                "secret_access_key": {
                    "default": None,
                    "required": False,
                    "sensitive": True,
                    "description": "AWS Secret Access Key",
                    "env_var": "AWS_SECRET_ACCESS_KEY",
                    "secret_name": "aws_secret_access_key"
                },
                "region": {
                    "default": "us-west-2",
                    "required": False,
                    "description": "AWS Default Region",
                    "env_var": "AWS_DEFAULT_REGION"
                }
            },
            
            "gcp": {
                "project_id": {
                    "default": None,
                    "required": False,
                    "description": "GCP Project ID",
                    "env_var": "GCP_PROJECT_ID"
                },
                "credentials_path": {
                    "default": None,
                    "required": False,
                    "sensitive": True,
                    "description": "Path to GCP service account credentials",
                    "env_var": "GOOGLE_APPLICATION_CREDENTIALS"
                },
                "organization_id": {
                    "default": None,
                    "required": False,
                    "description": "GCP Organization ID",
                    "env_var": "GCP_ORGANIZATION_ID"
                }
            },
            
            "azure": {
                "tenant_id": {
                    "default": None,
                    "required": False,
                    "description": "Azure Tenant ID",
                    "env_var": "AZURE_TENANT_ID"
                },
                "client_id": {
                    "default": None,
                    "required": False,
                    "description": "Azure Client ID",
                    "env_var": "AZURE_CLIENT_ID"
                },
                "client_secret": {
                    "default": None,
                    "required": False,
                    "sensitive": True,
                    "description": "Azure Client Secret",
                    "env_var": "AZURE_CLIENT_SECRET",
                    "secret_name": "azure_client_secret"
                },
                "subscription_id": {
                    "default": None,
                    "required": False,
                    "description": "Azure Subscription ID",
                    "env_var": "AZURE_SUBSCRIPTION_ID"
                }
            },
            
            # Application Configuration
            "app": {
                "debug": {
                    "default": False,
                    "required": False,
                    "description": "Enable debug mode",
                    "env_var": "DEBUG",
                    "type": bool
                },
                "log_level": {
                    "default": "INFO",
                    "required": False,
                    "description": "Logging level",
                    "env_var": "LOG_LEVEL",
                    "choices": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
                },
                "port": {
                    "default": 8501,
                    "required": False,
                    "description": "Application port",
                    "env_var": "PORT",
                    "type": int
                },
                "host": {
                    "default": "0.0.0.0",
                    "required": False,
                    "description": "Application host",
                    "env_var": "HOST"
                },
                "secret_key": {
                    "default": None,
                    "required": True,
                    "sensitive": True,
                    "description": "Application secret key",
                    "env_var": "SECRET_KEY",
                    "secret_name": "app_secret_key"
                }
            },
            
            # Security Configuration
            "security": {
                "encryption_key": {
                    "default": None,
                    "required": True,
                    "sensitive": True,
                    "description": "Encryption key for sensitive data",
                    "env_var": "AUDITHOUND_ENCRYPTION_KEY",
                    "secret_name": "encryption_key"
                },
                "jwt_secret": {
                    "default": None,
                    "required": False,
                    "sensitive": True,
                    "description": "JWT signing secret",
                    "env_var": "JWT_SECRET",
                    "secret_name": "jwt_secret"
                },
                "session_timeout": {
                    "default": 3600,
                    "required": False,
                    "description": "Session timeout in seconds",
                    "env_var": "SESSION_TIMEOUT",
                    "type": int
                }
            },
            
            # Third-party Integrations
            "integrations": {
                "thehive_url": {
                    "default": None,
                    "required": False,
                    "description": "TheHive instance URL",
                    "env_var": "THEHIVE_URL"
                },
                "thehive_api_key": {
                    "default": None,
                    "required": False,
                    "sensitive": True,
                    "description": "TheHive API key",
                    "env_var": "THEHIVE_API_KEY",
                    "secret_name": "thehive_api_key"
                },
                "misp_url": {
                    "default": None,
                    "required": False,
                    "description": "MISP instance URL",
                    "env_var": "MISP_URL"
                },
                "misp_api_key": {
                    "default": None,
                    "required": False,
                    "sensitive": True,
                    "description": "MISP API key",
                    "env_var": "MISP_API_KEY",
                    "secret_name": "misp_api_key"
                },
                "slack_webhook_url": {
                    "default": None,
                    "required": False,
                    "sensitive": True,
                    "description": "Slack webhook URL for notifications",
                    "env_var": "SLACK_WEBHOOK_URL",
                    "secret_name": "slack_webhook_url"
                }
            },
            
            # Secrets Management
            "secrets": {
                "vault_url": {
                    "default": "http://localhost:8200",
                    "required": False,
                    "description": "HashiCorp Vault URL",
                    "env_var": "VAULT_ADDR"
                },
                "vault_token": {
                    "default": None,
                    "required": False,
                    "sensitive": True,
                    "description": "HashiCorp Vault token",
                    "env_var": "VAULT_TOKEN",
                    "secret_name": "vault_token"
                },
                "aws_secrets_region": {
                    "default": "us-west-2",
                    "required": False,
                    "description": "AWS Secrets Manager region",
                    "env_var": "AWS_SECRETS_REGION"
                }
            },
            
            # MSP Configuration
            "msp": {
                "mode_enabled": {
                    "default": False,
                    "required": False,
                    "description": "Enable MSP mode",
                    "env_var": "MSP_MODE_ENABLED",
                    "type": bool
                },
                "white_label_enabled": {
                    "default": False,
                    "required": False,
                    "description": "Enable white-label branding",
                    "env_var": "WHITE_LABEL_ENABLED",
                    "type": bool
                },
                "trial_period_days": {
                    "default": 14,
                    "required": False,
                    "description": "Trial period in days",
                    "env_var": "TRIAL_PERIOD_DAYS",
                    "type": int
                }
            }
        }
    
    def _load_configuration(self):
        """Load configuration from all sources"""
        # Load from config file first (lowest precedence)
        if self.config_file and Path(self.config_file).exists():
            self._load_from_file()
        
        # Load from schema with environment variables and secrets
        for section, configs in self.config_schema.items():
            for key, config_def in configs.items():
                full_key = f"{section}.{key}"
                value = self._get_config_value(config_def)
                
                config_value = ConfigValue(
                    key=full_key,
                    value=value,
                    source=self._determine_source(config_def, value),
                    sensitive=config_def.get("sensitive", False),
                    required=config_def.get("required", False),
                    description=config_def.get("description", "")
                )
                
                self.config_values[full_key] = config_value
        
        # Validate required configuration
        self._validate_configuration()
    
    def _get_config_value(self, config_def: Dict[str, Any]) -> Any:
        """Get configuration value from the highest precedence source"""
        # 1. Environment variable (highest precedence)
        env_var = config_def.get("env_var")
        if env_var:
            env_value = os.getenv(env_var)
            if env_value is not None:
                return self._convert_type(env_value, config_def.get("type", str))
        
        # 2. Secrets manager
        secret_name = config_def.get("secret_name")
        if secret_name:
            secret_value = get_secret(secret_name)
            if secret_value is not None:
                return self._convert_type(secret_value, config_def.get("type", str))
        
        # 3. Default value (lowest precedence)
        default_value = config_def.get("default")
        if default_value is not None:
            return self._convert_type(default_value, config_def.get("type", str))
        
        return None
    
    def _convert_type(self, value: Any, target_type: type) -> Any:
        """Convert value to target type"""
        if target_type == bool:
            if isinstance(value, str):
                return value.lower() in ("true", "1", "yes", "on")
            return bool(value)
        elif target_type == int:
            return int(value)
        elif target_type == float:
            return float(value)
        else:
            return str(value)
    
    def _determine_source(self, config_def: Dict[str, Any], value: Any) -> ConfigSource:
        """Determine the source of a configuration value"""
        # Check environment variable
        env_var = config_def.get("env_var")
        if env_var and os.getenv(env_var) is not None:
            return ConfigSource.ENVIRONMENT
        
        # Check secrets manager
        secret_name = config_def.get("secret_name")
        if secret_name and get_secret(secret_name) is not None:
            return ConfigSource.SECRETS_MANAGER
        
        # Check if it's from config file
        # (This would require tracking during file load)
        
        # Default value
        if value == config_def.get("default"):
            return ConfigSource.DEFAULT
        
        return ConfigSource.DEFAULT
    
    def _load_from_file(self):
        """Load configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                if self.config_file.endswith('.json'):
                    file_config = json.load(f)
                else:
                    # Assume YAML
                    import yaml
                    file_config = yaml.safe_load(f)
            
            # Store file configuration (implementation would track source)
            logger.info(f"Loaded configuration from file: {self.config_file}")
        except Exception as e:
            logger.error(f"Failed to load configuration file {self.config_file}: {e}")
    
    def _validate_configuration(self):
        """Validate required configuration values"""
        missing_required = []
        
        for key, config_value in self.config_values.items():
            if config_value.required and config_value.value is None:
                missing_required.append(key)
        
        if missing_required:
            error_msg = f"Missing required configuration: {', '.join(missing_required)}"
            logger.error(error_msg)
            raise ValueError(error_msg)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        config_value = self.config_values.get(key)
        if config_value:
            return config_value.value
        return default
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get all configuration values for a section"""
        result = {}
        prefix = f"{section}."
        
        for key, config_value in self.config_values.items():
            if key.startswith(prefix):
                section_key = key[len(prefix):]
                result[section_key] = config_value.value
        
        return result
    
    def get_database_config(self) -> Dict[str, Any]:
        """Get database configuration"""
        return self.get_section("database")
    
    def get_aws_config(self) -> Dict[str, Any]:
        """Get AWS configuration"""
        return self.get_section("aws")
    
    def get_gcp_config(self) -> Dict[str, Any]:
        """Get GCP configuration"""
        return self.get_section("gcp")
    
    def get_azure_config(self) -> Dict[str, Any]:
        """Get Azure configuration"""
        return self.get_section("azure")
    
    def get_security_config(self) -> Dict[str, Any]:
        """Get security configuration"""
        return self.get_section("security")
    
    def get_app_config(self) -> Dict[str, Any]:
        """Get application configuration"""
        return self.get_section("app")
    
    def is_debug_enabled(self) -> bool:
        """Check if debug mode is enabled"""
        return self.get("app.debug", False)
    
    def is_msp_mode_enabled(self) -> bool:
        """Check if MSP mode is enabled"""
        return self.get("msp.mode_enabled", False)
    
    def get_config_summary(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Get configuration summary"""
        summary = {
            "total_configs": len(self.config_values),
            "sources": {},
            "sections": {},
            "sensitive_configs": 0,
            "required_configs": 0,
            "configs": {}
        }
        
        for key, config_value in self.config_values.items():
            # Count by source
            source = config_value.source.value
            summary["sources"][source] = summary["sources"].get(source, 0) + 1
            
            # Count by section
            section = key.split('.')[0]
            summary["sections"][section] = summary["sections"].get(section, 0) + 1
            
            # Count sensitive and required
            if config_value.sensitive:
                summary["sensitive_configs"] += 1
            if config_value.required:
                summary["required_configs"] += 1
            
            # Add config info
            config_info = {
                "source": source,
                "required": config_value.required,
                "sensitive": config_value.sensitive,
                "description": config_value.description
            }
            
            if include_sensitive or not config_value.sensitive:
                config_info["value"] = config_value.value
            else:
                config_info["value"] = "***HIDDEN***" if config_value.value else None
            
            summary["configs"][key] = config_info
        
        return summary
    
    def generate_env_template(self, output_file: str = ".env.template"):
        """Generate environment variable template file"""
        template_lines = [
            "# AuditHound Environment Configuration Template",
            "# Copy this file to .env and fill in the values",
            "",
            "# Required environment variables are marked with (REQUIRED)",
            "# Sensitive values should be set through environment variables or secrets manager",
            ""
        ]
        
        current_section = None
        for section, configs in self.config_schema.items():
            if section != current_section:
                template_lines.append(f"# {section.upper()} Configuration")
                template_lines.append("")
                current_section = section
            
            for key, config_def in configs.items():
                env_var = config_def.get("env_var")
                if env_var:
                    description = config_def.get("description", "")
                    required = " (REQUIRED)" if config_def.get("required", False) else ""
                    sensitive = " (SENSITIVE)" if config_def.get("sensitive", False) else ""
                    default = config_def.get("default", "")
                    
                    template_lines.append(f"# {description}{required}{sensitive}")
                    template_lines.append(f"{env_var}={default}")
                    template_lines.append("")
        
        with open(output_file, 'w') as f:
            f.write('\n'.join(template_lines))
        
        logger.info(f"Generated environment template: {output_file}")
    
    def validate_environment(self) -> Dict[str, Any]:
        """Validate current environment configuration"""
        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "missing_optional": [],
            "config_sources": {}
        }
        
        for key, config_value in self.config_values.items():
            # Track configuration sources
            source = config_value.source.value
            if source not in validation_result["config_sources"]:
                validation_result["config_sources"][source] = []
            validation_result["config_sources"][source].append(key)
            
            # Check required values
            if config_value.required and config_value.value is None:
                validation_result["errors"].append(f"Required configuration missing: {key}")
                validation_result["valid"] = False
            
            # Check optional values
            if not config_value.required and config_value.value is None:
                validation_result["missing_optional"].append(key)
            
            # Warn about sensitive values in environment
            if (config_value.sensitive and 
                config_value.source == ConfigSource.ENVIRONMENT and 
                config_value.value is not None):
                validation_result["warnings"].append(
                    f"Sensitive value '{key}' found in environment variables. "
                    "Consider using secrets manager."
                )
        
        return validation_result

# Global configuration manager instance
_global_config_manager = None

def get_config() -> ConfigManager:
    """Get global configuration manager instance"""
    global _global_config_manager
    if _global_config_manager is None:
        _global_config_manager = ConfigManager()
    return _global_config_manager

def get_config_value(key: str, default: Any = None) -> Any:
    """Get configuration value using global manager"""
    return get_config().get(key, default)

# Convenience functions for common configurations
def get_database_url() -> Optional[str]:
    """Get database URL"""
    config = get_config()
    weaviate_url = config.get("database.weaviate_url")
    return weaviate_url

def get_aws_credentials() -> Dict[str, str]:
    """Get AWS credentials"""
    config = get_config()
    return {
        "access_key_id": config.get("aws.access_key_id"),
        "secret_access_key": config.get("aws.secret_access_key"),
        "region": config.get("aws.region", "us-west-2")
    }

def get_encryption_key() -> Optional[str]:
    """Get encryption key"""
    return get_config_value("security.encryption_key")

def is_debug_mode() -> bool:
    """Check if debug mode is enabled"""
    return get_config().is_debug_enabled()

def is_msp_mode() -> bool:
    """Check if MSP mode is enabled"""
    return get_config().is_msp_mode_enabled()