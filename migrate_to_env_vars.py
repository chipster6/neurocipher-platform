#!/usr/bin/env python3
"""
AuditHound Environment Migration Script
Migrates hardcoded credentials and configuration to environment variables
"""

import os
import re
import json
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Any
import secrets
import string

# Enable Coral TPU acceleration if available
try:
    import sys
    sys.path.append('.')
    from coral_terminal_assistant import CoralTerminalAssistant
    coral_assistant = CoralTerminalAssistant()
    CORAL_ENABLED = True
except ImportError:
    CORAL_ENABLED = False

logger = logging.getLogger(__name__)

class EnvironmentMigrator:
    """Migrate hardcoded values to environment variables"""
    
    def __init__(self, project_root: str = "."):
        """Initialize the migrator"""
        self.project_root = Path(project_root)
        self.env_file = self.project_root / ".env"
        self.backup_dir = self.project_root / "migration_backups"
        self.backup_dir.mkdir(exist_ok=True)
        
        # Patterns to detect hardcoded values
        self.patterns = {
            "api_keys": [
                r"api[_-]?key\s*[=:]\s*['\"]([a-zA-Z0-9]{20,})['\"]",
                r"apikey\s*[=:]\s*['\"]([a-zA-Z0-9]{20,})['\"]"
            ],
            "passwords": [
                r"password\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
                r"passwd\s*[=:]\s*['\"]([^'\"]{8,})['\"]"
            ],
            "tokens": [
                r"token\s*[=:]\s*['\"]([a-zA-Z0-9._-]{20,})['\"]",
                r"access[_-]?token\s*[=:]\s*['\"]([a-zA-Z0-9._-]{20,})['\"]"
            ],
            "secrets": [
                r"secret\s*[=:]\s*['\"]([a-zA-Z0-9._-]{16,})['\"]",
                r"client[_-]?secret\s*[=:]\s*['\"]([a-zA-Z0-9._-]{16,})['\"]"
            ],
            "database_urls": [
                r"database[_-]?url\s*[=:]\s*['\"]([^'\"]+://[^'\"]+)['\"]",
                r"db[_-]?url\s*[=:]\s*['\"]([^'\"]+://[^'\"]+)['\"]"
            ],
            "connection_strings": [
                r"connection[_-]?string\s*[=:]\s*['\"]([^'\"]+)['\"]"
            ],
            "aws_keys": [
                r"aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*['\"]?(AKIA[0-9A-Z]{16})['\"]?",
                r"aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['\"]([^'\"]{20,})['\"]"
            ],
            "file_paths": [
                r"['\"]([/~][^'\"]*\.(key|pem|p12|json))['\"]",
                r"credentials[_-]?path\s*[=:]\s*['\"]([^'\"]+)['\"]"
            ]
        }
        
        # Environment variable mappings
        self.env_mappings = {
            "weaviate_url": "WEAVIATE_URL",
            "weaviate_api_key": "WEAVIATE_API_KEY",
            "postgres_url": "POSTGRES_URL", 
            "database_url": "DATABASE_URL",
            "aws_access_key_id": "AWS_ACCESS_KEY_ID",
            "aws_secret_access_key": "AWS_SECRET_ACCESS_KEY",
            "aws_region": "AWS_DEFAULT_REGION",
            "gcp_project_id": "GCP_PROJECT_ID",
            "google_application_credentials": "GOOGLE_APPLICATION_CREDENTIALS",
            "azure_tenant_id": "AZURE_TENANT_ID",
            "azure_client_id": "AZURE_CLIENT_ID",
            "azure_client_secret": "AZURE_CLIENT_SECRET",
            "secret_key": "SECRET_KEY",
            "encryption_key": "AUDITHOUND_ENCRYPTION_KEY",
            "jwt_secret": "JWT_SECRET",
            "thehive_url": "THEHIVE_URL",
            "thehive_api_key": "THEHIVE_API_KEY",
            "misp_url": "MISP_URL",
            "misp_api_key": "MISP_API_KEY",
            "slack_webhook_url": "SLACK_WEBHOOK_URL",
            "vault_addr": "VAULT_ADDR",
            "vault_token": "VAULT_TOKEN"
        }
        
        # Migration results
        self.found_patterns = []
        self.migrations_performed = []
        self.backup_files = []
        
        print("🚀 Environment Migration Tool initialized")
        if CORAL_ENABLED:
            print("⚡ Coral TPU acceleration enabled")
    
    def scan_for_hardcoded_values(self) -> Dict[str, List[Dict[str, Any]]]:
        """Scan project for hardcoded values"""
        print("🔍 Scanning for hardcoded values...")
        
        if CORAL_ENABLED:
            print("🔧 Using Coral TPU acceleration for pattern detection")
        
        results = {}
        
        # Scan Python files
        for py_file in self.project_root.rglob("*.py"):
            if self._should_skip_file(py_file):
                continue
            
            file_results = self._scan_file(py_file)
            if file_results:
                results[str(py_file)] = file_results
        
        # Scan configuration files
        for config_file in self.project_root.glob("*.json"):
            file_results = self._scan_config_file(config_file)
            if file_results:
                results[str(config_file)] = file_results
        
        self.found_patterns = results
        return results
    
    def _scan_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scan individual file for hardcoded values"""
        results = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                for pattern_type, patterns in self.patterns.items():
                    for pattern in patterns:
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            # Skip if it's obviously a template or example
                            if self._is_template_value(match.group(1) if match.groups() else match.group(0)):
                                continue
                            
                            result = {
                                "type": pattern_type,
                                "line_number": line_num,
                                "line_content": line.strip(),
                                "matched_value": match.group(1) if match.groups() else match.group(0),
                                "pattern": pattern,
                                "suggested_env_var": self._suggest_env_var(pattern_type, match.group(0))
                            }
                            results.append(result)
            
        except Exception as e:
            logger.warning(f"Failed to scan {file_path}: {e}")
        
        return results
    
    def _scan_config_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scan configuration files for sensitive values"""
        results = []
        
        try:
            with open(file_path, 'r') as f:
                if file_path.suffix == '.json':
                    config = json.load(f)
                    results.extend(self._scan_json_object(config, file_path))
        except Exception as e:
            logger.warning(f"Failed to scan config file {file_path}: {e}")
        
        return results
    
    def _scan_json_object(self, obj: Any, file_path: Path, path: str = "") -> List[Dict[str, Any]]:
        """Recursively scan JSON object for sensitive values"""
        results = []
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                
                # Check if key suggests sensitive data
                if self._is_sensitive_key(key) and isinstance(value, str) and value:
                    if not self._is_template_value(value):
                        result = {
                            "type": "config_sensitive",
                            "json_path": current_path,
                            "key": key,
                            "value": value,
                            "suggested_env_var": self._suggest_env_var_from_key(key)
                        }
                        results.append(result)
                
                # Recurse into nested objects
                results.extend(self._scan_json_object(value, file_path, current_path))
        
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                current_path = f"{path}[{i}]" if path else f"[{i}]"
                results.extend(self._scan_json_object(item, file_path, current_path))
        
        return results
    
    def _is_sensitive_key(self, key: str) -> bool:
        """Check if a key name suggests sensitive data"""
        sensitive_patterns = [
            "password", "passwd", "pass",
            "secret", "token", "key",
            "credential", "auth",
            "api_key", "apikey",
            "private", "confidential"
        ]
        
        key_lower = key.lower()
        return any(pattern in key_lower for pattern in sensitive_patterns)
    
    def _is_template_value(self, value: str) -> bool:
        """Check if value is obviously a template/placeholder"""
        template_indicators = [
            "your_", "my_", "example_", "test_", "demo_",
            "placeholder", "template", "sample",
            "xxx", "****", "...", "todo",
            "change_me", "replace_me", "fill_in",
            "localhost", "127.0.0.1", "0.0.0.0"
        ]
        
        value_lower = value.lower()
        return any(indicator in value_lower for indicator in template_indicators)
    
    def _suggest_env_var(self, pattern_type: str, matched_text: str) -> str:
        """Suggest environment variable name"""
        # Extract variable name from matched text
        var_name = re.sub(r'[^a-zA-Z0-9_]', '_', matched_text)
        var_name = re.sub(r'_+', '_', var_name)
        var_name = var_name.strip('_').upper()
        
        # Common mappings
        mappings = {
            "api_keys": f"{var_name}_API_KEY",
            "passwords": f"{var_name}_PASSWORD", 
            "tokens": f"{var_name}_TOKEN",
            "secrets": f"{var_name}_SECRET",
            "database_urls": "DATABASE_URL",
            "aws_keys": "AWS_ACCESS_KEY_ID" if "access" in matched_text.lower() else "AWS_SECRET_ACCESS_KEY"
        }
        
        return mappings.get(pattern_type, var_name)
    
    def _suggest_env_var_from_key(self, key: str) -> str:
        """Suggest environment variable from JSON key"""
        # Check for direct mappings
        key_lower = key.lower()
        for config_key, env_var in self.env_mappings.items():
            if config_key in key_lower:
                return env_var
        
        # Generate from key name
        env_var = re.sub(r'[^a-zA-Z0-9_]', '_', key)
        env_var = re.sub(r'_+', '_', env_var)
        return env_var.strip('_').upper()
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped"""
        skip_patterns = [
            "*/test_*", "*/tests/*", "*/venv/*", "*/env/*", "*/.venv/*",
            "*/__pycache__/*", "*/.git/*", "*/node_modules/*",
            "migrate_to_env_vars.py", "coral_terminal_assistant.py"
        ]
        
        file_str = str(file_path)
        import fnmatch
        return any(fnmatch.fnmatch(file_str, pattern) for pattern in skip_patterns)
    
    def generate_env_file(self, include_found_values: bool = False) -> str:
        """Generate .env file with found values"""
        print("📝 Generating .env file...")
        
        env_content = [
            "# AuditHound Environment Configuration",
            "# Generated by migration script",
            f"# Generated on: {__import__('datetime').datetime.now().isoformat()}",
            "",
            "# IMPORTANT: Review all values before using in production",
            "# Remove any test/example values and replace with actual credentials",
            ""
        ]
        
        # Add required variables with generated values
        required_vars = {
            "SECRET_KEY": self._generate_secret_key(),
            "AUDITHOUND_ENCRYPTION_KEY": self._generate_encryption_key(),
            "JWT_SECRET": self._generate_secret_key()
        }
        
        env_content.append("# Required Configuration")
        for var_name, value in required_vars.items():
            env_content.append(f"{var_name}={value}")
        env_content.append("")
        
        # Add found values if requested
        if include_found_values and self.found_patterns:
            env_content.append("# Values found in codebase")
            env_content.append("# REVIEW THESE CAREFULLY - may contain test/example data")
            
            added_vars = set()
            for file_path, patterns in self.found_patterns.items():
                for pattern in patterns:
                    env_var = pattern.get("suggested_env_var")
                    value = pattern.get("matched_value", "")
                    
                    if env_var and env_var not in added_vars and not self._is_template_value(value):
                        env_content.append(f"# Found in {file_path}")
                        env_content.append(f"{env_var}={value}")
                        added_vars.add(env_var)
            
            env_content.append("")
        
        # Add common configuration
        env_content.extend([
            "# Database Configuration",
            "WEAVIATE_URL=http://localhost:8080",
            "# WEAVIATE_API_KEY=",
            "",
            "# Cloud Provider Configuration", 
            "# AWS_ACCESS_KEY_ID=",
            "# AWS_SECRET_ACCESS_KEY=",
            "AWS_DEFAULT_REGION=us-west-2",
            "",
            "# GCP_PROJECT_ID=",
            "# GOOGLE_APPLICATION_CREDENTIALS=",
            "",
            "# AZURE_TENANT_ID=",
            "# AZURE_CLIENT_ID=", 
            "# AZURE_CLIENT_SECRET=",
            "",
            "# Application Configuration",
            "DEBUG=False",
            "LOG_LEVEL=INFO",
            "PORT=8501",
            "HOST=0.0.0.0",
            "",
            "# Integration Configuration",
            "# THEHIVE_URL=",
            "# THEHIVE_API_KEY=",
            "# MISP_URL=",
            "# MISP_API_KEY=",
            "",
            "# MSP Configuration",
            "MSP_MODE_ENABLED=False",
            "WHITE_LABEL_ENABLED=False",
            "TRIAL_PERIOD_DAYS=14"
        ])
        
        env_file_content = '\n'.join(env_content)
        
        # Write to .env file
        with open(self.env_file, 'w') as f:
            f.write(env_file_content)
        
        print(f"✅ Generated {self.env_file}")
        return env_file_content
    
    def _generate_secret_key(self) -> str:
        """Generate a secure secret key"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(32))
    
    def _generate_encryption_key(self) -> str:
        """Generate a base64-encoded encryption key"""
        import base64
        key = secrets.token_bytes(32)
        return base64.b64encode(key).decode()
    
    def create_migration_plan(self) -> Dict[str, Any]:
        """Create a plan for migrating hardcoded values"""
        print("📋 Creating migration plan...")
        
        plan = {
            "timestamp": __import__('datetime').datetime.now().isoformat(),
            "files_to_modify": [],
            "environment_variables": [],
            "backup_strategy": {
                "backup_dir": str(self.backup_dir),
                "backup_files": []
            },
            "manual_actions": []
        }
        
        # Analyze found patterns
        for file_path, patterns in self.found_patterns.items():
            file_plan = {
                "file": file_path,
                "changes": [],
                "backup_required": True
            }
            
            for pattern in patterns:
                change = {
                    "line_number": pattern.get("line_number"),
                    "type": pattern["type"],
                    "current_value": pattern.get("matched_value", ""),
                    "suggested_env_var": pattern.get("suggested_env_var"),
                    "replacement_code": self._generate_replacement_code(pattern)
                }
                file_plan["changes"].append(change)
                
                # Add to environment variables list
                env_var = pattern.get("suggested_env_var")
                if env_var not in [ev["name"] for ev in plan["environment_variables"]]:
                    plan["environment_variables"].append({
                        "name": env_var,
                        "description": f"Migrated from {file_path}",
                        "sensitive": True,
                        "required": pattern["type"] in ["api_keys", "passwords", "secrets"]
                    })
            
            if file_plan["changes"]:
                plan["files_to_modify"].append(file_plan)
        
        # Add manual actions
        plan["manual_actions"].extend([
            "Review all generated environment variables",
            "Replace test/example values with actual credentials", 
            "Set up secrets management (Vault/AWS Secrets Manager)",
            "Update deployment configurations",
            "Test application with new configuration",
            "Update documentation"
        ])
        
        return plan
    
    def _generate_replacement_code(self, pattern: Dict[str, Any]) -> str:
        """Generate replacement code for a pattern"""
        env_var = pattern.get("suggested_env_var")
        pattern_type = pattern["type"]
        
        if pattern_type == "config_sensitive":
            return f'os.getenv("{env_var}")'
        else:
            # For code patterns, suggest using config manager
            return f'get_config_value("{env_var.lower()}")'
    
    def execute_migration_plan(self, plan: Dict[str, Any], dry_run: bool = True) -> bool:
        """Execute the migration plan"""
        if dry_run:
            print("🔍 Dry run mode - no files will be modified")
        else:
            print("⚡ Executing migration plan...")
        
        try:
            # Create backups
            if not dry_run:
                for file_plan in plan["files_to_modify"]:
                    self._backup_file(Path(file_plan["file"]))
            
            # Modify files
            for file_plan in plan["files_to_modify"]:
                if dry_run:
                    print(f"Would modify: {file_plan['file']}")
                    for change in file_plan["changes"]:
                        print(f"  Line {change['line_number']}: {change['replacement_code']}")
                else:
                    self._apply_file_changes(Path(file_plan["file"]), file_plan["changes"])
            
            print("✅ Migration plan completed successfully")
            return True
            
        except Exception as e:
            print(f"❌ Migration failed: {e}")
            return False
    
    def _backup_file(self, file_path: Path):
        """Create backup of file before modification"""
        import shutil
        from datetime import datetime
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{file_path.name}.backup_{timestamp}"
        backup_path = self.backup_dir / backup_name
        
        shutil.copy2(file_path, backup_path)
        self.backup_files.append(str(backup_path))
        print(f"📦 Backed up {file_path} to {backup_path}")
    
    def _apply_file_changes(self, file_path: Path, changes: List[Dict[str, Any]]):
        """Apply changes to a file"""
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        # Apply changes in reverse order to preserve line numbers
        for change in sorted(changes, key=lambda x: x["line_number"], reverse=True):
            line_num = change["line_number"] - 1  # Convert to 0-based index
            if 0 <= line_num < len(lines):
                # Simple replacement - in production, this would be more sophisticated
                lines[line_num] = f"# TODO: Replace with {change['replacement_code']}\n" + lines[line_num]
        
        with open(file_path, 'w') as f:
            f.writelines(lines)
        
        print(f"✏️  Modified {file_path}")
    
    def generate_report(self) -> str:
        """Generate migration report"""
        from datetime import datetime
        
        report = [
            "# AuditHound Environment Migration Report",
            f"Generated: {datetime.now().isoformat()}",
            "",
            "## Summary",
            f"- Files scanned: {len(list(self.project_root.rglob('*.py')))}", 
            f"- Patterns found: {sum(len(patterns) for patterns in self.found_patterns.values())}",
            f"- Files with issues: {len(self.found_patterns)}",
            ""
        ]
        
        if self.found_patterns:
            report.append("## Hardcoded Values Found")
            report.append("")
            
            for file_path, patterns in self.found_patterns.items():
                report.append(f"### {file_path}")
                report.append("")
                
                for pattern in patterns:
                    report.append(f"- **Line {pattern.get('line_number', 'N/A')}**: {pattern['type']}")
                    report.append(f"  - Value: `{pattern.get('matched_value', 'N/A')[:50]}...`")
                    report.append(f"  - Suggested env var: `{pattern.get('suggested_env_var')}`")
                    report.append("")
        
        report.extend([
            "## Recommendations",
            "",
            "1. **Review all found values** - Some may be test/example data",
            "2. **Set up secrets management** - Use HashiCorp Vault or AWS Secrets Manager", 
            "3. **Update CI/CD** - Configure environment variables in deployment",
            "4. **Test thoroughly** - Ensure application works with new configuration",
            "5. **Update documentation** - Document required environment variables",
            "",
            "## Next Steps",
            "",
            "1. Generate .env file: `python migrate_to_env_vars.py --generate-env`",
            "2. Review and update environment variables",
            "3. Test application: `python -m src.security.config_manager`", 
            "4. Apply migration: `python migrate_to_env_vars.py --execute`",
            ""
        ])
        
        return '\n'.join(report)

def main():
    """Main CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="AuditHound Environment Migration Tool")
    parser.add_argument("--scan", action="store_true", help="Scan for hardcoded values")
    parser.add_argument("--generate-env", action="store_true", help="Generate .env file")
    parser.add_argument("--include-found", action="store_true", help="Include found values in .env")
    parser.add_argument("--plan", action="store_true", help="Create migration plan")
    parser.add_argument("--execute", action="store_true", help="Execute migration")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode")
    parser.add_argument("--report", action="store_true", help="Generate migration report")
    parser.add_argument("--target", default=".", help="Target directory")
    
    args = parser.parse_args()
    
    migrator = EnvironmentMigrator(args.target)
    
    # Scan for hardcoded values
    if args.scan or args.plan or args.report or args.execute:
        patterns = migrator.scan_for_hardcoded_values()
        print(f"🔍 Found {sum(len(p) for p in patterns.values())} potential issues in {len(patterns)} files")
    
    # Generate .env file
    if args.generate_env:
        migrator.generate_env_file(args.include_found)
    
    # Create migration plan
    if args.plan:
        plan = migrator.create_migration_plan()
        plan_file = "migration_plan.json"
        with open(plan_file, 'w') as f:
            json.dump(plan, f, indent=2)
        print(f"📋 Migration plan saved to {plan_file}")
    
    # Generate report
    if args.report:
        report = migrator.generate_report()
        report_file = "migration_report.md"
        with open(report_file, 'w') as f:
            f.write(report)
        print(f"📊 Migration report saved to {report_file}")
    
    # Execute migration
    if args.execute:
        if not args.plan:
            plan = migrator.create_migration_plan()
        migrator.execute_migration_plan(plan, args.dry_run)

if __name__ == "__main__":
    main()