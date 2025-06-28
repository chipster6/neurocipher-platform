#!/usr/bin/env python3
"""
AuditHound Security Scanner
Automated security scanning with bandit, safety, and custom checks
"""

import os
import json
import subprocess
import tempfile
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path
import time
from enum import Enum

logger = logging.getLogger(__name__)

class SeverityLevel(Enum):
    """Security issue severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ScanType(Enum):
    """Types of security scans"""
    STATIC_ANALYSIS = "static_analysis"
    DEPENDENCY_CHECK = "dependency_check"
    SECRETS_DETECTION = "secrets_detection"
    CONFIGURATION_AUDIT = "configuration_audit"

@dataclass
class SecurityIssue:
    """Security issue found during scanning"""
    scan_type: ScanType
    severity: SeverityLevel
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    rule_id: Optional[str] = None
    cwe_id: Optional[str] = None
    confidence: Optional[str] = None
    recommendation: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "scan_type": self.scan_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "rule_id": self.rule_id,
            "cwe_id": self.cwe_id,
            "confidence": self.confidence,
            "recommendation": self.recommendation
        }

@dataclass
class ScanResult:
    """Results from a security scan"""
    scan_type: ScanType
    timestamp: float
    duration: float
    issues: List[SecurityIssue] = field(default_factory=list)
    files_scanned: int = 0
    scan_successful: bool = True
    error_message: Optional[str] = None
    
    def get_issues_by_severity(self, severity: SeverityLevel) -> List[SecurityIssue]:
        """Get issues by severity level"""
        return [issue for issue in self.issues if issue.severity == severity]
    
    def get_critical_count(self) -> int:
        """Get count of critical issues"""
        return len(self.get_issues_by_severity(SeverityLevel.CRITICAL))
    
    def get_high_count(self) -> int:
        """Get count of high severity issues"""
        return len(self.get_issues_by_severity(SeverityLevel.HIGH))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "scan_type": self.scan_type.value,
            "timestamp": self.timestamp,
            "duration": self.duration,
            "issues": [issue.to_dict() for issue in self.issues],
            "files_scanned": self.files_scanned,
            "scan_successful": self.scan_successful,
            "error_message": self.error_message,
            "summary": {
                "total_issues": len(self.issues),
                "critical": self.get_critical_count(),
                "high": self.get_high_count(),
                "medium": len(self.get_issues_by_severity(SeverityLevel.MEDIUM)),
                "low": len(self.get_issues_by_severity(SeverityLevel.LOW))
            }
        }

class SecurityScanner:
    """Comprehensive security scanner for AuditHound"""
    
    def __init__(self, project_root: str = "."):
        """Initialize security scanner"""
        self.project_root = Path(project_root)
        self.results_dir = self.project_root / "security_reports"
        self.results_dir.mkdir(exist_ok=True)
        
        # Check tool availability
        self.tools_available = self._check_tool_availability()
        
        logger.info(f"Security scanner initialized for {project_root}")
        logger.info(f"Available tools: {list(self.tools_available.keys())}")
    
    def _check_tool_availability(self) -> Dict[str, bool]:
        """Check which security tools are available"""
        tools = {}
        
        # Check bandit
        try:
            subprocess.run(["bandit", "--version"], 
                         capture_output=True, check=True, timeout=10)
            tools["bandit"] = True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            tools["bandit"] = False
            logger.warning("Bandit not available. Install with: pip install bandit")
        
        # Check safety
        try:
            subprocess.run(["safety", "--version"], 
                         capture_output=True, check=True, timeout=10)
            tools["safety"] = True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            tools["safety"] = False
            logger.warning("Safety not available. Install with: pip install safety")
        
        # Check semgrep (optional)
        try:
            subprocess.run(["semgrep", "--version"], 
                         capture_output=True, check=True, timeout=10)
            tools["semgrep"] = True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            tools["semgrep"] = False
            logger.info("Semgrep not available (optional)")
        
        return tools
    
    def run_bandit_scan(self, target_path: str = None) -> ScanResult:
        """Run bandit static analysis security scan"""
        start_time = time.time()
        target = target_path or str(self.project_root)
        
        result = ScanResult(
            scan_type=ScanType.STATIC_ANALYSIS,
            timestamp=start_time,
            duration=0
        )
        
        if not self.tools_available.get("bandit", False):
            result.scan_successful = False
            result.error_message = "Bandit not available"
            result.duration = time.time() - start_time
            return result
        
        try:
            # Run bandit scan
            cmd = [
                "bandit",
                "-r", target,
                "-f", "json",
                "--exclude", "*/tests/*,*/test_*,*/venv/*,*/env/*,*/.venv/*"
            ]
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Parse bandit results
            if process.stdout:
                bandit_data = json.loads(process.stdout)
                
                # Count files scanned
                result.files_scanned = len(bandit_data.get("metrics", {}).get("_totals", {}).get("loc", 0))
                
                # Parse issues
                for issue_data in bandit_data.get("results", []):
                    severity_map = {
                        "LOW": SeverityLevel.LOW,
                        "MEDIUM": SeverityLevel.MEDIUM,
                        "HIGH": SeverityLevel.HIGH
                    }
                    
                    issue = SecurityIssue(
                        scan_type=ScanType.STATIC_ANALYSIS,
                        severity=severity_map.get(issue_data.get("issue_severity"), SeverityLevel.MEDIUM),
                        title=issue_data.get("test_name", "Unknown Issue"),
                        description=issue_data.get("issue_text", ""),
                        file_path=issue_data.get("filename"),
                        line_number=issue_data.get("line_number"),
                        rule_id=issue_data.get("test_id"),
                        confidence=issue_data.get("issue_confidence"),
                        recommendation=self._get_bandit_recommendation(issue_data.get("test_id"))
                    )
                    
                    result.issues.append(issue)
            
            result.scan_successful = True
            
        except subprocess.TimeoutExpired:
            result.scan_successful = False
            result.error_message = "Bandit scan timed out"
        except json.JSONDecodeError as e:
            result.scan_successful = False
            result.error_message = f"Failed to parse bandit output: {e}"
        except Exception as e:
            result.scan_successful = False
            result.error_message = f"Bandit scan failed: {e}"
        
        result.duration = time.time() - start_time
        return result
    
    def run_safety_scan(self) -> ScanResult:
        """Run safety dependency vulnerability scan"""
        start_time = time.time()
        
        result = ScanResult(
            scan_type=ScanType.DEPENDENCY_CHECK,
            timestamp=start_time,
            duration=0
        )
        
        if not self.tools_available.get("safety", False):
            result.scan_successful = False
            result.error_message = "Safety not available"
            result.duration = time.time() - start_time
            return result
        
        try:
            # Run safety scan
            cmd = ["safety", "check", "--json"]
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=self.project_root
            )
            
            # Parse safety results
            if process.stdout:
                try:
                    safety_data = json.loads(process.stdout)
                    
                    # Parse vulnerabilities
                    for vuln_data in safety_data:
                        severity = SeverityLevel.HIGH  # Safety reports are typically high severity
                        
                        issue = SecurityIssue(
                            scan_type=ScanType.DEPENDENCY_CHECK,
                            severity=severity,
                            title=f"Vulnerable dependency: {vuln_data.get('package_name')}",
                            description=vuln_data.get('advisory', ''),
                            rule_id=vuln_data.get('id'),
                            recommendation=f"Update {vuln_data.get('package_name')} to version {vuln_data.get('analyzed_version')} or later"
                        )
                        
                        result.issues.append(issue)
                
                except json.JSONDecodeError:
                    # Safety might output non-JSON when no vulnerabilities found
                    if "No known security vulnerabilities found" in process.stdout:
                        pass  # No issues found
                    else:
                        result.error_message = "Failed to parse safety output"
            
            result.scan_successful = True
            
        except subprocess.TimeoutExpired:
            result.scan_successful = False
            result.error_message = "Safety scan timed out"
        except Exception as e:
            result.scan_successful = False
            result.error_message = f"Safety scan failed: {e}"
        
        result.duration = time.time() - start_time
        return result
    
    def run_secrets_detection(self, target_path: str = None) -> ScanResult:
        """Run custom secrets detection scan"""
        start_time = time.time()
        target = Path(target_path) if target_path else self.project_root
        
        result = ScanResult(
            scan_type=ScanType.SECRETS_DETECTION,
            timestamp=start_time,
            duration=0
        )
        
        try:
            # Common secret patterns
            secret_patterns = {
                "api_key": [
                    r"api[_-]?key[s]?\s*[=:]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?",
                    r"apikey[s]?\s*[=:]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?"
                ],
                "password": [
                    r"password[s]?\s*[=:]\s*['\"]?[^\s'\";]{8,}['\"]?",
                    r"passwd[s]?\s*[=:]\s*['\"]?[^\s'\";]{8,}['\"]?"
                ],
                "token": [
                    r"token[s]?\s*[=:]\s*['\"]?[a-zA-Z0-9._-]{20,}['\"]?",
                    r"access[_-]?token[s]?\s*[=:]\s*['\"]?[a-zA-Z0-9._-]{20,}['\"]?"
                ],
                "secret": [
                    r"secret[s]?\s*[=:]\s*['\"]?[a-zA-Z0-9._-]{16,}['\"]?",
                    r"client[_-]?secret[s]?\s*[=:]\s*['\"]?[a-zA-Z0-9._-]{16,}['\"]?"
                ],
                "private_key": [
                    r"-----BEGIN\s+PRIVATE\s+KEY-----",
                    r"-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----"
                ],
                "aws_key": [
                    r"AKIA[0-9A-Z]{16}",
                    r"aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*['\"]?AKIA[0-9A-Z]{16}['\"]?"
                ]
            }
            
            import re
            
            # Scan files
            for py_file in target.rglob("*.py"):
                if self._should_skip_file(py_file):
                    continue
                
                try:
                    with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')
                    
                    for line_num, line in enumerate(lines, 1):
                        for secret_type, patterns in secret_patterns.items():
                            for pattern in patterns:
                                if re.search(pattern, line, re.IGNORECASE):
                                    issue = SecurityIssue(
                                        scan_type=ScanType.SECRETS_DETECTION,
                                        severity=SeverityLevel.HIGH,
                                        title=f"Potential {secret_type} detected",
                                        description=f"Line contains pattern matching {secret_type}",
                                        file_path=str(py_file.relative_to(self.project_root)),
                                        line_number=line_num,
                                        rule_id=f"secrets_{secret_type}",
                                        recommendation="Move sensitive values to environment variables or secrets manager"
                                    )
                                    result.issues.append(issue)
                    
                    result.files_scanned += 1
                
                except Exception as e:
                    logger.warning(f"Failed to scan {py_file}: {e}")
            
            result.scan_successful = True
            
        except Exception as e:
            result.scan_successful = False
            result.error_message = f"Secrets detection failed: {e}"
        
        result.duration = time.time() - start_time
        return result
    
    def run_configuration_audit(self) -> ScanResult:
        """Run configuration security audit"""
        start_time = time.time()
        
        result = ScanResult(
            scan_type=ScanType.CONFIGURATION_AUDIT,
            timestamp=start_time,
            duration=0
        )
        
        try:
            # Check for insecure configurations
            config_issues = []
            
            # Check .env files
            for env_file in self.project_root.glob("*.env*"):
                if env_file.name not in [".env.template", ".env.example"]:
                    issue = SecurityIssue(
                        scan_type=ScanType.CONFIGURATION_AUDIT,
                        severity=SeverityLevel.MEDIUM,
                        title="Environment file in repository",
                        description=f"Environment file {env_file.name} may contain sensitive data",
                        file_path=str(env_file),
                        recommendation="Add to .gitignore and use template files instead"
                    )
                    result.issues.append(issue)
            
            # Check for debug mode in production files
            for py_file in self.project_root.rglob("*.py"):
                if self._should_skip_file(py_file):
                    continue
                
                try:
                    with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')
                    
                    for line_num, line in enumerate(lines, 1):
                        if "debug=True" in line.lower() or "debug = True" in line.lower():
                            issue = SecurityIssue(
                                scan_type=ScanType.CONFIGURATION_AUDIT,
                                severity=SeverityLevel.MEDIUM,
                                title="Debug mode enabled",
                                description="Debug mode should not be enabled in production",
                                file_path=str(py_file.relative_to(self.project_root)),
                                line_number=line_num,
                                recommendation="Use environment variables to control debug mode"
                            )
                            result.issues.append(issue)
                
                except Exception as e:
                    logger.warning(f"Failed to audit {py_file}: {e}")
            
            result.scan_successful = True
            
        except Exception as e:
            result.scan_successful = False
            result.error_message = f"Configuration audit failed: {e}"
        
        result.duration = time.time() - start_time
        return result
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped during scanning"""
        skip_patterns = [
            "*/test_*",
            "*/tests/*",
            "*/venv/*",
            "*/env/*",
            "*/.venv/*",
            "*/__pycache__/*",
            "*/node_modules/*",
            "*/.git/*"
        ]
        
        file_str = str(file_path)
        for pattern in skip_patterns:
            import fnmatch
            if fnmatch.fnmatch(file_str, pattern):
                return True
        
        return False
    
    def _get_bandit_recommendation(self, test_id: str) -> str:
        """Get recommendation for bandit test ID"""
        recommendations = {
            "B101": "Use assert only for testing, not for validation in production code",
            "B102": "Avoid using exec() function as it can execute arbitrary code",
            "B103": "Set appropriate file permissions (avoid 0o777)",
            "B104": "Validate network binding addresses",
            "B105": "Use strong, randomly generated passwords",
            "B106": "Use strong, randomly generated passwords",
            "B107": "Use strong, randomly generated passwords",
            "B108": "Use secure temporary file creation methods",
            "B110": "Avoid using try/except/pass blocks",
            "B112": "Avoid infinite loops without break conditions",
            "B201": "Use proper XML parsing to prevent XXE attacks",
            "B301": "Use safe pickle alternatives like json",
            "B302": "Use safe marshalling methods",
            "B303": "Use cryptographically secure random number generators",
            "B304": "Use secure cipher modes and algorithms",
            "B305": "Use parameterized queries to prevent SQL injection",
            "B306": "Use secure temporary file creation",
            "B307": "Use safe eval alternatives",
            "B308": "Use safe shell command execution",
            "B309": "Use secure HTTP methods",
            "B310": "Validate URLs to prevent SSRF attacks",
            "B311": "Use cryptographically secure random number generators",
            "B312": "Use secure network communication",
            "B313": "Validate XML input to prevent XXE attacks",
            "B314": "Use secure XML processing",
            "B315": "Use secure XML processing",
            "B316": "Use secure XML processing",
            "B317": "Use secure XML processing",
            "B318": "Use secure XML processing",
            "B319": "Use secure XML processing",
            "B320": "Use secure XML processing",
            "B321": "Use secure FTP alternatives",
            "B322": "Use secure network protocols",
            "B323": "Use secure network protocols",
            "B324": "Use secure hash algorithms",
            "B325": "Use secure temporary directories",
            "B501": "Use secure SSL/TLS configurations",
            "B502": "Use secure SSL/TLS configurations",
            "B503": "Use secure SSL/TLS configurations",
            "B504": "Use secure SSL/TLS configurations",
            "B505": "Use secure cryptographic algorithms",
            "B506": "Use secure YAML loading methods",
            "B507": "Validate and sanitize SSH host keys",
            "B601": "Use parameterized shell commands",
            "B602": "Use parameterized shell commands",
            "B603": "Use parameterized shell commands",
            "B604": "Use parameterized shell commands",
            "B605": "Use parameterized shell commands",
            "B606": "Use parameterized shell commands",
            "B607": "Use absolute paths for executables",
            "B608": "Use parameterized SQL queries",
            "B609": "Use secure file permissions",
            "B610": "Use parameterized shell commands",
            "B611": "Use parameterized shell commands",
            "B701": "Use secure Jinja2 templates",
            "B702": "Use secure test configurations",
            "B703": "Use secure Django configurations"
        }
        
        return recommendations.get(test_id, "Review security implications of this code")
    
    def run_comprehensive_scan(self, target_path: str = None) -> Dict[str, ScanResult]:
        """Run all available security scans"""
        logger.info("Starting comprehensive security scan...")
        
        results = {}
        
        # Run bandit scan
        logger.info("Running bandit static analysis...")
        results["bandit"] = self.run_bandit_scan(target_path)
        
        # Run safety scan
        logger.info("Running safety dependency check...")
        results["safety"] = self.run_safety_scan()
        
        # Run secrets detection
        logger.info("Running secrets detection...")
        results["secrets"] = self.run_secrets_detection(target_path)
        
        # Run configuration audit
        logger.info("Running configuration audit...")
        results["config"] = self.run_configuration_audit()
        
        # Save results
        self._save_scan_results(results)
        
        logger.info("Comprehensive security scan completed")
        return results
    
    def _save_scan_results(self, results: Dict[str, ScanResult]):
        """Save scan results to files"""
        timestamp = int(time.time())
        
        # Save individual results
        for scan_name, result in results.items():
            result_file = self.results_dir / f"{scan_name}_scan_{timestamp}.json"
            with open(result_file, 'w') as f:
                json.dump(result.to_dict(), f, indent=2)
        
        # Save combined summary
        summary = self._generate_scan_summary(results)
        summary_file = self.results_dir / f"security_summary_{timestamp}.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"Scan results saved to {self.results_dir}")
    
    def _generate_scan_summary(self, results: Dict[str, ScanResult]) -> Dict[str, Any]:
        """Generate summary of all scan results"""
        total_issues = 0
        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0
        
        scan_summaries = {}
        
        for scan_name, result in results.items():
            if result.scan_successful:
                total_issues += len(result.issues)
                total_critical += result.get_critical_count()
                total_high += result.get_high_count()
                total_medium += len(result.get_issues_by_severity(SeverityLevel.MEDIUM))
                total_low += len(result.get_issues_by_severity(SeverityLevel.LOW))
            
            scan_summaries[scan_name] = {
                "successful": result.scan_successful,
                "issues_found": len(result.issues),
                "duration": result.duration,
                "error": result.error_message
            }
        
        return {
            "timestamp": time.time(),
            "total_issues": total_issues,
            "severity_breakdown": {
                "critical": total_critical,
                "high": total_high,
                "medium": total_medium,
                "low": total_low
            },
            "scan_results": scan_summaries,
            "tools_available": self.tools_available,
            "recommendation": self._get_overall_recommendation(total_critical, total_high)
        }
    
    def _get_overall_recommendation(self, critical_count: int, high_count: int) -> str:
        """Get overall security recommendation"""
        if critical_count > 0:
            return "CRITICAL: Immediate action required. Critical security issues found."
        elif high_count > 5:
            return "HIGH: Multiple high-severity issues found. Address immediately."
        elif high_count > 0:
            return "MEDIUM: High-severity issues found. Address soon."
        else:
            return "LOW: No critical or high-severity issues found."

# Factory function
def create_security_scanner(project_root: str = ".") -> SecurityScanner:
    """Create security scanner instance"""
    return SecurityScanner(project_root)

# CLI interface
def main():
    """Main CLI interface for security scanner"""
    import argparse
    
    parser = argparse.ArgumentParser(description="AuditHound Security Scanner")
    parser.add_argument("--target", "-t", default=".", help="Target directory to scan")
    parser.add_argument("--scan-type", "-s", choices=["all", "bandit", "safety", "secrets", "config"],
                       default="all", help="Type of scan to run")
    parser.add_argument("--output", "-o", help="Output file for results")
    parser.add_argument("--format", "-f", choices=["json", "text"], default="text",
                       help="Output format")
    
    args = parser.parse_args()
    
    scanner = create_security_scanner(args.target)
    
    if args.scan_type == "all":
        results = scanner.run_comprehensive_scan()
    elif args.scan_type == "bandit":
        results = {"bandit": scanner.run_bandit_scan()}
    elif args.scan_type == "safety":
        results = {"safety": scanner.run_safety_scan()}
    elif args.scan_type == "secrets":
        results = {"secrets": scanner.run_secrets_detection()}
    elif args.scan_type == "config":
        results = {"config": scanner.run_configuration_audit()}
    
    # Output results
    if args.format == "json":
        output = {scan_name: result.to_dict() for scan_name, result in results.items()}
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(output, f, indent=2)
        else:
            print(json.dumps(output, indent=2))
    else:
        # Text format
        for scan_name, result in results.items():
            print(f"\n=== {scan_name.upper()} SCAN RESULTS ===")
            print(f"Status: {'✅ SUCCESS' if result.scan_successful else '❌ FAILED'}")
            if not result.scan_successful:
                print(f"Error: {result.error_message}")
                continue
            
            print(f"Duration: {result.duration:.2f}s")
            print(f"Issues found: {len(result.issues)}")
            
            for issue in result.issues:
                severity_icon = {
                    SeverityLevel.CRITICAL: "🔴",
                    SeverityLevel.HIGH: "🟠", 
                    SeverityLevel.MEDIUM: "🟡",
                    SeverityLevel.LOW: "🟢"
                }.get(issue.severity, "⚪")
                
                print(f"\n  {severity_icon} {issue.severity.value.upper()}: {issue.title}")
                if issue.file_path:
                    location = f"{issue.file_path}"
                    if issue.line_number:
                        location += f":{issue.line_number}"
                    print(f"    Location: {location}")
                print(f"    Description: {issue.description}")
                if issue.recommendation:
                    print(f"    Recommendation: {issue.recommendation}")

if __name__ == "__main__":
    main()