#!/usr/bin/env python3
"""
Test runner script for AuditHound
Provides convenient way to run different test suites
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path
from typing import List, Dict, Any

def run_command(cmd: List[str], description: str) -> bool:
    """Run a command and return success status"""
    print(f"\n🔍 {description}")
    print(f"Command: {' '.join(cmd)}")
    print("-" * 50)
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=False)
        print(f"✅ {description} - PASSED")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} - FAILED (exit code: {e.returncode})")
        return False
    except FileNotFoundError:
        print(f"❌ {description} - FAILED (command not found)")
        return False

def run_unit_tests() -> bool:
    """Run unit tests"""
    cmd = [
        "python3", "-m", "pytest", 
        "tests/", 
        "-v", 
        "-m", "not slow and not integration and not e2e",
        "--tb=short"
    ]
    return run_command(cmd, "Unit Tests")

def run_integration_tests() -> bool:
    """Run integration tests"""
    cmd = [
        "python3", "-m", "pytest", 
        "tests/", 
        "-v", 
        "-m", "integration",
        "--tb=short"
    ]
    return run_command(cmd, "Integration Tests")

def run_weaviate_tests() -> bool:
    """Run Weaviate-specific tests"""
    cmd = [
        "python3", "-m", "pytest", 
        "tests/test_weaviate_comprehensive.py", 
        "-v",
        "--tb=short"
    ]
    return run_command(cmd, "Weaviate Integration Tests")

def run_soc_tests() -> bool:
    """Run SOC connector tests"""
    cmd = [
        "python3", "-m", "pytest", 
        "tests/test_soc_connectors.py", 
        "-v",
        "--tb=short"
    ]
    return run_command(cmd, "SOC Connector Tests")

def run_e2e_tests() -> bool:
    """Run end-to-end tests"""
    cmd = [
        "python3", "-m", "pytest", 
        "tests/test_e2e_smoke.py", 
        "-v",
        "-m", "not slow",
        "--tb=short"
    ]
    return run_command(cmd, "End-to-End Tests")

def run_slow_tests() -> bool:
    """Run slow/performance tests"""
    cmd = [
        "python3", "-m", "pytest", 
        "tests/", 
        "-v", 
        "-m", "slow",
        "--tb=short",
        "--timeout=600"
    ]
    return run_command(cmd, "Slow/Performance Tests")

def run_type_checking() -> bool:
    """Run mypy type checking"""
    cmd = ["python3", "-m", "mypy", "src/", "--config-file", "mypy.ini"]
    return run_command(cmd, "Type Checking (mypy)")

def run_style_checking() -> bool:
    """Run flake8 style checking"""
    cmd = ["python3", "-m", "flake8", "src/", "tests/", "--config=.flake8"]
    return run_command(cmd, "Style Checking (flake8)")

def run_security_scan() -> bool:
    """Run security scanning"""
    cmd = ["python3", "-m", "bandit", "-r", "src/", "-f", "txt"]
    return run_command(cmd, "Security Scan (bandit)")

def run_all_tests() -> bool:
    """Run all test suites"""
    results = []
    
    # Type and style checking first
    results.append(run_type_checking())
    results.append(run_style_checking())
    
    # Core functionality tests
    results.append(run_unit_tests())
    results.append(run_weaviate_tests())
    results.append(run_soc_tests())
    results.append(run_e2e_tests())
    
    # Security scan
    results.append(run_security_scan())
    
    return all(results)

def run_quick_tests() -> bool:
    """Run quick test suite (unit + basic integration)"""
    results = []
    
    results.append(run_type_checking())
    results.append(run_style_checking())
    results.append(run_unit_tests())
    
    return all(results)

def run_ci_tests() -> bool:
    """Run CI-appropriate test suite"""
    results = []
    
    # Quality checks
    results.append(run_type_checking())
    results.append(run_style_checking())
    results.append(run_security_scan())
    
    # Core tests (excluding slow ones)
    results.append(run_unit_tests())
    results.append(run_weaviate_tests())
    results.append(run_soc_tests())
    results.append(run_e2e_tests())
    
    return all(results)

def generate_test_report() -> None:
    """Generate comprehensive test report"""
    print("\n📊 Generating Test Report")
    print("=" * 60)
    
    # Run tests with coverage
    coverage_cmd = [
        "python3", "-m", "pytest", 
        "tests/", 
        "--cov=src", 
        "--cov-report=term-missing",
        "--cov-report=html:htmlcov",
        "--cov-report=xml:coverage.xml",
        "-v"
    ]
    
    try:
        subprocess.run(coverage_cmd, check=True)
        print("✅ Test report generated successfully")
        print("📄 HTML report: htmlcov/index.html")
        print("📄 XML report: coverage.xml")
    except subprocess.CalledProcessError:
        print("❌ Failed to generate test report")
    except FileNotFoundError:
        print("⚠️ pytest-cov not installed, skipping coverage report")

def main():
    """Main test runner"""
    parser = argparse.ArgumentParser(description="AuditHound Test Runner")
    parser.add_argument(
        "suite", 
        choices=[
            "unit", "integration", "weaviate", "soc", "e2e", "slow",
            "type", "style", "security", 
            "all", "quick", "ci", "report"
        ],
        help="Test suite to run"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Change to project root directory
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)
    
    print("🚀 AuditHound Test Runner")
    print(f"📁 Working directory: {os.getcwd()}")
    print(f"🎯 Test suite: {args.suite}")
    print("=" * 60)
    
    # Map suite names to functions
    suite_functions = {
        "unit": run_unit_tests,
        "integration": run_integration_tests,
        "weaviate": run_weaviate_tests,
        "soc": run_soc_tests,
        "e2e": run_e2e_tests,
        "slow": run_slow_tests,
        "type": run_type_checking,
        "style": run_style_checking,
        "security": run_security_scan,
        "all": run_all_tests,
        "quick": run_quick_tests,
        "ci": run_ci_tests,
        "report": generate_test_report
    }
    
    if args.suite == "report":
        generate_test_report()
        return
    
    # Run the selected test suite
    success = suite_functions[args.suite]()
    
    print("\n" + "=" * 60)
    if success:
        print("✅ All tests PASSED")
        sys.exit(0)
    else:
        print("❌ Some tests FAILED")
        sys.exit(1)

if __name__ == "__main__":
    main()