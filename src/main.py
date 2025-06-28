#!/usr/bin/env python3
"""
AuditHound - Main application entry point
"""
from typing import Dict, Any
from .audit import AuditManager
from .cli import cli

def main() -> None:
    """Main application entry point"""
    print("Welcome to AuditHound!")
    print("Audit and compliance tracking tool")
    print("\nUse 'python -m src.cli --help' for command line interface")
    
    # Example usage
    manager: AuditManager = AuditManager()
    
    # Create sample findings
    finding1 = manager.create_finding(
        "Weak password policy", 
        "Password policy allows weak passwords", 
        "high", 
        "security"
    )
    
    finding2 = manager.create_finding(
        "Missing SSL certificate", 
        "Web application lacks SSL encryption", 
        "critical", 
        "security"
    )
    
    print(f"\nCreated {len(manager.findings)} sample findings:")
    for finding in manager.findings:
        print(f"  #{finding.id}: {finding.title} [{finding.severity}]")
    
    summary: Dict[str, Any] = manager.get_summary()
    print(f"\nStatus summary: {summary}")

if __name__ == "__main__":
    main()