"""Tests for AuditHound"""
import pytest
from src.audit import AuditFinding, AuditManager

def test_audit_finding_creation():
    """Test creating an audit finding"""
    finding = AuditFinding("Test Finding", "Test description", "high", "security")
    assert finding.title == "Test Finding"
    assert finding.severity == "high"
    assert finding.status == "open"

def test_audit_manager():
    """Test audit manager functionality"""
    manager = AuditManager()
    finding = manager.create_finding("Test", "Description", "medium", "compliance")
    
    assert finding.id == 1
    assert len(manager.findings) == 1
    
    summary = manager.get_summary()
    assert summary["open"] == 1

def test_finding_status_update():
    """Test updating finding status"""
    finding = AuditFinding("Test", "Desc", "low", "operational")
    finding.update_status("in_progress")
    assert finding.status == "in_progress"
    
    with pytest.raises(ValueError):
        finding.update_status("invalid_status")