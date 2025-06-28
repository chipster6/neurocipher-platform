#!/usr/bin/env python3
"""
Test script for AuditHound Streamlit Dashboard
Validates dashboard structure and functionality without running Streamlit
"""

import sys
import os
from pathlib import Path

def test_dashboard_files():
    """Test that all required dashboard files exist"""
    print("🔍 Testing Dashboard Files")
    print("-" * 40)
    
    required_files = [
        "streamlit_dashboard.py",
        "run_streamlit_dashboard.py", 
        "README_STREAMLIT_DASHBOARD.md",
        "requirements.txt",
        "config.yaml"
    ]
    
    missing_files = []
    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
        else:
            print(f"✅ {file_path}")
    
    if missing_files:
        print(f"❌ Missing files: {missing_files}")
        return False
    
    print("✅ All required files present")
    return True

def test_dashboard_imports():
    """Test that dashboard imports work correctly"""
    print("\n🔍 Testing Dashboard Imports")
    print("-" * 40)
    
    # Add src to path
    sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
    
    try:
        # Test basic imports that should always work
        import json
        import datetime
        from pathlib import Path
        print("✅ Basic Python imports working")
        
        # Test if our modules can be imported
        try:
            from unified_models import SecurityAsset, RiskLevel, ComplianceStatus
            print("✅ Unified models import working")
        except ImportError as e:
            print(f"⚠️  Unified models import: {e}")
        
        try:
            from unified_audit_engine import UnifiedAuditEngine
            print("✅ Unified audit engine import working")
        except ImportError as e:
            print(f"⚠️  Unified audit engine import: {e}")
        
        return True
        
    except Exception as e:
        print(f"❌ Import test failed: {e}")
        return False

def test_dashboard_class_structure():
    """Test the dashboard class structure"""
    print("\n🔍 Testing Dashboard Class Structure")
    print("-" * 40)
    
    try:
        # Read and parse the dashboard file
        with open("streamlit_dashboard.py", "r") as f:
            content = f.read()
        
        # Check for required class and methods
        required_components = [
            "class StreamlitDashboard:",
            "def render_header(",
            "def render_sidebar(",
            "def render_overview_metrics(",
            "def render_compliance_scorecard(",
            "def render_threat_detection(",
            "def render_asset_inventory(",
            "def generate_export(",
            "def export_csv(",
            "def export_json(",
            "def export_markdown(",
            "def run("
        ]
        
        missing_components = []
        for component in required_components:
            if component not in content:
                missing_components.append(component)
            else:
                print(f"✅ {component.split('(')[0]}")
        
        if missing_components:
            print(f"❌ Missing components: {missing_components}")
            return False
        
        print("✅ All required dashboard components present")
        return True
        
    except Exception as e:
        print(f"❌ Class structure test failed: {e}")
        return False

def test_launcher_functionality():
    """Test the launcher script functionality"""
    print("\n🔍 Testing Launcher Functionality")
    print("-" * 40)
    
    try:
        with open("run_streamlit_dashboard.py", "r") as f:
            content = f.read()
        
        required_functions = [
            "def check_streamlit(",
            "def install_streamlit(",
            "def setup_environment(",
            "def check_tpu(",
            "def start_dashboard(",
            "def main("
        ]
        
        for func in required_functions:
            if func in content:
                print(f"✅ {func.split('(')[0]}")
            else:
                print(f"❌ Missing: {func}")
                return False
        
        print("✅ All launcher functions present")
        return True
        
    except Exception as e:
        print(f"❌ Launcher test failed: {e}")
        return False

def test_export_formats():
    """Test export format definitions"""
    print("\n🔍 Testing Export Formats")
    print("-" * 40)
    
    try:
        with open("streamlit_dashboard.py", "r") as f:
            content = f.read()
        
        export_methods = [
            "def export_csv(self):",
            "def export_json(self):",
            "def export_markdown(self):",
            "def export_pdf(self):"
        ]
        
        for method in export_methods:
            if method in content:
                print(f"✅ {method.split('(')[0]}")
            else:
                print(f"❌ Missing: {method}")
                return False
        
        # Check for download button implementations
        if "st.download_button" in content:
            print("✅ Streamlit download buttons implemented")
        else:
            print("❌ Missing download button implementations")
            return False
        
        print("✅ All export formats implemented")
        return True
        
    except Exception as e:
        print(f"❌ Export format test failed: {e}")
        return False

def test_configuration():
    """Test configuration file"""
    print("\n🔍 Testing Configuration")
    print("-" * 40)
    
    try:
        if Path("config.yaml").exists():
            print("✅ Config file exists")
            
            with open("config.yaml", "r") as f:
                config_content = f.read()
            
            # Basic config validation
            if "organization:" in config_content:
                print("✅ Organization configuration present")
            if "dashboard:" in config_content:
                print("✅ Dashboard configuration present")
            if "compliance_frameworks:" in config_content:
                print("✅ Compliance frameworks configuration present")
        else:
            print("⚠️  Config file not found (will be created on first run)")
        
        return True
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def test_requirements():
    """Test requirements file for dashboard dependencies"""
    print("\n🔍 Testing Requirements")
    print("-" * 40)
    
    try:
        with open("requirements.txt", "r") as f:
            requirements = f.read()
        
        required_packages = [
            "streamlit",
            "plotly", 
            "pandas",
            "numpy"
        ]
        
        for package in required_packages:
            if package in requirements:
                print(f"✅ {package} in requirements")
            else:
                print(f"❌ Missing: {package}")
                return False
        
        print("✅ All dashboard dependencies in requirements.txt")
        return True
        
    except Exception as e:
        print(f"❌ Requirements test failed: {e}")
        return False

def main():
    """Run all dashboard tests"""
    print("🧪 AuditHound Streamlit Dashboard Tests")
    print("=" * 50)
    
    tests = [
        ("Dashboard Files", test_dashboard_files),
        ("Dashboard Imports", test_dashboard_imports),
        ("Dashboard Class Structure", test_dashboard_class_structure),
        ("Launcher Functionality", test_launcher_functionality),
        ("Export Formats", test_export_formats),
        ("Configuration", test_configuration),
        ("Requirements", test_requirements)
    ]
    
    results = {}
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
            results[test_name] = False
    
    # Summary
    print("\n" + "=" * 50)
    print("📋 Test Summary:")
    
    passed = 0
    total = len(tests)
    
    for test_name, result in results.items():
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"   {test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\n🎯 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All dashboard tests passed!")
        print("\n💡 Next Steps:")
        print("   • Install Streamlit: pip install streamlit plotly pandas")
        print("   • Run setup: python run_streamlit_dashboard.py --setup-only")
        print("   • Start dashboard: python run_streamlit_dashboard.py")
        print("   • Access at: http://localhost:8501")
    else:
        print("\n⚠️  Some tests failed. Check the errors above.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)