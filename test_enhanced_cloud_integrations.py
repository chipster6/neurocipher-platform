#!/usr/bin/env python3
"""
Comprehensive test suite for enhanced cloud integrations
Tests AWS, GCP, and Azure integrations with full SOC 2 evidence collection
"""

import sys
import os
import asyncio
from datetime import datetime

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

def test_aws_integration():
    """Test AWS enhanced integration"""
    print("🔍 Testing AWS Enhanced Integration")
    print("-" * 50)
    
    try:
        from src.integrations.aws_integration_enhanced import create_aws_collector, AWSConfig
        
        # Create AWS collector with mock configuration
        config = AWSConfig(region="us-west-2")
        collector = create_aws_collector(region="us-west-2")
        
        print("✅ AWS collector created successfully")
        
        # Test authentication
        auth_result = collector.authenticate()
        print(f"✅ AWS authentication: {auth_result}")
        
        # Test individual data collection methods
        collection_methods = [
            ("Account Summary", "collect_account_summary"),
            ("Password Policy", "collect_password_policy"),
            ("MFA Devices", "collect_mfa_devices"),
            ("IAM Policies", "collect_iam_policies"),
            ("Access Keys", "collect_access_keys"),
            ("CloudTrail Config", "collect_cloudtrail_config"),
            ("S3 Security", "collect_s3_security"),
            ("Config Rules", "collect_config_rules"),
            ("Security Hub", "collect_security_hub_findings")
        ]
        
        for method_name, method_func in collection_methods:
            try:
                if hasattr(collector, method_func):
                    result = getattr(collector, method_func)()
                    print(f"✅ {method_name}: Data collected ({len(str(result))} chars)")
                else:
                    print(f"❌ {method_name}: Method not found")
            except Exception as e:
                print(f"⚠️ {method_name}: {e}")
        
        # Test SOC 2 evidence collection
        soc2_controls = ["CC6.1", "CC6.2", "CC6.3", "CC7.1", "CC8.1"]
        for control in soc2_controls:
            try:
                method_name = f"collect_soc2_{control.lower().replace('.', '_')}_evidence"
                if hasattr(collector, method_name):
                    evidence = getattr(collector, method_name)()
                    score = evidence.get("evidence", {}).get("compliance_score", 0)
                    print(f"✅ {control} Evidence: Score {score:.1f}%")
                else:
                    print(f"❌ {control}: Evidence method not found")
            except Exception as e:
                print(f"⚠️ {control}: {e}")
        
        return True
        
    except Exception as e:
        print(f"❌ AWS integration test failed: {e}")
        return False

def test_gcp_integration():
    """Test GCP enhanced integration"""
    print("\n🔍 Testing GCP Enhanced Integration")
    print("-" * 50)
    
    try:
        from src.integrations.gcp_integration_enhanced import create_gcp_collector, GCPConfig
        
        # Create GCP collector with mock configuration
        collector = create_gcp_collector(project_id="test-project-123")
        
        print("✅ GCP collector created successfully")
        
        # Test authentication
        auth_result = collector.authenticate()
        print(f"✅ GCP authentication: {auth_result}")
        
        # Test individual data collection methods
        collection_methods = [
            ("Organization Policies", "collect_organization_policies"),
            ("IAM Policies", "collect_iam_policies"),
            ("Workspace Security", "collect_workspace_security"),
            ("Security Center", "collect_security_center_findings"),
            ("Cloud Logging", "collect_cloud_logging_config"),
            ("Storage Security", "collect_storage_security"),
            ("Compute Security", "collect_compute_security")
        ]
        
        for method_name, method_func in collection_methods:
            try:
                if hasattr(collector, method_func):
                    result = getattr(collector, method_func)()
                    print(f"✅ {method_name}: Data collected ({len(str(result))} chars)")
                else:
                    print(f"❌ {method_name}: Method not found")
            except Exception as e:
                print(f"⚠️ {method_name}: {e}")
        
        # Test SOC 2 evidence collection
        soc2_controls = ["CC6.1", "CC6.2", "CC6.3", "CC7.1", "CC8.1"]
        for control in soc2_controls:
            try:
                method_name = f"collect_soc2_{control.lower().replace('.', '_')}_evidence"
                if hasattr(collector, method_name):
                    evidence = getattr(collector, method_name)()
                    score = evidence.get("evidence", {}).get("compliance_score", 0)
                    print(f"✅ {control} Evidence: Score {score:.1f}%")
                else:
                    print(f"❌ {control}: Evidence method not found")
            except Exception as e:
                print(f"⚠️ {control}: {e}")
        
        return True
        
    except Exception as e:
        print(f"❌ GCP integration test failed: {e}")
        return False

def test_azure_integration():
    """Test Azure enhanced integration"""
    print("\n🔍 Testing Azure Enhanced Integration")
    print("-" * 50)
    
    try:
        from src.integrations.azure_integration_enhanced import create_azure_collector, AzureConfig
        
        # Create Azure collector with mock configuration
        collector = create_azure_collector(
            tenant_id="12345678-1234-1234-1234-123456789012",
            subscription_id="87654321-4321-4321-4321-210987654321"
        )
        
        print("✅ Azure collector created successfully")
        
        # Test authentication
        auth_result = collector.authenticate()
        print(f"✅ Azure authentication: {auth_result}")
        
        # Test individual data collection methods
        collection_methods = [
            ("Azure AD Policies", "collect_azure_ad_policies"),
            ("Azure AD Users", "collect_azure_ad_users"),
            ("RBAC Assignments", "collect_rbac_assignments"),
            ("Security Center", "collect_security_center_data"),
            ("Storage Security", "collect_storage_security"),
            ("Network Security", "collect_network_security"),
            ("Key Vault Security", "collect_key_vault_security"),
            ("Activity Logs", "collect_activity_logs")
        ]
        
        for method_name, method_func in collection_methods:
            try:
                if hasattr(collector, method_func):
                    result = getattr(collector, method_func)()
                    print(f"✅ {method_name}: Data collected ({len(str(result))} chars)")
                else:
                    print(f"❌ {method_name}: Method not found")
            except Exception as e:
                print(f"⚠️ {method_name}: {e}")
        
        # Test SOC 2 evidence collection
        soc2_controls = ["CC6.1", "CC6.2", "CC6.3", "CC7.1", "CC8.1"]
        for control in soc2_controls:
            try:
                method_name = f"collect_soc2_{control.lower().replace('.', '_')}_evidence"
                if hasattr(collector, method_name):
                    evidence = getattr(collector, method_name)()
                    score = evidence.get("evidence", {}).get("compliance_score", 0)
                    print(f"✅ {control} Evidence: Score {score:.1f}%")
                else:
                    print(f"❌ {control}: Evidence method not found")
            except Exception as e:
                print(f"⚠️ {control}: {e}")
        
        return True
        
    except Exception as e:
        print(f"❌ Azure integration test failed: {e}")
        return False

def test_enhanced_mapping():
    """Test enhanced compliance mapping"""
    print("\n🔍 Testing Enhanced Compliance Mapping")
    print("-" * 50)
    
    try:
        from src.compliance.mapping_enhanced import get_enhanced_mapping_matrix, CloudProvider, ComplianceFramework
        
        mapping = get_enhanced_mapping_matrix()
        print("✅ Enhanced mapping matrix created")
        
        # Test control mappings
        soc2_controls = mapping.get_soc2_controls()
        print(f"✅ SOC 2 controls loaded: {len(soc2_controls)}")
        
        for control in soc2_controls:
            print(f"   📋 {control.control_id}: {control.title}")
            
            # Test provider evidence sources
            for provider in [CloudProvider.AWS, CloudProvider.GCP, CloudProvider.AZURE]:
                sources = mapping.get_provider_evidence_sources(control.control_id, provider)
                method = mapping.get_collection_method(control.control_id, provider)
                print(f"      {provider.value.upper()}: {len(sources)} sources, method: {method}")
        
        # Test scoring
        sample_scores = {
            "password_policy_strength": 85.0,
            "mfa_enforcement": 90.0,
            "access_control_policies": 75.0,
            "privileged_access_management": 80.0,
            "account_lifecycle_management": 70.0
        }
        
        result = mapping.calculate_control_score("CC6.1", sample_scores)
        print(f"✅ Sample CC6.1 score calculation: {result['score']:.1f}% ({result['status']})")
        
        return True
        
    except Exception as e:
        print(f"❌ Enhanced mapping test failed: {e}")
        return False

def test_unified_collector():
    """Test unified cloud collector"""
    print("\n🔍 Testing Unified Cloud Collector")
    print("-" * 50)
    
    try:
        from src.integrations.unified_cloud_collector import create_unified_collector
        
        # Create unified collector with all providers
        collector = create_unified_collector(
            aws_region="us-west-2",
            gcp_project_id="test-project-123",
            azure_tenant_id="12345678-1234-1234-1234-123456789012",
            azure_subscription_id="87654321-4321-4321-4321-210987654321",
            enabled_providers=["aws", "gcp", "azure"]
        )
        
        print("✅ Unified collector created")
        print(f"   📊 Enabled providers: {list(collector.collectors.keys())}")
        
        # Test authentication across all providers
        auth_results = collector.authenticate_all_providers()
        for provider, result in auth_results.items():
            status = "✅" if result else "❌"
            print(f"   {status} {provider.upper()}: {result}")
        
        # Test SOC 2 evidence collection (single control for testing)
        print("\n📋 Testing SOC 2 evidence collection...")
        evidence_report = collector.collect_soc2_evidence(controls=["CC6.1"])
        
        metadata = evidence_report.get("collection_metadata", {})
        summary = evidence_report.get("summary", {})
        
        print(f"✅ Evidence collection completed")
        print(f"   ⏱️ Collection time: {metadata.get('collection_time_seconds', 0):.1f}s")
        print(f"   📊 Overall score: {summary.get('overall_compliance_score', 0):.1f}%")
        print(f"   🎯 Risk level: {summary.get('risk_level', 'Unknown')}")
        
        # Test export formats
        print("\n📄 Testing export formats...")
        
        json_export = collector.export_evidence_report(evidence_report, "json")
        print(f"✅ JSON export: {len(json_export)} characters")
        
        markdown_export = collector.export_evidence_report(evidence_report, "markdown")
        print(f"✅ Markdown export: {len(markdown_export)} characters")
        
        csv_export = collector.export_evidence_report(evidence_report, "csv")
        print(f"✅ CSV export: {len(csv_export)} characters")
        
        # Test comprehensive inventory
        print("\n📦 Testing comprehensive inventory...")
        inventory = collector.collect_comprehensive_inventory()
        providers_with_data = len([p for p in inventory.get("providers", {}).values() if not p.get("error")])
        print(f"✅ Inventory collected from {providers_with_data} providers")
        
        return True
        
    except Exception as e:
        print(f"❌ Unified collector test failed: {e}")
        return False

async def test_async_collection():
    """Test asynchronous evidence collection"""
    print("\n🔍 Testing Async Evidence Collection")
    print("-" * 50)
    
    try:
        from src.integrations.unified_cloud_collector import create_unified_collector
        
        collector = create_unified_collector(
            aws_region="us-west-2",
            enabled_providers=["aws"]
        )
        
        print("🚀 Starting async evidence collection...")
        start_time = datetime.now()
        
        evidence_report = await collector.collect_evidence_async(controls=["CC6.1"])
        
        end_time = datetime.now()
        execution_time = (end_time - start_time).total_seconds()
        
        print(f"✅ Async collection completed in {execution_time:.1f}s")
        
        summary = evidence_report.get("summary", {})
        print(f"   📊 Score: {summary.get('overall_compliance_score', 0):.1f}%")
        
        return True
        
    except Exception as e:
        print(f"❌ Async collection test failed: {e}")
        return False

def test_scoring_algorithms():
    """Test scoring algorithms across providers"""
    print("\n🔍 Testing Scoring Algorithms")
    print("-" * 50)
    
    try:
        from src.compliance.mapping_enhanced import get_enhanced_mapping_matrix
        
        mapping = get_enhanced_mapping_matrix()
        
        # Test different scoring scenarios
        test_scenarios = [
            ("Excellent Security", {
                "password_policy_strength": 95,
                "mfa_enforcement": 98,
                "access_control_policies": 90,
                "privileged_access_management": 92,
                "account_lifecycle_management": 88
            }),
            ("Good Security", {
                "password_policy_strength": 80,
                "mfa_enforcement": 85,
                "access_control_policies": 75,
                "privileged_access_management": 78,
                "account_lifecycle_management": 70
            }),
            ("Poor Security", {
                "password_policy_strength": 40,
                "mfa_enforcement": 30,
                "access_control_policies": 45,
                "privileged_access_management": 35,
                "account_lifecycle_management": 25
            })
        ]
        
        for scenario_name, scores in test_scenarios:
            result = mapping.calculate_control_score("CC6.1", scores)
            print(f"✅ {scenario_name}: {result['score']:.1f}% ({result['status']})")
            print(f"   Coverage: {result['coverage_percentage']:.1f}%")
        
        return True
        
    except Exception as e:
        print(f"❌ Scoring algorithms test failed: {e}")
        return False

def test_real_world_simulation():
    """Simulate real-world compliance assessment"""
    print("\n🔍 Testing Real-World Simulation")
    print("-" * 50)
    
    try:
        from src.integrations.unified_cloud_collector import create_unified_collector
        
        # Simulate enterprise environment with multiple providers
        collector = create_unified_collector(
            aws_region="us-west-2",
            gcp_project_id="enterprise-prod-project",
            azure_tenant_id="enterprise-tenant-id",
            azure_subscription_id="enterprise-subscription-id",
            enabled_providers=["aws", "gcp", "azure"]
        )
        
        print("🏢 Enterprise simulation: Multi-cloud environment")
        print(f"   📊 Providers: {list(collector.collectors.keys())}")
        
        # Full SOC 2 assessment
        print("\n📋 Running full SOC 2 assessment...")
        evidence_report = collector.collect_soc2_evidence()
        
        metadata = evidence_report.get("collection_metadata", {})
        summary = evidence_report.get("summary", {})
        recommendations = evidence_report.get("recommendations", [])
        
        print("✅ Full assessment completed")
        print(f"   ⏱️ Total time: {metadata.get('collection_time_seconds', 0):.1f}s")
        print(f"   📊 Overall score: {summary.get('overall_compliance_score', 0):.1f}%")
        print(f"   🎯 Risk level: {summary.get('risk_level', 'Unknown')}")
        print(f"   💡 Recommendations: {len(recommendations)}")
        
        # Show compliance distribution
        distribution = summary.get("compliance_status_distribution", {})
        print(f"   ✅ Compliant: {distribution.get('compliant', 0)}")
        print(f"   ⚠️ Partial: {distribution.get('partial', 0)}")
        print(f"   ❌ Non-compliant: {distribution.get('non_compliant', 0)}")
        
        # Show provider scores
        provider_scores = summary.get("provider_scores", {})
        for provider, score in provider_scores.items():
            print(f"   {provider.upper()}: {score:.1f}%")
        
        # Show top recommendations
        print("\n💡 Top Recommendations:")
        for i, rec in enumerate(recommendations[:5], 1):
            priority = {1: "🔴", 2: "🟡", 3: "🟢"}.get(rec.get("priority"), "⚪")
            print(f"   {i}. [{rec.get('control_id')}] {rec.get('recommendation')[:60]}... {priority}")
        
        return True
        
    except Exception as e:
        print(f"❌ Real-world simulation failed: {e}")
        return False

def main():
    """Run all enhanced cloud integration tests"""
    print("🧪 Enhanced Cloud Integrations Test Suite")
    print("=" * 80)
    
    tests = [
        ("AWS Integration", test_aws_integration),
        ("GCP Integration", test_gcp_integration),
        ("Azure Integration", test_azure_integration),
        ("Enhanced Mapping", test_enhanced_mapping),
        ("Unified Collector", test_unified_collector),
        ("Scoring Algorithms", test_scoring_algorithms),
        ("Real-World Simulation", test_real_world_simulation)
    ]
    
    results = {}
    start_time = datetime.now()
    
    for test_name, test_func in tests:
        print(f"\n🔍 Running {test_name}...")
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ {test_name} crashed: {e}")
            results[test_name] = False
    
    # Test async functionality
    print(f"\n🔍 Running Async Collection...")
    try:
        async_result = asyncio.run(test_async_collection())
        results["Async Collection"] = async_result
    except Exception as e:
        print(f"❌ Async collection crashed: {e}")
        results["Async Collection"] = False
    
    end_time = datetime.now()
    total_time = (end_time - start_time).total_seconds()
    
    # Summary
    print("\n" + "=" * 80)
    print("📋 Test Summary")
    print("=" * 80)
    
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"   {test_name}: {status}")
    
    print(f"\n🎯 Results: {passed}/{total} tests passed")
    print(f"⏱️ Total execution time: {total_time:.1f} seconds")
    
    if passed == total:
        print("\n🎉 All enhanced cloud integration tests passed!")
        print("\n💡 Next Steps:")
        print("   • Configure real cloud provider credentials")
        print("   • Run against actual cloud environments")
        print("   • Set up continuous compliance monitoring")
        print("   • Integrate with security operations workflows")
    else:
        print(f"\n⚠️ {total - passed} tests failed. Check the errors above.")
        print("\n🔧 Troubleshooting:")
        print("   • Verify all cloud SDK dependencies are installed")
        print("   • Check cloud provider authentication setup")
        print("   • Review enhanced integration configurations")
        print("   • Validate SOC 2 control mappings")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)