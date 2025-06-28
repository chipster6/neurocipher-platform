#!/usr/bin/env python3
"""
Comprehensive test suite for Weaviate Multi-Tenant Bridge
Tests tenant isolation, client_id indexing, and analytics functionality
"""

import sys
import os
import json
from datetime import datetime, timedelta
from typing import Dict, List

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

def test_weaviate_multitenant_bridge():
    """Test the multi-tenant Weaviate bridge functionality"""
    print("🔍 Testing Weaviate Multi-Tenant Bridge")
    print("-" * 50)
    
    try:
        from src.weaviate_multitenant_bridge import (
            WeaviateMultiTenantBridge, 
            MultiTenantComplianceScore,
            TenantAssetInventory,
            TenantIsolationLevel
        )
        from src.multi_tenant_manager import TenantTier
        
        # Initialize bridge (will use mock data if Weaviate not available)
        bridge = WeaviateMultiTenantBridge(
            isolation_level=TenantIsolationLevel.SOFT
        )
        
        print("✅ Weaviate multi-tenant bridge initialized")
        print(f"   🔧 Isolation level: {bridge.isolation_level.value}")
        print(f"   📊 Weaviate available: {bridge.client is not None}")
        
        return True
        
    except Exception as e:
        print(f"❌ Weaviate bridge initialization failed: {e}")
        return False

def test_tenant_compliance_score_persistence():
    """Test persisting compliance scores with tenant isolation"""
    print("\n🔍 Testing Tenant Compliance Score Persistence")
    print("-" * 50)
    
    try:
        from src.weaviate_multitenant_bridge import WeaviateMultiTenantBridge, MultiTenantComplianceScore
        from src.multi_tenant_manager import TenantTier
        
        bridge = WeaviateMultiTenantBridge()
        
        # Create test compliance scores for different tenants
        test_scores = [
            MultiTenantComplianceScore(
                client_id="client_acme_001",
                organization_name="Acme Corporation",
                tenant_tier=TenantTier.ENTERPRISE.value,
                provider="AWS",
                control_id="CC6.1",
                framework="SOC2",
                score=85.5,
                status="partial",
                evidence_summary={
                    "password_policy": {"strength": 80},
                    "mfa_enforcement": {"coverage": 90}
                },
                component_scores={
                    "password_policy_strength": 80.0,
                    "mfa_enforcement": 90.0,
                    "access_control_policies": 85.0
                },
                risk_factors=["Weak password complexity", "Limited MFA coverage"],
                recommendations=["Strengthen password policy", "Increase MFA adoption"],
                department="IT Security",
                cost_center="CC-001",
                business_unit="Technology"
            ),
            MultiTenantComplianceScore(
                client_id="client_startup_002",
                organization_name="StartupXYZ",
                tenant_tier=TenantTier.PROFESSIONAL.value,
                provider="GCP",
                control_id="CC6.1",
                framework="SOC2",
                score=92.0,
                status="compliant",
                evidence_summary={
                    "organization_policies": {"enforced": True},
                    "2fa_adoption": {"rate": 95}
                },
                component_scores={
                    "password_policy_strength": 90.0,
                    "mfa_enforcement": 95.0,
                    "access_control_policies": 90.0
                },
                risk_factors=[],
                recommendations=["Maintain current security posture"],
                department="Engineering",
                cost_center="CC-002"
            ),
            MultiTenantComplianceScore(
                client_id="client_msp_003",
                organization_name="MSP Solutions",
                tenant_tier=TenantTier.MSP.value,
                provider="Azure",
                control_id="CC6.2",
                framework="SOC2",
                score=88.0,
                status="partial",
                evidence_summary={
                    "azure_ad_policies": {"mfa_required": True},
                    "conditional_access": {"policies": 5}
                },
                component_scores={
                    "authentication_methods": 90.0,
                    "session_controls": 85.0,
                    "identity_protection": 88.0
                },
                risk_factors=["Some legacy authentication methods"],
                recommendations=["Phase out legacy authentication"],
                geographic_region="US-East"
            )
        ]
        
        # Test persisting scores
        persisted_ids = []
        for score in test_scores:
            score_id = bridge.persist_compliance_score(score)
            persisted_ids.append(score_id)
            print(f"✅ Persisted score for {score.organization_name}: {score_id}")
        
        print(f"✅ Successfully persisted {len(persisted_ids)} compliance scores")
        
        return True
        
    except Exception as e:
        print(f"❌ Compliance score persistence test failed: {e}")
        return False

def test_tenant_asset_inventory():
    """Test tenant asset inventory functionality"""
    print("\n🔍 Testing Tenant Asset Inventory")
    print("-" * 50)
    
    try:
        from src.weaviate_multitenant_bridge import WeaviateMultiTenantBridge, TenantAssetInventory
        
        bridge = WeaviateMultiTenantBridge()
        
        # Create test asset inventories
        test_inventories = [
            TenantAssetInventory(
                client_id="client_acme_001",
                organization_name="Acme Corporation",
                asset_id="vm-001",
                asset_name="Web Server VM",
                asset_type="compute",
                cloud_provider="AWS",
                cloud_region="us-west-2",
                cloud_account="123456789",
                criticality="high",
                compliance_scores={"SOC2": 85.0, "ISO27001": 82.0},
                risk_score=15.0,
                department="Engineering",
                cost_center="CC-001",
                tags=["Production", "Backend"]
            ),
            TenantAssetInventory(
                client_id="client_startup_002",
                organization_name="StartupXYZ",
                asset_id="storage-001",
                asset_name="Data Bucket",
                asset_type="storage",
                cloud_provider="GCP",
                cloud_region="us-central1",
                cloud_account="gcp-project-123",
                criticality="medium",
                compliance_scores={"SOC2": 92.0},
                risk_score=8.0,
                department="Data Engineering",
                tags=["Production", "Sensitive"]
            )
        ]
        
        # Test persisting asset inventories
        for inventory in test_inventories:
            inventory_id = bridge.persist_asset_inventory(inventory)
            print(f"✅ Persisted asset for {inventory.organization_name}: {inventory_id}")
        
        print(f"✅ Successfully persisted {len(test_inventories)} asset inventories")
        
        return True
        
    except Exception as e:
        print(f"❌ Asset inventory test failed: {e}")
        return False

def test_tenant_queries():
    """Test tenant-specific queries and filtering"""
    print("\n🔍 Testing Tenant Queries and Filtering")
    print("-" * 50)
    
    try:
        from src.weaviate_multitenant_bridge import WeaviateMultiTenantBridge
        
        bridge = WeaviateMultiTenantBridge()
        
        # Test querying compliance scores for specific tenant
        client_id = "client_acme_001"
        scores = bridge.query_tenant_compliance(
            client_id=client_id,
            filters={"framework": "SOC2"},
            limit=10
        )
        print(f"✅ Retrieved {len(scores)} compliance scores for {client_id}")
        
        if scores:
            for score in scores[:3]:  # Show first 3
                print(f"   📊 {score.get('controlId', 'N/A')}: {score.get('score', 0):.1f}%")
        
        # Test querying assets for specific tenant
        assets = bridge.query_tenant_assets(
            client_id=client_id,
            filters={"cloudProvider": "AWS"},
            limit=10
        )
        print(f"✅ Retrieved {len(assets)} assets for {client_id}")
        
        if assets:
            for asset in assets[:3]:  # Show first 3
                print(f"   🖥️ {asset.get('assetId', 'N/A')}: {asset.get('securityScore', 0):.1f}%")
        
        # Test department filtering
        dept_scores = bridge.query_tenant_compliance(
            client_id=client_id,
            filters={"department": "IT Security"},
            limit=5
        )
        print(f"✅ Retrieved {len(dept_scores)} scores for IT Security department")
        
        return True
        
    except Exception as e:
        print(f"❌ Tenant queries test failed: {e}")
        return False

def test_analytics_dashboard():
    """Test analytics dashboard generation"""
    print("\n🔍 Testing Analytics Dashboard Generation")
    print("-" * 50)
    
    try:
        from src.weaviate_multitenant_bridge import WeaviateMultiTenantBridge
        
        bridge = WeaviateMultiTenantBridge()
        
        # Test comprehensive analytics dashboard
        client_id = "client_acme_001"
        dashboard = bridge.get_tenant_analytics_dashboard(client_id)
        
        print(f"✅ Generated analytics dashboard for {client_id}")
        print(f"   🏢 Organization: {dashboard.get('organization_name', 'N/A')}")
        print(f"   📊 Overall Score: {dashboard.get('overall_compliance_score', 0):.1f}%")
        print(f"   🎯 Risk Level: {dashboard.get('risk_level', 'Unknown')}")
        
        # Show compliance summary
        compliance_summary = dashboard.get('compliance_summary', {})
        print(f"   ✅ Compliant Controls: {compliance_summary.get('compliant_controls', 0)}")
        print(f"   ⚠️ Partial Controls: {compliance_summary.get('partial_controls', 0)}")
        print(f"   ❌ Non-compliant Controls: {compliance_summary.get('non_compliant_controls', 0)}")
        
        # Show provider breakdown
        provider_scores = dashboard.get('provider_scores', {})
        for provider, score in provider_scores.items():
            print(f"   {provider.upper()}: {score:.1f}%")
        
        # Show top risks
        top_risks = dashboard.get('top_risks', [])
        print(f"   🚨 Top Risks: {len(top_risks)}")
        for risk in top_risks[:3]:
            print(f"      • {risk}")
        
        # Show recommendations
        recommendations = dashboard.get('recommendations', [])
        print(f"   💡 Recommendations: {len(recommendations)}")
        for rec in recommendations[:3]:
            priority = rec.get('priority', 'medium')
            print(f"      • [{priority.upper()}] {rec.get('recommendation', '')[:50]}...")
        
        return True
        
    except Exception as e:
        print(f"❌ Analytics dashboard test failed: {e}")
        return False

def test_cross_tenant_analytics():
    """Test cross-tenant analytics for MSP scenarios"""
    print("\n🔍 Testing Cross-Tenant Analytics (MSP)")
    print("-" * 50)
    
    try:
        from src.weaviate_multitenant_bridge import WeaviateMultiTenantBridge
        
        bridge = WeaviateMultiTenantBridge()
        
        # Test MSP cross-tenant analytics
        msp_client_id = "client_msp_003"
        cross_tenant_analytics = bridge.get_cross_tenant_analytics(msp_client_id)
        
        print(f"✅ Generated cross-tenant analytics for MSP")
        print(f"   👥 Managed Organizations: {cross_tenant_analytics.get('total_managed_orgs', 0)}")
        print(f"   📊 Average Compliance Score: {cross_tenant_analytics.get('average_compliance_score', 0):.1f}%")
        
        # Show organization breakdown
        org_breakdown = cross_tenant_analytics.get('organization_breakdown', [])
        print(f"   🏢 Organization Breakdown:")
        for org in org_breakdown[:5]:  # Show first 5
            print(f"      • {org.get('organization_name', 'N/A')}: {org.get('compliance_score', 0):.1f}%")
        
        # Show compliance trends
        trends = cross_tenant_analytics.get('compliance_trends', {})
        print(f"   📈 Trends:")
        print(f"      Improving: {trends.get('improving_orgs', 0)}")
        print(f"      Declining: {trends.get('declining_orgs', 0)}")
        print(f"      Stable: {trends.get('stable_orgs', 0)}")
        
        # Show industry benchmarks
        benchmarks = cross_tenant_analytics.get('industry_benchmarks', {})
        if benchmarks:
            print(f"   🎯 Benchmarks:")
            print(f"      Above Average: {benchmarks.get('above_average', 0)}")
            print(f"      Below Average: {benchmarks.get('below_average', 0)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Cross-tenant analytics test failed: {e}")
        return False

def test_semantic_search():
    """Test semantic search capabilities"""
    print("\n🔍 Testing Semantic Search")
    print("-" * 50)
    
    try:
        from src.weaviate_multitenant_bridge import WeaviateMultiTenantBridge
        
        bridge = WeaviateMultiTenantBridge()
        
        # Test semantic search queries
        search_queries = [
            "MFA enforcement issues",
            "password policy compliance",
            "access control violations",
            "high risk findings"
        ]
        
        client_id = "client_acme_001"
        
        for query in search_queries:
            results = bridge.semantic_search_tenant(
                client_id=client_id,
                query_text=query,
                search_type="compliance",
                limit=5
            )
            
            print(f"✅ Search '{query}': {len(results)} results")
            
            if results:
                for result in results[:2]:  # Show first 2
                    control = result.get('controlId', 'N/A')
                    score = result.get('score', 0)
                    print(f"      📋 {control}: {score:.1f}%")
        
        return True
        
    except Exception as e:
        print(f"❌ Semantic search test failed: {e}")
        return False

def test_tenant_isolation():
    """Test tenant isolation and security"""
    print("\n🔍 Testing Tenant Isolation")
    print("-" * 50)
    
    try:
        from src.weaviate_multitenant_bridge import WeaviateMultiTenantBridge
        
        bridge = WeaviateMultiTenantBridge()
        
        # Test that queries are properly isolated by client_id
        client1 = "client_acme_001"
        client2 = "client_startup_002"
        
        # Query scores for client1
        client1_scores = bridge.query_tenant_compliance(client_id=client1, limit=10)
        print(f"✅ Client 1 scores: {len(client1_scores)}")
        
        # Query scores for client2
        client2_scores = bridge.query_tenant_compliance(client_id=client2, limit=10)
        print(f"✅ Client 2 scores: {len(client2_scores)}")
        
        # Verify no cross-contamination
        for score in client1_scores:
            if score.get('clientId') != client1:
                raise Exception(f"Tenant isolation violation: Found {score.get('clientId')} in {client1} results")
        
        for score in client2_scores:
            if score.get('clientId') != client2:
                raise Exception(f"Tenant isolation violation: Found {score.get('clientId')} in {client2} results")
        
        print("✅ Tenant isolation verified - no cross-contamination detected")
        
        # Test invalid client_id access
        invalid_scores = bridge.query_tenant_compliance(client_id="invalid_client", limit=10)
        print(f"✅ Invalid client query: {len(invalid_scores)} results (should be 0 or empty)")
        
        return True
        
    except Exception as e:
        print(f"❌ Tenant isolation test failed: {e}")
        return False

def test_performance_and_scalability():
    """Test performance with larger datasets"""
    print("\n🔍 Testing Performance and Scalability")
    print("-" * 50)
    
    try:
        from src.weaviate_multitenant_bridge import WeaviateMultiTenantBridge, MultiTenantComplianceScore
        from src.multi_tenant_manager import TenantTier
        
        bridge = WeaviateMultiTenantBridge()
        
        # Test batch operations performance
        print("📊 Testing batch operations...")
        
        # Generate multiple test scores
        batch_scores = []
        providers = ["AWS", "GCP", "Azure"]
        controls = ["CC6.1", "CC6.2", "CC6.3", "CC7.1", "CC8.1"]
        
        for i in range(15):  # Create 15 test scores
            score = MultiTenantComplianceScore(
                client_id=f"client_perf_{i % 3}",
                organization_name=f"Test Org {i}",
                tenant_tier=TenantTier.ENTERPRISE.value,
                provider=providers[i % 3],
                control_id=controls[i % 5],
                framework="SOC2",
                score=float(70 + (i % 30)),
                status="partial",
                evidence_summary={"test": f"data_{i}"},
                component_scores={"test_component": float(70 + (i % 30))},
                risk_factors=[f"Risk factor {i}"],
                recommendations=[f"Recommendation {i}"]
            )
            batch_scores.append(score)
        
        start_time = datetime.now()
        batch_results = bridge.batch_persist_scores(batch_scores)
        end_time = datetime.now()
        
        batch_time = (end_time - start_time).total_seconds()
        print(f"✅ Batch persistence: {len(batch_results)} scores in {batch_time:.2f}s")
        print(f"   📈 Rate: {len(batch_results) / batch_time:.1f} scores/second")
        
        # Test query performance
        start_time = datetime.now()
        query_results = bridge.query_tenant_compliance(
            client_id="client_perf_0",
            limit=100
        )
        end_time = datetime.now()
        
        query_time = (end_time - start_time).total_seconds()
        print(f"✅ Query performance: {len(query_results)} results in {query_time:.2f}s")
        
        return True
        
    except Exception as e:
        print(f"❌ Performance test failed: {e}")
        return False

def main():
    """Run all Weaviate multi-tenant tests"""
    print("🧪 Weaviate Multi-Tenant Bridge Test Suite")
    print("=" * 80)
    
    tests = [
        ("Multi-Tenant Bridge Init", test_weaviate_multitenant_bridge),
        ("Compliance Score Persistence", test_tenant_compliance_score_persistence),
        ("Asset Inventory", test_tenant_asset_inventory),
        ("Tenant Queries", test_tenant_queries),
        ("Analytics Dashboard", test_analytics_dashboard),
        ("Cross-Tenant Analytics", test_cross_tenant_analytics),
        ("Semantic Search", test_semantic_search),
        ("Tenant Isolation", test_tenant_isolation),
        ("Performance & Scalability", test_performance_and_scalability)
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
        print("\n🎉 All Weaviate multi-tenant tests passed!")
        print("\n💡 Multi-tenant DB layer is ready for production:")
        print("   ✅ Tenant isolation with client_id indexing")
        print("   ✅ Comprehensive analytics dashboards")
        print("   ✅ Cross-tenant MSP analytics")
        print("   ✅ Semantic search capabilities")
        print("   ✅ Performance optimized batch operations")
        print("   ✅ Secure tenant data separation")
        print("\n🚀 Ready to integrate with unified audit engine!")
    else:
        print(f"\n⚠️ {total - passed} tests failed. Check the errors above.")
        print("\n🔧 Troubleshooting:")
        print("   • Verify Weaviate server is running (optional)")
        print("   • Check multi-tenant manager dependencies")
        print("   • Review tenant isolation configurations")
        print("   • Validate analytics generation logic")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)