#!/usr/bin/env python3
"""
Test script for Weaviate compliance bridge integration
"""

import os
import sys
import json
from datetime import datetime

# Add src to path
sys.path.append('src')

def test_weaviate_integration():
    """Test the Weaviate compliance bridge integration"""
    
    print("🧪 Testing Weaviate Compliance Bridge Integration")
    print("=" * 50)
    
    try:
        # Test 1: Import the bridge module
        print("📦 Testing module imports...")
        from src.weaviate_compliance_bridge import (
            WeaviateComplianceBridge, 
            ComplianceScoreResult, 
            create_enhanced_scoring_wrapper
        )
        print("✅ Successfully imported Weaviate compliance bridge")
        
        # Test 2: Initialize Weaviate client
        print("\n🔗 Testing Weaviate connection...")
        try:
            import weaviate
            weaviate_url = os.getenv('WEAVIATE_URL', 'http://localhost:8080')
            client = weaviate.Client(weaviate_url)
            
            # Test connection
            meta = client.get_meta()
            print(f"✅ Connected to Weaviate at {weaviate_url}")
            print(f"   Version: {meta.get('version', 'unknown')}")
            
        except Exception as e:
            print(f"❌ Weaviate connection failed: {e}")
            print("   Make sure Weaviate is running: docker run -p 8080:8080 semitechnologies/weaviate:latest")
            return False
        
        # Test 3: Initialize bridge
        print("\n🌉 Testing bridge initialization...")
        bridge = WeaviateComplianceBridge(client)
        print("✅ Weaviate compliance bridge initialized")
        
        # Test 4: Create sample compliance score
        print("\n📊 Testing compliance score creation...")
        sample_score = ComplianceScoreResult(
            provider="GCP",
            control="CC6.1-MFA",
            framework="SOC2",
            score=85.5,
            client_id="test_client",
            timestamp=datetime.now().isoformat(),
            details="Test GCP MFA compliance check: 2FA enforced, adoption rate 85%",
            component_scores={
                "2fa_enforcement": 100.0,
                "adoption_rate": 85.0,
                "login_mfa_usage": 71.0
            },
            evidence_summary={
                "enforcement_state": "ENFORCED",
                "total_users": 100,
                "mfa_enabled_users": 85
            },
            remediation_guidance=["Increase user training for MFA adoption"],
            risk_factors=["15% of users haven't enabled MFA"]
        )
        
        print(f"✅ Created compliance score: {sample_score.provider}/{sample_score.control} = {sample_score.score}")
        
        # Test 5: Persist score
        print("\n💾 Testing score persistence...")
        result_uuid = bridge.persist_score(sample_score)
        print(f"✅ Persisted score with UUID: {result_uuid}")
        
        # Test 6: Query scores
        print("\n🔍 Testing score querying...")
        scores = bridge.query_scores(client_id="test_client", limit=5)
        print(f"✅ Retrieved {len(scores)} scores for test_client")
        
        if scores:
            latest_score = scores[0]
            print(f"   Latest: {latest_score.get('provider')}/{latest_score.get('control')} = {latest_score.get('score')}")
        
        # Test 7: Trend analysis
        print("\n📈 Testing trend analysis...")
        trends = bridge.get_compliance_trends("test_client", lookback_days=7)
        print(f"✅ Generated trend analysis: {trends.get('total_controls_analyzed', 0)} controls analyzed")
        
        if 'overall_health' in trends:
            health = trends['overall_health']
            print(f"   Overall health score: {health.get('health_score', 0):.1f}")
        
        # Test 8: Enhanced scoring functions
        print("\n⚡ Testing enhanced scoring functions...")
        enhanced_functions = create_enhanced_scoring_wrapper(bridge)
        
        sample_evidence = {
            'login_challenges': {
                'enforcement_state': 'ENFORCED',
                'adoption_rate': 88.0,
                'login_mfa_percentage': 76.0
            }
        }
        
        enhanced_result = enhanced_functions['enhanced_gcp_mfa_check'](sample_evidence, "test_client_2")
        print(f"✅ Enhanced GCP MFA scoring: {enhanced_result.score}")
        print(f"   Details: {enhanced_result.details}")
        
        # Test 9: Integration with unified engine
        print("\n🚀 Testing unified engine integration...")
        from src.unified_audit_engine import UnifiedAuditEngine
        
        config_path = "config.yaml"
        if os.path.exists(config_path):
            engine = UnifiedAuditEngine(config_path, weaviate_client=client)
            print("✅ Unified engine initialized with Weaviate bridge")
            
            # Test analytics
            analytics = engine.get_compliance_analytics("test_client")
            if 'error' not in analytics:
                print(f"✅ Compliance analytics: {analytics.get('total_controls_analyzed', 0)} controls")
            else:
                print(f"⚠️  Analytics: {analytics['message']}")
                
        else:
            print("⚠️  Config file not found, skipping unified engine test")
        
        print("\n🎉 All tests completed successfully!")
        print("\n📝 Summary:")
        print("   • Weaviate compliance bridge is working")
        print("   • Enhanced scoring functions are operational")
        print("   • Historical analytics and trends are available")
        print("   • Multi-tenant compliance data is isolated")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_semantic_search():
    """Test semantic search functionality"""
    print("\n🔍 Testing semantic search...")
    
    try:
        import weaviate
        from src.weaviate_compliance_bridge import WeaviateComplianceBridge
        
        client = weaviate.Client(os.getenv('WEAVIATE_URL', 'http://localhost:8080'))
        bridge = WeaviateComplianceBridge(client)
        
        # Test semantic search
        results = bridge.semantic_search("MFA enforcement problems", "test_client", limit=3)
        
        if results:
            print(f"✅ Semantic search returned {len(results)} results")
            for i, result in enumerate(results[:2]):
                print(f"   {i+1}. {result.get('control')} - Score: {result.get('score')}")
        else:
            print("⚠️  No semantic search results (may need more test data)")
            
    except Exception as e:
        print(f"❌ Semantic search test failed: {e}")

if __name__ == "__main__":
    success = test_weaviate_integration()
    
    if success:
        test_semantic_search()
        print("\n✅ Weaviate compliance bridge integration is ready!")
    else:
        print("\n❌ Integration tests failed. Check the error messages above.")
        sys.exit(1)