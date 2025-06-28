#!/usr/bin/env python3
"""
AuditHound API Usage Examples
Demonstrates how to use the compliance scanning and scoring APIs
"""
import requests
import json
import time
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:5000"
HEADERS = {"Content-Type": "application/json"}

def run_comprehensive_scan():
    """Example: Run a comprehensive compliance scan across all providers"""
    print("=== Running Comprehensive Compliance Scan ===")
    
    scan_request = {
        "providers": ["all"],  # Scan AWS, GCP, and Azure
        "frameworks": ["soc2"],
        "controls": []  # Empty = all controls
    }
    
    print(f"Sending scan request: {json.dumps(scan_request, indent=2)}")
    
    response = requests.post(f"{BASE_URL}/api/scan", 
                           headers=HEADERS,
                           data=json.dumps(scan_request))
    
    if response.status_code == 200:
        result = response.json()
        print(f"✅ Scan completed successfully!")
        print(f"📊 Scan ID: {result['scan_id']}")
        print(f"📈 Overall Score: {result['summary']['overall_score']:.1f}%")
        print(f"✅ Compliant: {result['summary']['compliant']}")
        print(f"⚠️  Partial: {result['summary']['partial']}")
        print(f"❌ Non-compliant: {result['summary']['non_compliant']}")
        
        return result
    else:
        print(f"❌ Scan failed: {response.text}")
        return None

def run_targeted_aws_scan():
    """Example: Run a targeted scan for AWS CC6.1 control only"""
    print("\n=== Running Targeted AWS CC6.1 Scan ===")
    
    scan_request = {
        "providers": ["aws"],
        "frameworks": ["soc2"],
        "controls": ["CC6.1"]  # Only logical access controls
    }
    
    print(f"Sending targeted scan request: {json.dumps(scan_request, indent=2)}")
    
    response = requests.post(f"{BASE_URL}/api/scan",
                           headers=HEADERS,
                           data=json.dumps(scan_request))
    
    if response.status_code == 200:
        result = response.json()
        print(f"✅ Targeted scan completed!")
        print(f"📊 Scan ID: {result['scan_id']}")
        
        # Show detailed results for each control
        for control_result in result['results']:
            print(f"\n🔍 Control: {control_result['control_id']}")
            print(f"☁️  Provider: {control_result['cloud_provider'].upper()}")
            print(f"📈 Score: {control_result['overall_score']:.1f}%")
            print(f"🚦 Status: {control_result['compliance_status']}")
            
            if 'component_scores' in control_result:
                print("📋 Component Breakdown:")
                for component, score in control_result['component_scores'].items():
                    print(f"   • {component.replace('_', ' ').title()}: {score:.1f}%")
        
        return result
    else:
        print(f"❌ Targeted scan failed: {response.text}")
        return None

def query_compliance_scores():
    """Example: Query compliance scores with various filters"""
    print("\n=== Querying Compliance Scores ===")
    
    # Get all scores
    print("📊 Fetching all compliance scores...")
    response = requests.get(f"{BASE_URL}/api/score")
    
    if response.status_code == 200:
        all_scores = response.json()
        print(f"✅ Retrieved {all_scores['total_results']} total scores")
        print(f"📈 Average Score: {all_scores['summary']['average_score']:.1f}%")
    
    # Filter for high-performing controls only
    print("\n🎯 Filtering for high-performing controls (score >= 90)...")
    response = requests.get(f"{BASE_URL}/api/score?min_score=90")
    
    if response.status_code == 200:
        high_scores = response.json()
        print(f"✅ Found {high_scores['total_results']} high-performing controls")
        
        for score in high_scores['scores'][:3]:  # Show first 3
            print(f"   • {score['control_id']} ({score['cloud_provider'].upper()}): {score['overall_score']:.1f}%")
    
    # Filter for problematic controls
    print("\n⚠️  Filtering for problematic controls (score < 70)...")
    response = requests.get(f"{BASE_URL}/api/score?max_score=70&status=non_compliant")
    
    if response.status_code == 200:
        problem_scores = response.json()
        print(f"❌ Found {problem_scores['total_results']} problematic controls")
        
        for score in problem_scores['scores'][:3]:  # Show first 3
            print(f"   • {score['control_id']} ({score['cloud_provider'].upper()}): {score['overall_score']:.1f}%")

def query_provider_specific_scores():
    """Example: Get scores for specific cloud providers"""
    print("\n=== Provider-Specific Score Analysis ===")
    
    providers = ['aws', 'gcp', 'azure']
    
    for provider in providers:
        print(f"\n☁️  Analyzing {provider.upper()} compliance...")
        response = requests.get(f"{BASE_URL}/api/score?provider={provider}")
        
        if response.status_code == 200:
            provider_scores = response.json()
            summary = provider_scores['summary']
            
            print(f"📊 {provider.upper()} Summary:")
            print(f"   • Total Controls: {provider_scores['total_results']}")
            print(f"   • Average Score: {summary['average_score']:.1f}%")
            print(f"   • ✅ Compliant: {summary['compliant']}")
            print(f"   • ⚠️  Partial: {summary['partial']}")
            print(f"   • ❌ Non-compliant: {summary['non_compliant']}")

def generate_compliance_report():
    """Example: Generate a compliance report"""
    print("\n=== Generating Compliance Report ===")
    
    response = requests.get(f"{BASE_URL}/api/generate-report?provider=all&framework=soc2")
    
    if response.status_code == 200:
        report = response.json()
        print(f"📄 Report generated successfully!")
        print(f"🆔 Report ID: {report['report_id']}")
        print(f"📅 Generated: {report['generated_at']}")
        print(f"🔗 Download URL: {report['download_url']}")
    else:
        print(f"❌ Report generation failed: {response.text}")

def main():
    """Run all API usage examples"""
    print("🔍 AuditHound API Usage Examples")
    print("=" * 50)
    
    try:
        # Test if the API is running
        response = requests.get(f"{BASE_URL}/api/compliance-summary")
        if response.status_code != 200:
            print("❌ API server is not running. Please start with:")
            print("   python run_dashboard.py")
            return
        
        print("✅ API server is running!\n")
        
        # Run examples
        run_comprehensive_scan()
        run_targeted_aws_scan()
        query_compliance_scores()
        query_provider_specific_scores()
        generate_compliance_report()
        
        print("\n" + "=" * 50)
        print("🎉 All API examples completed successfully!")
        print("\n💡 Next steps:")
        print("   • Visit http://localhost:5000 for the dashboard")
        print("   • Run unit tests: pytest tests/")
        print("   • Integrate with your CI/CD pipeline")
        
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to API server.")
        print("Please ensure the dashboard is running:")
        print("   python run_dashboard.py")
    except Exception as e:
        print(f"❌ Error running examples: {e}")

if __name__ == "__main__":
    main()