"""Flask web dashboard for AuditHound compliance reporting"""
from flask import Flask, render_template, jsonify, request
from datetime import datetime
import sys
import os

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from integrations.gcp_integration import GCPSecurityCollector
from integrations.azure_integration import AzureSecurityCollector
from integrations.aws_integration import AWSSecurityCollector
from compliance.mapping import ComplianceMappingMatrix

app = Flask(__name__)

# Initialize compliance mapping
compliance_mapper = ComplianceMappingMatrix()

@app.route('/')
def dashboard():
    """Main dashboard view"""
    return render_template('dashboard.html')

@app.route('/api/compliance-summary')
def compliance_summary():
    """API endpoint for compliance summary data"""
    # Mock data for demonstration
    summary = {
        "total_controls": 5,
        "compliant": 2,
        "partial": 2,
        "non_compliant": 1,
        "overall_score": 78.5,
        "last_updated": datetime.now().isoformat()
    }
    return jsonify(summary)

@app.route('/api/compliance-details')
def compliance_details():
    """API endpoint for detailed compliance status"""
    cloud_provider = request.args.get('provider', 'all')
    
    # Sample compliance data
    details = []
    
    if cloud_provider in ['all', 'gcp']:
        gcp_collector = GCPSecurityCollector("sample-project")
        gcp_evidence = gcp_collector.collect_soc2_cc6_1_evidence()
        gcp_score = compliance_mapper.normalize_compliance_score("CC6.1", "gcp", gcp_evidence)
        details.append(gcp_score)
    
    if cloud_provider in ['all', 'azure']:
        azure_collector = AzureSecurityCollector("sample-tenant", "sample-subscription")
        azure_evidence = azure_collector.collect_soc2_cc6_1_evidence()
        azure_score = compliance_mapper.normalize_compliance_score("CC6.1", "azure", azure_evidence)
        details.append(azure_score)
    
    if cloud_provider in ['all', 'aws']:
        aws_collector = AWSSecurityCollector("us-west-2")
        aws_evidence = aws_collector.collect_soc2_cc6_1_evidence()
        aws_score = compliance_mapper.normalize_compliance_score("CC6.1", "aws", aws_evidence)
        details.append(aws_score)
    
    # Add other controls
    for control_id in ["CC6.2", "CC6.3", "CC7.1", "CC8.1"]:
        mock_evidence = {"timestamp": datetime.now().isoformat()}
        for provider in ["gcp", "azure", "aws"]:
            if cloud_provider in ['all', provider]:
                score = compliance_mapper.normalize_compliance_score(control_id, provider, mock_evidence)
                details.append(score)
    
    return jsonify(details)

@app.route('/api/cloud-providers')
def cloud_providers():
    """API endpoint for available cloud providers"""
    providers = [
        {"id": "gcp", "name": "Google Cloud Platform", "status": "connected"},
        {"id": "azure", "name": "Microsoft Azure", "status": "connected"},
        {"id": "aws", "name": "Amazon Web Services", "status": "connected"}
    ]
    return jsonify(providers)

@app.route('/api/frameworks')
def frameworks():
    """API endpoint for available compliance frameworks"""
    frameworks = [
        {"id": "soc2", "name": "SOC 2", "controls_count": 5, "status": "active"},
        {"id": "iso27001", "name": "ISO 27001", "controls_count": 0, "status": "planned"},
        {"id": "cis", "name": "CIS Benchmarks", "controls_count": 0, "status": "planned"}
    ]
    return jsonify(frameworks)

@app.route('/api/generate-report')
def generate_report():
    """API endpoint to generate compliance report"""
    provider = request.args.get('provider', 'all')
    framework = request.args.get('framework', 'soc2')
    
    # Mock report generation
    report = {
        "report_id": f"RPT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "provider": provider,
        "framework": framework,
        "generated_at": datetime.now().isoformat(),
        "status": "generated",
        "download_url": f"/reports/compliance-report-{provider}-{framework}.pdf"
    }
    
    return jsonify(report)

@app.route('/api/scan', methods=['POST'])
def start_compliance_scan():
    """API endpoint to start a comprehensive compliance scan"""
    try:
        request_data = request.get_json()
        
        # Parse scan parameters
        providers = request_data.get('providers', ['all'])
        frameworks = request_data.get('frameworks', ['soc2'])
        controls = request_data.get('controls', [])  # Specific controls or empty for all
        
        # Generate scan ID
        scan_id = f"SCAN-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Initialize results structure
        scan_results = {
            "scan_id": scan_id,
            "started_at": datetime.now().isoformat(),
            "status": "in_progress",
            "parameters": {
                "providers": providers,
                "frameworks": frameworks,
                "controls": controls
            },
            "results": [],
            "summary": {
                "total_controls": 0,
                "compliant": 0,
                "partial": 0,
                "non_compliant": 0,
                "overall_score": 0.0
            }
        }
        
        # Determine which providers to scan
        providers_to_scan = []
        if 'all' in providers:
            providers_to_scan = ['aws', 'gcp', 'azure']
        else:
            providers_to_scan = providers
        
        # Determine which controls to evaluate
        controls_to_evaluate = controls if controls else ["CC6.1", "CC6.2", "CC6.3", "CC7.1", "CC8.1"]
        
        # Perform scan across providers and controls
        all_scores = []
        
        for provider in providers_to_scan:
            for framework in frameworks:
                for control_id in controls_to_evaluate:
                    try:
                        # Collect evidence based on provider
                        if provider == 'aws':
                            collector = AWSSecurityCollector("us-west-2")
                            if control_id == "CC6.1":
                                evidence = collector.collect_soc2_cc6_1_evidence()
                            else:
                                evidence = {"timestamp": datetime.now().isoformat()}
                        elif provider == 'gcp':
                            collector = GCPSecurityCollector("sample-project")
                            if control_id == "CC6.1":
                                evidence = collector.collect_soc2_cc6_1_evidence()
                            else:
                                evidence = {"timestamp": datetime.now().isoformat()}
                        elif provider == 'azure':
                            collector = AzureSecurityCollector("sample-tenant", "sample-subscription")
                            if control_id == "CC6.1":
                                evidence = collector.collect_soc2_cc6_1_evidence()
                            else:
                                evidence = {"timestamp": datetime.now().isoformat()}
                        
                        # Normalize scoring
                        score_result = compliance_mapper.normalize_compliance_score(control_id, provider, evidence)
                        score_result["scan_id"] = scan_id
                        all_scores.append(score_result)
                        
                    except Exception as e:
                        # Handle individual control failures gracefully
                        error_result = {
                            "scan_id": scan_id,
                            "control_id": control_id,
                            "cloud_provider": provider,
                            "framework": framework,
                            "overall_score": 0.0,
                            "compliance_status": "error",
                            "error": str(e),
                            "timestamp": datetime.now().isoformat()
                        }
                        all_scores.append(error_result)
        
        # Update scan results
        scan_results["results"] = all_scores
        scan_results["status"] = "completed"
        scan_results["completed_at"] = datetime.now().isoformat()
        
        # Calculate summary statistics
        valid_scores = [s for s in all_scores if s.get("overall_score", 0) > 0 and s.get("compliance_status") != "error"]
        
        if valid_scores:
            scan_results["summary"]["total_controls"] = len(valid_scores)
            scan_results["summary"]["compliant"] = len([s for s in valid_scores if s.get("compliance_status") == "compliant"])
            scan_results["summary"]["partial"] = len([s for s in valid_scores if s.get("compliance_status") == "partial"])
            scan_results["summary"]["non_compliant"] = len([s for s in valid_scores if s.get("compliance_status") == "non_compliant"])
            
            total_score = sum(s.get("overall_score", 0) for s in valid_scores)
            scan_results["summary"]["overall_score"] = total_score / len(valid_scores)
        
        return jsonify(scan_results), 200
        
    except Exception as e:
        return jsonify({
            "error": "Scan failed",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

@app.route('/api/score', methods=['GET'])
def get_compliance_scores():
    """API endpoint to retrieve compliance scores with advanced filtering"""
    try:
        # Parse query parameters
        provider = request.args.get('provider', 'all')
        framework = request.args.get('framework', 'soc2')
        control_id = request.args.get('control')
        min_score = float(request.args.get('min_score', 0))
        max_score = float(request.args.get('max_score', 100))
        status_filter = request.args.get('status')  # compliant, partial, non_compliant
        
        # Get detailed compliance data (reuse existing logic)
        providers_to_query = []
        if provider == 'all':
            providers_to_query = ['aws', 'gcp', 'azure']
        else:
            providers_to_query = [provider]
        
        controls_to_query = []
        if control_id:
            controls_to_query = [control_id]
        else:
            controls_to_query = ["CC6.1", "CC6.2", "CC6.3", "CC7.1", "CC8.1"]
        
        # Collect scores
        all_scores = []
        
        for prov in providers_to_query:
            for ctrl in controls_to_query:
                try:
                    # Collect evidence
                    if prov == 'aws':
                        collector = AWSSecurityCollector("us-west-2")
                        if ctrl == "CC6.1":
                            evidence = collector.collect_soc2_cc6_1_evidence()
                        else:
                            evidence = {"timestamp": datetime.now().isoformat()}
                    elif prov == 'gcp':
                        collector = GCPSecurityCollector("sample-project")
                        if ctrl == "CC6.1":
                            evidence = collector.collect_soc2_cc6_1_evidence()
                        else:
                            evidence = {"timestamp": datetime.now().isoformat()}
                    elif prov == 'azure':
                        collector = AzureSecurityCollector("sample-tenant", "sample-subscription")
                        if ctrl == "CC6.1":
                            evidence = collector.collect_soc2_cc6_1_evidence()
                        else:
                            evidence = {"timestamp": datetime.now().isoformat()}
                    
                    # Normalize scoring
                    score_result = compliance_mapper.normalize_compliance_score(ctrl, prov, evidence)
                    all_scores.append(score_result)
                    
                except Exception as e:
                    # Continue on errors for individual controls
                    continue
        
        # Apply filters
        filtered_scores = []
        for score in all_scores:
            # Score range filter
            if score.get("overall_score", 0) < min_score or score.get("overall_score", 0) > max_score:
                continue
            
            # Status filter
            if status_filter and score.get("compliance_status") != status_filter:
                continue
            
            filtered_scores.append(score)
        
        # Calculate response statistics
        response = {
            "total_results": len(filtered_scores),
            "filters_applied": {
                "provider": provider,
                "framework": framework,
                "control_id": control_id,
                "min_score": min_score,
                "max_score": max_score,
                "status": status_filter
            },
            "summary": {
                "compliant": len([s for s in filtered_scores if s.get("compliance_status") == "compliant"]),
                "partial": len([s for s in filtered_scores if s.get("compliance_status") == "partial"]),
                "non_compliant": len([s for s in filtered_scores if s.get("compliance_status") == "non_compliant"]),
                "average_score": sum(s.get("overall_score", 0) for s in filtered_scores) / len(filtered_scores) if filtered_scores else 0
            },
            "scores": filtered_scores,
            "generated_at": datetime.now().isoformat()
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        return jsonify({
            "error": "Failed to retrieve scores",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    """API endpoint to retrieve results from a specific scan"""
    # In a real implementation, this would query a database
    # For now, return a mock response
    return jsonify({
        "scan_id": scan_id,
        "status": "completed",
        "message": "Scan results would be retrieved from database",
        "note": "This endpoint requires database persistence to be fully functional"
    }), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)