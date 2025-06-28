"""Integration tests for AuditHound API endpoints"""
import pytest
import json
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from dashboard.app import app

class TestAPIEndpoints:
    """Test the Flask API endpoints"""
    
    def setup_method(self):
        """Setup test fixtures"""
        app.config['TESTING'] = True
        self.client = app.test_client()
    
    def test_dashboard_route(self):
        """Test the main dashboard route"""
        response = self.client.get('/')
        assert response.status_code == 200
        assert b'AuditHound' in response.data
    
    def test_compliance_summary_api(self):
        """Test the compliance summary API endpoint"""
        response = self.client.get('/api/compliance-summary')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'total_controls' in data
        assert 'compliant' in data
        assert 'partial' in data
        assert 'non_compliant' in data
        assert 'overall_score' in data
        assert 'last_updated' in data
    
    def test_compliance_details_api_all_providers(self):
        """Test compliance details API with all providers"""
        response = self.client.get('/api/compliance-details?provider=all')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert isinstance(data, list)
        
        if len(data) > 0:
            # Check structure of first result
            first_result = data[0]
            assert 'control_id' in first_result
            assert 'cloud_provider' in first_result
            assert 'framework' in first_result
            assert 'overall_score' in first_result
            assert 'compliance_status' in first_result
    
    def test_compliance_details_api_specific_provider(self):
        """Test compliance details API with specific provider"""
        for provider in ['aws', 'gcp', 'azure']:
            response = self.client.get(f'/api/compliance-details?provider={provider}')
            assert response.status_code == 200
            
            data = json.loads(response.data)
            assert isinstance(data, list)
            
            # All results should be for the specified provider
            for result in data:
                assert result['cloud_provider'] == provider
    
    def test_cloud_providers_api(self):
        """Test the cloud providers API endpoint"""
        response = self.client.get('/api/cloud-providers')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert isinstance(data, list)
        assert len(data) == 3  # AWS, GCP, Azure
        
        provider_ids = [p['id'] for p in data]
        assert 'aws' in provider_ids
        assert 'gcp' in provider_ids
        assert 'azure' in provider_ids
        
        # Check structure
        for provider in data:
            assert 'id' in provider
            assert 'name' in provider
            assert 'status' in provider
    
    def test_frameworks_api(self):
        """Test the frameworks API endpoint"""
        response = self.client.get('/api/frameworks')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert isinstance(data, list)
        
        # Should include SOC2 at minimum
        framework_ids = [f['id'] for f in data]
        assert 'soc2' in framework_ids
        
        # Check structure
        for framework in data:
            assert 'id' in framework
            assert 'name' in framework
            assert 'controls_count' in framework
            assert 'status' in framework
    
    def test_generate_report_api(self):
        """Test the generate report API endpoint"""
        response = self.client.get('/api/generate-report?provider=aws&framework=soc2')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'report_id' in data
        assert 'provider' in data
        assert 'framework' in data
        assert 'generated_at' in data
        assert 'status' in data
        assert data['provider'] == 'aws'
        assert data['framework'] == 'soc2'
        assert data['status'] == 'generated'

class TestScanAPI:
    """Test the scan API endpoints"""
    
    def setup_method(self):
        """Setup test fixtures"""
        app.config['TESTING'] = True
        self.client = app.test_client()
    
    def test_scan_all_providers_default(self):
        """Test scanning all providers with default settings"""
        scan_request = {
            "providers": ["all"],
            "frameworks": ["soc2"]
        }
        
        response = self.client.post('/api/scan', 
                                  data=json.dumps(scan_request),
                                  content_type='application/json')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'scan_id' in data
        assert data['status'] == 'completed'
        assert 'results' in data
        assert 'summary' in data
        
        # Check summary structure
        summary = data['summary']
        assert 'total_controls' in summary
        assert 'compliant' in summary
        assert 'partial' in summary
        assert 'non_compliant' in summary
        assert 'overall_score' in summary
        
        # Should have results for all providers
        results = data['results']
        assert len(results) > 0
        
        provider_results = set(r['cloud_provider'] for r in results)
        assert 'aws' in provider_results
        assert 'gcp' in provider_results
        assert 'azure' in provider_results
    
    def test_scan_specific_provider(self):
        """Test scanning specific provider"""
        scan_request = {
            "providers": ["aws"],
            "frameworks": ["soc2"],
            "controls": ["CC6.1"]
        }
        
        response = self.client.post('/api/scan',
                                  data=json.dumps(scan_request),
                                  content_type='application/json')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'completed'
        
        # All results should be for AWS only
        results = data['results']
        for result in results:
            assert result['cloud_provider'] == 'aws'
            assert result['control_id'] == 'CC6.1'
    
    def test_scan_invalid_request(self):
        """Test scan with invalid request data"""
        # Test with no JSON data
        response = self.client.post('/api/scan', 
                                  data='invalid json',
                                  content_type='application/json')
        assert response.status_code == 500
        
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_get_scan_results(self):
        """Test retrieving scan results by ID"""
        scan_id = "SCAN-20240616-123456"
        response = self.client.get(f'/api/scan/{scan_id}')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'scan_id' in data
        assert data['scan_id'] == scan_id

class TestScoreAPI:
    """Test the score API endpoints"""
    
    def setup_method(self):
        """Setup test fixtures"""
        app.config['TESTING'] = True
        self.client = app.test_client()
    
    def test_get_scores_default(self):
        """Test getting scores with default parameters"""
        response = self.client.get('/api/score')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'total_results' in data
        assert 'filters_applied' in data
        assert 'summary' in data
        assert 'scores' in data
        assert 'generated_at' in data
        
        # Check filters structure
        filters = data['filters_applied']
        assert filters['provider'] == 'all'
        assert filters['framework'] == 'soc2'
        assert filters['min_score'] == 0
        assert filters['max_score'] == 100
    
    def test_get_scores_with_filters(self):
        """Test getting scores with specific filters"""
        response = self.client.get('/api/score?provider=aws&control=CC6.1&min_score=80&status=compliant')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        filters = data['filters_applied']
        assert filters['provider'] == 'aws'
        assert filters['control_id'] == 'CC6.1'
        assert filters['min_score'] == 80.0
        assert filters['status'] == 'compliant'
        
        # All returned scores should match filters
        scores = data['scores']
        for score in scores:
            assert score['cloud_provider'] == 'aws'
            assert score['control_id'] == 'CC6.1'
            assert score['overall_score'] >= 80.0
            assert score['compliance_status'] == 'compliant'
    
    def test_get_scores_score_range_filter(self):
        """Test getting scores with score range filter"""
        response = self.client.get('/api/score?min_score=90&max_score=100')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        scores = data['scores']
        
        for score in scores:
            assert 90.0 <= score['overall_score'] <= 100.0
    
    def test_get_scores_provider_filter(self):
        """Test getting scores filtered by provider"""
        for provider in ['aws', 'gcp', 'azure']:
            response = self.client.get(f'/api/score?provider={provider}')
            assert response.status_code == 200
            
            data = json.loads(response.data)
            scores = data['scores']
            
            # All scores should be for the specified provider
            for score in scores:
                assert score['cloud_provider'] == provider
    
    def test_get_scores_invalid_parameters(self):
        """Test getting scores with invalid parameters"""
        # Test with invalid score range
        response = self.client.get('/api/score?min_score=invalid')
        assert response.status_code == 500
        
        data = json.loads(response.data)
        assert 'error' in data

if __name__ == '__main__':
    pytest.main([__file__])