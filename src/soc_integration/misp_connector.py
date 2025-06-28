#!/usr/bin/env python3
"""
MISP Threat Intelligence Platform Connector
Submits IOCs and threat indicators to MISP for community sharing
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import requests
from requests.auth import HTTPBasicAuth
import hashlib
import re

logger = logging.getLogger(__name__)

class MISPConnector:
    """MISP Platform connector for threat intelligence sharing"""
    
    def __init__(self, misp_url: str, api_key: str, verify_ssl: bool = True):
        """
        Initialize MISP connector
        
        Args:
            misp_url: MISP instance URL
            api_key: MISP API authentication key
            verify_ssl: Whether to verify SSL certificates
        """
        self.misp_url = misp_url.rstrip('/')
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
        # IOC classification mapping
        self.ioc_types = {
            'ip': 'ip-dst',
            'domain': 'domain',
            'url': 'url',
            'hash_md5': 'md5',
            'hash_sha1': 'sha1',
            'hash_sha256': 'sha256',
            'email': 'email-src',
            'filename': 'filename',
            'mutex': 'mutex',
            'registry_key': 'regkey'
        }
        
        # Threat actor mapping
        self.threat_actors = {
            'apt1': 'APT1',
            'apt28': 'APT28 (Fancy Bear)',
            'apt29': 'APT29 (Cozy Bear)',
            'lazarus': 'Lazarus Group',
            'carbanak': 'Carbanak',
            'unknown': 'Unknown Actor'
        }
    
    def create_event(self, hunting_result: Dict) -> Optional[str]:
        """
        Create new MISP event from hunting results
        
        Args:
            hunting_result: Threat hunting analysis results
            
        Returns:
            MISP event UUID if successful, None otherwise
        """
        try:
            # Extract threat intelligence from hunting results
            threat_data = self._extract_threat_data(hunting_result)
            
            # Build MISP event payload
            event_payload = {
                'Event': {
                    'info': f"AuditHound Detection: {threat_data['title']}",
                    'threat_level_id': self._calculate_threat_level(threat_data['risk_score']),
                    'analysis': '1',  # Initial analysis
                    'distribution': '1',  # Your organization only
                    'published': False,
                    'date': datetime.now().strftime('%Y-%m-%d'),
                    'orgc_id': '1',  # Your organization
                    'Attribute': self._build_attributes(threat_data),
                    'Tag': self._build_tags(threat_data)
                }
            }
            
            # Submit to MISP
            response = self.session.post(
                f"{self.misp_url}/events/add",
                json=event_payload,
                verify=self.verify_ssl,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                event_uuid = result.get('Event', {}).get('uuid')
                logger.info(f"Successfully created MISP event: {event_uuid}")
                return event_uuid
            else:
                logger.error(f"MISP event creation failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating MISP event: {str(e)}")
            return None
    
    def submit_indicators(self, indicators: List[Dict]) -> List[str]:
        """
        Submit IOCs as individual attributes to existing event
        
        Args:
            indicators: List of IOC dictionaries
            
        Returns:
            List of created attribute UUIDs
        """
        created_attributes = []
        
        for indicator in indicators:
            try:
                attr_payload = {
                    'Attribute': {
                        'type': self.ioc_types.get(indicator['type'], 'other'),
                        'value': indicator['value'],
                        'category': self._get_category(indicator['type']),
                        'to_ids': indicator.get('to_ids', True),
                        'distribution': '1',
                        'comment': indicator.get('description', 'AuditHound detection')
                    }
                }
                
                response = self.session.post(
                    f"{self.misp_url}/attributes/add",
                    json=attr_payload,
                    verify=self.verify_ssl,
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    attr_uuid = result.get('Attribute', {}).get('uuid')
                    created_attributes.append(attr_uuid)
                    logger.info(f"Created MISP attribute: {attr_uuid} - {indicator['value']}")
                else:
                    logger.warning(f"Failed to create attribute for {indicator['value']}")
                    
            except Exception as e:
                logger.error(f"Error submitting indicator {indicator['value']}: {str(e)}")
        
        return created_attributes
    
    def enrich_with_misp(self, ioc_value: str) -> Dict:
        """
        Query MISP for existing intelligence on IOC
        
        Args:
            ioc_value: IOC value to search for
            
        Returns:
            Dictionary containing MISP intelligence data
        """
        try:
            search_payload = {
                'value': ioc_value,
                'type': 'attribute',
                'limit': 50,
                'page': 1
            }
            
            response = self.session.post(
                f"{self.misp_url}/attributes/restSearch",
                json=search_payload,
                verify=self.verify_ssl,
                timeout=30
            )
            
            if response.status_code == 200:
                results = response.json()
                return self._process_misp_results(results)
            else:
                logger.warning(f"MISP search failed for {ioc_value}: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error querying MISP for {ioc_value}: {str(e)}")
            return {}
    
    def _extract_threat_data(self, hunting_result: Dict) -> Dict:
        """Extract and normalize threat data from hunting results"""
        risk_score = hunting_result.get('risk_score', 50)
        hunting_type = hunting_result.get('hunting_type', 'unknown')
        
        # Extract IOCs from results
        iocs = []
        if 'matched_assets' in hunting_result:
            for asset in hunting_result['matched_assets']:
                # Extract IP addresses
                if 'ip_address' in asset:
                    iocs.append({
                        'type': 'ip',
                        'value': asset['ip_address'],
                        'description': f"Asset involved in {hunting_type}",
                        'to_ids': True
                    })
                
                # Extract domains from URLs
                if 'network_connections' in asset:
                    for conn in asset['network_connections']:
                        if 'destination' in conn:
                            domain = self._extract_domain(conn['destination'])
                            if domain:
                                iocs.append({
                                    'type': 'domain',
                                    'value': domain,
                                    'description': f"Network connection in {hunting_type}",
                                    'to_ids': True
                                })
        
        return {
            'title': f"{hunting_type.replace('_', ' ').title()} Detection",
            'description': hunting_result.get('description', 'Automated threat hunting detection'),
            'risk_score': risk_score,
            'hunting_type': hunting_type,
            'iocs': iocs,
            'threat_actor': hunting_result.get('threat_actor', 'unknown'),
            'attack_techniques': hunting_result.get('mitre_techniques', [])
        }
    
    def _build_attributes(self, threat_data: Dict) -> List[Dict]:
        """Build MISP attributes from threat data"""
        attributes = []
        
        # Add IOCs as attributes
        for ioc in threat_data['iocs']:
            attributes.append({
                'type': self.ioc_types.get(ioc['type'], 'other'),
                'value': ioc['value'],
                'category': self._get_category(ioc['type']),
                'to_ids': ioc.get('to_ids', True),
                'distribution': '1',
                'comment': ioc.get('description', '')
            })
        
        # Add MITRE ATT&CK techniques
        for technique in threat_data['attack_techniques']:
            attributes.append({
                'type': 'text',
                'value': technique,
                'category': 'External analysis',
                'to_ids': False,
                'distribution': '1',
                'comment': 'MITRE ATT&CK Technique'
            })
        
        return attributes
    
    def _build_tags(self, threat_data: Dict) -> List[Dict]:
        """Build MISP tags from threat data"""
        tags = []
        
        # Add hunting type tag
        tags.append({'name': f"audithound:{threat_data['hunting_type']}"})
        
        # Add threat actor tag if known
        if threat_data['threat_actor'] != 'unknown':
            actor = self.threat_actors.get(threat_data['threat_actor'], threat_data['threat_actor'])
            tags.append({'name': f"actor:{actor}"})
        
        # Add risk level tag
        risk_level = self._get_risk_level(threat_data['risk_score'])
        tags.append({'name': f"risk:{risk_level}"})
        
        # Add MITRE ATT&CK tags
        for technique in threat_data['attack_techniques']:
            tags.append({'name': f"mitre-attack:{technique}"})
        
        return tags
    
    def _calculate_threat_level(self, risk_score: float) -> int:
        """Calculate MISP threat level from risk score"""
        if risk_score >= 90:
            return 1  # High
        elif risk_score >= 70:
            return 2  # Medium
        elif risk_score >= 50:
            return 3  # Low
        else:
            return 4  # Undefined
    
    def _get_category(self, ioc_type: str) -> str:
        """Get MISP category for IOC type"""
        category_mapping = {
            'ip': 'Network activity',
            'domain': 'Network activity',
            'url': 'Network activity',
            'hash_md5': 'Payload delivery',
            'hash_sha1': 'Payload delivery',
            'hash_sha256': 'Payload delivery',
            'email': 'Payload delivery',
            'filename': 'Artifacts dropped',
            'mutex': 'Artifacts dropped',
            'registry_key': 'Persistence mechanism'
        }
        return category_mapping.get(ioc_type, 'Other')
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level string"""
        if risk_score >= 90:
            return 'critical'
        elif risk_score >= 70:
            return 'high'
        elif risk_score >= 50:
            return 'medium'
        else:
            return 'low'
    
    def _extract_domain(self, url_or_ip: str) -> Optional[str]:
        """Extract domain from URL or return None for IP"""
        # Simple domain extraction - can be enhanced
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', url_or_ip):
            return None  # IP address
        
        # Extract domain from URL
        domain_match = re.search(r'(?:https?://)?(?:www\.)?([^/]+)', url_or_ip)
        if domain_match:
            return domain_match.group(1)
        
        return None
    
    def _process_misp_results(self, results: Dict) -> Dict:
        """Process MISP search results into structured format"""
        processed = {
            'found': False,
            'events': [],
            'threat_actors': [],
            'attack_techniques': [],
            'first_seen': None,
            'last_seen': None
        }
        
        if 'response' in results and 'Attribute' in results['response']:
            attributes = results['response']['Attribute']
            processed['found'] = len(attributes) > 0
            
            for attr in attributes:
                event_info = attr.get('Event', {})
                processed['events'].append({
                    'event_id': event_info.get('id'),
                    'info': event_info.get('info'),
                    'date': attr.get('timestamp'),
                    'category': attr.get('category'),
                    'type': attr.get('type')
                })
        
        return processed

# Example usage and testing
if __name__ == "__main__":
    import sys
    import os
    
    # Test MISP connector
    misp_url = os.getenv('MISP_URL', 'https://misp.yourdomain.com')
    api_key = os.getenv('MISP_API_KEY', 'your-api-key-here')
    
    if api_key == 'your-api-key-here':
        print("Please set MISP_URL and MISP_API_KEY environment variables")
        sys.exit(1)
    
    connector = MISPConnector(misp_url, api_key)
    
    # Test with sample hunting result
    sample_result = {
        'hunting_type': 'lateral_movement',
        'risk_score': 85,
        'description': 'Detected lateral movement patterns',
        'threat_actor': 'apt28',
        'mitre_techniques': ['T1021.001', 'T1078'],
        'matched_assets': [
            {
                'ip_address': '192.168.1.100',
                'network_connections': [
                    {'destination': 'malicious.example.com'}
                ]
            }
        ]
    }
    
    print("Testing MISP event creation...")
    event_uuid = connector.create_event(sample_result)
    if event_uuid:
        print(f"✅ Successfully created MISP event: {event_uuid}")
    else:
        print("❌ Failed to create MISP event")