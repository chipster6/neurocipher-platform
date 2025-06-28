import random
from datetime import datetime, timedelta
from typing import Dict, List, Any
import streamlit as st

class CloudScanner:
    """
    Simulates cloud security scanning for AWS, Azure, and GCP
    Generates realistic mock data for demonstration purposes
    """
    
    def __init__(self):
        self.scan_results = {}
        self.overall_score = 0
        
    def scan_provider(self, provider: str, scan_options: Dict[str, bool]) -> Dict[str, Any]:
        """
        Simulate scanning a cloud provider for security issues
        """
        # Input validation
        from input_validation import validator
        
        # Validate provider
        is_valid, error = validator.validate_input(provider, 'provider_name')
        if not is_valid:
            raise ValueError(f"Invalid provider: {error}")
        
        # Validate scan options
        is_valid, error = validator.validate_scan_options(scan_options)
        if not is_valid:
            raise ValueError(f"Invalid scan options: {error}")
        results = {
            'provider': provider,
            'timestamp': datetime.now().isoformat(),
            'risks': [],
            'compliance': {},
            'score': 0
        }
        
        # Generate mock security risks based on scan options
        if scan_options.get('security_groups', False):
            results['risks'].extend(self._generate_security_group_risks(provider))
        
        if scan_options.get('encryption', False):
            results['risks'].extend(self._generate_encryption_risks(provider))
        
        if scan_options.get('access_controls', False):
            results['risks'].extend(self._generate_access_control_risks(provider))
        
        if scan_options.get('network_config', False):
            results['risks'].extend(self._generate_network_risks(provider))
        
        if scan_options.get('compliance', False):
            results['compliance'] = self._generate_compliance_data(provider)
        
        # Calculate score based on risks
        results['score'] = self._calculate_provider_score(results['risks'])
        
        self.scan_results[provider] = results
        return results
    
    def _generate_security_group_risks(self, provider: str) -> List[Dict[str, Any]]:
        """Generate mock security group related risks"""
        risks = []
        
        # Common security group issues
        potential_risks = [
            {
                'title': 'Wide Open Access Door',
                'description': 'Some of your security rules allow anyone on the internet to connect to your systems.',
                'impact': 'This is like leaving your front door wide open - anyone could walk in and access your business data.',
                'remediation': 'Change your security settings to only allow specific, trusted IP addresses to connect. It\'s like giving keys only to people who need them.',
                'severity': 'Critical',
                'provider': provider,
                'category': 'access_control'
            },
            {
                'title': 'Database Exposed to Internet',
                'description': 'Your database can be reached directly from the internet.',
                'impact': 'This is like keeping your filing cabinet on the sidewalk - anyone could access your important customer information.',
                'remediation': 'Move your database behind a firewall so only your applications can reach it, not the whole internet.',
                'severity': 'Critical',
                'provider': provider,
                'category': 'network_security'
            },
            {
                'title': 'Too Many Open Ports',
                'description': 'Your systems have many unnecessary network ports open.',
                'impact': 'Think of this like having too many unlocked doors in your building - more ways for intruders to get in.',
                'remediation': 'Close network ports you don\'t need. Keep only the doors open that you actually use for business.',
                'severity': 'Medium',
                'provider': provider,
                'category': 'network_security'
            }
        ]
        
        # Randomly select 1-3 risks for demonstration
        num_risks = random.randint(1, 3)
        selected_risks = random.sample(potential_risks, min(num_risks, len(potential_risks)))
        
        return selected_risks
    
    def _generate_encryption_risks(self, provider: str) -> List[Dict[str, Any]]:
        """Generate mock encryption related risks"""
        risks = []
        
        potential_risks = [
            {
                'title': 'Unprotected Data Storage',
                'description': 'Some of your stored data is not encrypted (scrambled for protection).',
                'impact': 'This is like keeping important documents in a regular folder instead of a locked safe - if someone gets access, they can read everything.',
                'remediation': 'Turn on encryption for your data storage. It\'s like putting your important files in a combination safe.',
                'severity': 'High',
                'provider': provider,
                'category': 'data_protection'
            },
            {
                'title': 'Weak Encryption Settings',
                'description': 'Your data protection is using old, weaker encryption methods.',
                'impact': 'This is like using an old lock that\'s easier to pick - it provides some protection but not the best available.',
                'remediation': 'Upgrade to stronger encryption settings. It\'s like replacing an old lock with a modern, high-security one.',
                'severity': 'Medium',
                'provider': provider,
                'category': 'data_protection'
            },
            {
                'title': 'Unencrypted Data Transfer',
                'description': 'Data moving between your systems is not protected during transfer.',
                'impact': 'This is like sending important mail without putting it in an envelope - people could read it while it\'s being delivered.',
                'remediation': 'Enable encryption for data in transit. It\'s like sealing your mail in a secure envelope that only the recipient can open.',
                'severity': 'Medium',
                'provider': provider,
                'category': 'data_protection'
            }
        ]
        
        num_risks = random.randint(1, 2)
        selected_risks = random.sample(potential_risks, min(num_risks, len(potential_risks)))
        
        return selected_risks
    
    def _generate_access_control_risks(self, provider: str) -> List[Dict[str, Any]]:
        """Generate mock access control related risks"""
        risks = []
        
        potential_risks = [
            {
                'title': 'Too Many Administrator Accounts',
                'description': 'Several people have full administrator access to your cloud systems.',
                'impact': 'This is like giving master keys to too many employees - if one key gets lost or misused, it could affect everything.',
                'remediation': 'Give people only the access they need for their job. Use the "principle of least privilege" - like giving department keys instead of master keys.',
                'severity': 'High',
                'provider': provider,
                'category': 'access_control'
            },
            {
                'title': 'No Multi-Factor Authentication',
                'description': 'Important accounts only require a password to log in.',
                'impact': 'This is like protecting your safe with just one lock - if someone guesses or steals the password, they\'re in.',
                'remediation': 'Set up two-factor authentication. It\'s like requiring both a key and a security code to open your safe.',
                'severity': 'High',
                'provider': provider,
                'category': 'access_control'
            },
            {
                'title': 'Inactive User Accounts',
                'description': 'Former employees or unused accounts still have access to your systems.',
                'impact': 'This is like not collecting keys when an employee leaves - their access could be misused later.',
                'remediation': 'Regularly review and remove access for people who no longer need it. It\'s like collecting keys when someone leaves the company.',
                'severity': 'Medium',
                'provider': provider,
                'category': 'access_control'
            }
        ]
        
        num_risks = random.randint(1, 3)
        selected_risks = random.sample(potential_risks, min(num_risks, len(potential_risks)))
        
        return selected_risks
    
    def _generate_network_risks(self, provider: str) -> List[Dict[str, Any]]:
        """Generate mock network configuration related risks"""
        risks = []
        
        potential_risks = [
            {
                'title': 'Missing Network Monitoring',
                'description': 'Your network traffic is not being watched for suspicious activity.',
                'impact': 'This is like not having security cameras in your building - you won\'t know if someone unauthorized is sneaking around.',
                'remediation': 'Set up network monitoring to watch for unusual activity. It\'s like installing security cameras and alarms.',
                'severity': 'Medium',
                'provider': provider,
                'category': 'monitoring'
            },
            {
                'title': 'Unprotected Network Communications',
                'description': 'Some network connections are not using secure protocols.',
                'impact': 'This is like having phone conversations on an old party line - others might be able to listen in.',
                'remediation': 'Use secure communication protocols (HTTPS, TLS) for all network traffic. It\'s like switching to a private, encrypted phone line.',
                'severity': 'Medium',
                'provider': provider,
                'category': 'network_security'
            }
        ]
        
        num_risks = random.randint(0, 2)
        selected_risks = random.sample(potential_risks, min(num_risks, len(potential_risks))) if num_risks > 0 else []
        
        return selected_risks
    
    def _generate_compliance_data(self, provider: str) -> Dict[str, int]:
        """Generate mock compliance scores"""
        return {
            'data_protection': random.randint(70, 95),
            'access_control': random.randint(65, 90),
            'network_security': random.randint(75, 95),
            'monitoring': random.randint(60, 85),
            'backup_recovery': random.randint(80, 100)
        }
    
    def _calculate_provider_score(self, risks: List[Dict[str, Any]]) -> int:
        """Calculate overall security score based on risks"""
        base_score = 100
        
        for risk in risks:
            severity = risk['severity']
            if severity == 'Critical':
                base_score -= random.randint(15, 25)
            elif severity == 'High':
                base_score -= random.randint(8, 15)
            elif severity == 'Medium':
                base_score -= random.randint(3, 8)
            elif severity == 'Low':
                base_score -= random.randint(1, 3)
        
        return max(0, base_score)
    
    def get_comprehensive_results(self) -> Dict[str, Any]:
        """
        Combine results from all scanned providers into a comprehensive report
        """
        all_risks = []
        all_compliance = {}
        provider_scores = []
        
        # Combine data from all providers
        for provider, results in self.scan_results.items():
            all_risks.extend(results['risks'])
            provider_scores.append(results['score'])
            
            # Merge compliance data
            for key, value in results.get('compliance', {}).items():
                if key in all_compliance:
                    all_compliance[key] = (all_compliance[key] + value) / 2
                else:
                    all_compliance[key] = value
        
        # Calculate overall score
        overall_score = sum(provider_scores) / len(provider_scores) if provider_scores else 0
        
        # Calculate compliance score
        compliance_score = sum(all_compliance.values()) / len(all_compliance) if all_compliance else 0
        
        # Add some resolved issues for demonstration
        resolved_issues = random.randint(2, 8)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'overall_score': round(overall_score),
            'compliance_score': round(compliance_score),
            'risks': all_risks,
            'compliance': all_compliance,
            'providers_scanned': list(self.scan_results.keys()),
            'resolved_issues': resolved_issues,
            'scan_duration': f"{random.randint(2, 8)} minutes"
        }
