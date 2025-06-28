"""
Threat Intelligence Correlation Engine
Maps risk titles to CVE keywords and MITRE tactics for enhanced threat context
"""

import json
import logging
import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import defaultdict
import difflib


@dataclass
class ThreatCorrelation:
    """Represents a correlation between scan findings and threat intelligence"""
    risk_id: str
    risk_title: str
    correlated_cves: List[Dict[str, Any]]
    mitre_tactics: List[Dict[str, Any]]
    correlation_confidence: float
    threat_context: Dict[str, Any]


@dataclass
class CorrelationRule:
    """Represents a correlation rule for mapping risks to threats"""
    rule_id: str
    risk_patterns: List[str]
    cve_keywords: List[str]
    mitre_techniques: List[str]
    confidence_weight: float


class ThreatCorrelationEngine:
    """
    Correlates security scan results with threat intelligence data
    Maps detected vulnerabilities to CVEs and MITRE ATT&CK techniques
    """
    
    def __init__(self, storage_backend):
        self.storage = storage_backend
        self.logger = logging.getLogger(__name__)
        
        # Initialize correlation rules
        self.correlation_rules = self._initialize_correlation_rules()
        
        # Load threat intelligence data
        self.threat_data = self._load_threat_intelligence()
        
        # CVE database
        self.cve_database = self._load_cve_database()
        
        # MITRE ATT&CK database
        self.mitre_database = self._load_mitre_database()
        
    def correlate_threats(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlate scan results with threat intelligence
        
        Args:
            scan_data: Security scan results
            
        Returns:
            Comprehensive threat correlation analysis
        """
        try:
            self.logger.info("Starting threat intelligence correlation analysis")
            
            risks = scan_data.get('risks', [])
            correlations = []
            
            # Process each risk
            for risk in risks:
                correlation = self._correlate_single_risk(risk)
                if correlation:
                    correlations.append(correlation)
            
            # Aggregate analysis
            aggregated_analysis = self._aggregate_threat_analysis(correlations)
            
            # Generate threat landscape view
            threat_landscape = self._generate_threat_landscape(correlations)
            
            # Create attack path analysis
            attack_paths = self._analyze_attack_paths(correlations)
            
            # Priority threat assessment
            priority_threats = self._assess_priority_threats(correlations)
            
            correlation_results = {
                'analysis_timestamp': datetime.now().isoformat(),
                'total_risks_analyzed': len(risks),
                'correlations_found': len(correlations),
                'individual_correlations': [self._serialize_correlation(c) for c in correlations],
                'aggregated_analysis': aggregated_analysis,
                'threat_landscape': threat_landscape,
                'attack_paths': attack_paths,
                'priority_threats': priority_threats,
                'intelligence_freshness': self._assess_intelligence_freshness(),
                'recommendations': self._generate_correlation_recommendations(correlations)
            }
            
            self.logger.info(f"Threat correlation completed: {len(correlations)} correlations found")
            return correlation_results
            
        except Exception as e:
            self.logger.error(f"Error in threat correlation: {e}")
            return {'error': str(e), 'timestamp': datetime.now().isoformat()}
    
    def get_cve_threat_context(self, cve_id: str) -> Dict[str, Any]:
        """Get detailed threat context for a specific CVE"""
        cve_data = self.cve_database.get(cve_id, {})
        if not cve_data:
            return {'error': f'CVE {cve_id} not found in database'}
        
        # Find related MITRE techniques
        related_techniques = self._find_related_mitre_techniques(cve_data)
        
        # Assess current threat level
        threat_level = self._assess_cve_threat_level(cve_data)
        
        # Find exploitation indicators
        exploitation_indicators = self._find_exploitation_indicators(cve_id)
        
        return {
            'cve_id': cve_id,
            'description': cve_data.get('description', ''),
            'cvss_score': cve_data.get('cvss_score', 0),
            'severity': cve_data.get('severity', 'Unknown'),
            'published_date': cve_data.get('published_date', ''),
            'related_mitre_techniques': related_techniques,
            'threat_level': threat_level,
            'exploitation_indicators': exploitation_indicators,
            'remediation_guidance': cve_data.get('remediation', []),
            'affected_products': cve_data.get('affected_products', [])
        }
    
    def analyze_mitre_coverage(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze MITRE ATT&CK technique coverage from scan results"""
        risks = scan_data.get('risks', [])
        
        # Map risks to MITRE techniques
        technique_coverage = defaultdict(list)
        tactic_coverage = defaultdict(int)
        
        for risk in risks:
            techniques = self._map_risk_to_mitre(risk)
            for technique in techniques:
                technique_id = technique.get('technique_id', '')
                tactic = technique.get('tactic', '')
                
                technique_coverage[technique_id].append({
                    'risk_id': risk.get('id', ''),
                    'risk_description': risk.get('description', ''),
                    'severity': risk.get('severity', 'Medium'),
                    'provider': risk.get('provider', 'unknown')
                })
                
                if tactic:
                    tactic_coverage[tactic] += 1
        
        # Calculate coverage statistics
        total_techniques = len(self.mitre_database)
        covered_techniques = len(technique_coverage)
        coverage_percentage = (covered_techniques / total_techniques) * 100 if total_techniques > 0 else 0
        
        # Identify gaps
        uncovered_techniques = [
            technique_id for technique_id in self.mitre_database.keys()
            if technique_id not in technique_coverage
        ]
        
        return {
            'total_mitre_techniques': total_techniques,
            'covered_techniques': covered_techniques,
            'coverage_percentage': round(coverage_percentage, 1),
            'technique_coverage': dict(technique_coverage),
            'tactic_coverage': dict(tactic_coverage),
            'uncovered_techniques': uncovered_techniques[:20],  # Top 20 gaps
            'high_risk_techniques': self._identify_high_risk_techniques(technique_coverage),
            'recommended_detections': self._recommend_detection_gaps(uncovered_techniques)
        }
    
    def _initialize_correlation_rules(self) -> List[CorrelationRule]:
        """Initialize correlation rules for mapping risks to threats"""
        rules = [
            CorrelationRule(
                rule_id="SSH_ACCESS",
                risk_patterns=["ssh", "port 22", "remote access", "unrestricted access"],
                cve_keywords=["ssh", "openssh", "remote", "authentication"],
                mitre_techniques=["T1021.004", "T1078"],
                confidence_weight=0.8
            ),
            CorrelationRule(
                rule_id="ENCRYPTION_WEAK",
                risk_patterns=["weak encryption", "unencrypted", "no encryption", "ssl", "tls"],
                cve_keywords=["encryption", "ssl", "tls", "crypto", "cipher"],
                mitre_techniques=["T1040", "T1557"],
                confidence_weight=0.7
            ),
            CorrelationRule(
                rule_id="ACCESS_CONTROL",
                risk_patterns=["access control", "authentication", "authorization", "mfa", "multi-factor"],
                cve_keywords=["authentication", "authorization", "access", "privilege"],
                mitre_techniques=["T1078", "T1110", "T1556"],
                confidence_weight=0.9
            ),
            CorrelationRule(
                rule_id="DATABASE_EXPOSURE",
                risk_patterns=["database", "exposed", "public access", "storage"],
                cve_keywords=["database", "sql", "mongodb", "redis", "storage"],
                mitre_techniques=["T1530", "T1505.003"],
                confidence_weight=0.8
            ),
            CorrelationRule(
                rule_id="NETWORK_SECURITY",
                risk_patterns=["security group", "firewall", "network", "port", "open"],
                cve_keywords=["network", "firewall", "port", "protocol"],
                mitre_techniques=["T1021", "T1046", "T1040"],
                confidence_weight=0.6
            ),
            CorrelationRule(
                rule_id="ADMIN_PRIVILEGES",
                risk_patterns=["admin", "administrator", "root", "privileged", "elevated"],
                cve_keywords=["privilege", "escalation", "admin", "root"],
                mitre_techniques=["T1078.003", "T1548", "T1134"],
                confidence_weight=0.8
            ),
            CorrelationRule(
                rule_id="LOG4SHELL",
                risk_patterns=["log4j", "java", "logging", "deserialization"],
                cve_keywords=["log4j", "java", "jndi", "ldap"],
                mitre_techniques=["T1190", "T1059.007"],
                confidence_weight=0.95
            ),
            CorrelationRule(
                rule_id="XZ_BACKDOOR",
                risk_patterns=["xz", "compression", "backdoor", "supply chain"],
                cve_keywords=["xz", "liblzma", "backdoor", "compression"],
                mitre_techniques=["T1195.002", "T1554"],
                confidence_weight=0.95
            )
        ]
        
        return rules
    
    def _correlate_single_risk(self, risk: Dict[str, Any]) -> Optional[ThreatCorrelation]:
        """Correlate a single risk with threat intelligence"""
        risk_description = risk.get('description', '').lower()
        risk_category = risk.get('category', '').lower()
        
        # Find matching correlation rules
        matching_rules = []
        for rule in self.correlation_rules:
            if self._matches_rule(risk_description + " " + risk_category, rule):
                matching_rules.append(rule)
        
        if not matching_rules:
            return None
        
        # Get CVE correlations
        correlated_cves = []
        for rule in matching_rules:
            cves = self._find_matching_cves(rule.cve_keywords)
            correlated_cves.extend(cves)
        
        # Get MITRE technique correlations
        mitre_tactics = []
        for rule in matching_rules:
            techniques = self._get_mitre_techniques(rule.mitre_techniques)
            mitre_tactics.extend(techniques)
        
        # Calculate correlation confidence
        confidence = self._calculate_correlation_confidence(matching_rules, correlated_cves, mitre_tactics)
        
        # Generate threat context
        threat_context = self._generate_threat_context(risk, correlated_cves, mitre_tactics)
        
        return ThreatCorrelation(
            risk_id=risk.get('id', f"risk_{hash(risk_description)}"),
            risk_title=risk.get('title', risk_description[:50]),
            correlated_cves=correlated_cves,
            mitre_tactics=mitre_tactics,
            correlation_confidence=confidence,
            threat_context=threat_context
        )
    
    def _matches_rule(self, text: str, rule: CorrelationRule) -> bool:
        """Check if text matches correlation rule patterns"""
        for pattern in rule.risk_patterns:
            if pattern.lower() in text.lower():
                return True
        return False
    
    def _find_matching_cves(self, keywords: List[str]) -> List[Dict[str, Any]]:
        """Find CVEs matching keywords"""
        matching_cves = []
        
        for cve_id, cve_data in self.cve_database.items():
            description = cve_data.get('description', '').lower()
            
            # Check if any keyword matches
            for keyword in keywords:
                if keyword.lower() in description:
                    matching_cves.append({
                        'cve_id': cve_id,
                        'description': cve_data.get('description', ''),
                        'cvss_score': cve_data.get('cvss_score', 0),
                        'severity': cve_data.get('severity', 'Unknown'),
                        'published_date': cve_data.get('published_date', ''),
                        'match_keywords': [keyword]
                    })
                    break
        
        # Sort by CVSS score (highest first)
        matching_cves.sort(key=lambda x: x['cvss_score'], reverse=True)
        
        return matching_cves[:5]  # Return top 5 matches
    
    def _get_mitre_techniques(self, technique_ids: List[str]) -> List[Dict[str, Any]]:
        """Get MITRE technique details"""
        techniques = []
        
        for technique_id in technique_ids:
            if technique_id in self.mitre_database:
                technique_data = self.mitre_database[technique_id]
                techniques.append({
                    'technique_id': technique_id,
                    'name': technique_data.get('name', ''),
                    'tactic': technique_data.get('tactic', ''),
                    'description': technique_data.get('description', ''),
                    'platforms': technique_data.get('platforms', []),
                    'detection': technique_data.get('detection', ''),
                    'mitigation': technique_data.get('mitigation', '')
                })
        
        return techniques
    
    def _calculate_correlation_confidence(self, rules: List[CorrelationRule], 
                                        cves: List[Dict[str, Any]], 
                                        techniques: List[Dict[str, Any]]) -> float:
        """Calculate confidence score for correlation"""
        if not rules:
            return 0.0
        
        # Base confidence from rule weights
        rule_confidence = sum(rule.confidence_weight for rule in rules) / len(rules)
        
        # Boost confidence based on number of correlations found
        cve_boost = min(0.2, len(cves) * 0.05)
        technique_boost = min(0.2, len(techniques) * 0.1)
        
        # Reduce confidence if no correlations found
        if not cves and not techniques:
            rule_confidence *= 0.3
        
        total_confidence = min(1.0, rule_confidence + cve_boost + technique_boost)
        
        return round(total_confidence, 2)
    
    def _generate_threat_context(self, risk: Dict[str, Any], 
                               cves: List[Dict[str, Any]], 
                               techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive threat context"""
        context = {
            'threat_level': self._assess_threat_level(risk, cves, techniques),
            'exploitation_likelihood': self._assess_exploitation_likelihood(cves),
            'business_impact': self._assess_business_impact(risk, techniques),
            'attack_vectors': self._identify_attack_vectors(techniques),
            'detection_methods': self._suggest_detection_methods(techniques),
            'mitigation_strategies': self._suggest_mitigations(cves, techniques)
        }
        
        return context
    
    def _assess_threat_level(self, risk: Dict[str, Any], 
                           cves: List[Dict[str, Any]], 
                           techniques: List[Dict[str, Any]]) -> str:
        """Assess overall threat level"""
        severity = risk.get('severity', 'Medium')
        
        # Factor in CVE scores
        max_cvss = max((cve.get('cvss_score', 0) for cve in cves), default=0)
        
        # Factor in MITRE technique criticality
        critical_techniques = [t for t in techniques if t.get('tactic') in ['Initial Access', 'Execution', 'Persistence']]
        
        if severity == 'Critical' or max_cvss >= 9.0 or len(critical_techniques) >= 2:
            return 'Critical'
        elif severity == 'High' or max_cvss >= 7.0 or critical_techniques:
            return 'High'
        elif severity == 'Medium' or max_cvss >= 4.0:
            return 'Medium'
        else:
            return 'Low'
    
    def _assess_exploitation_likelihood(self, cves: List[Dict[str, Any]]) -> str:
        """Assess likelihood of exploitation"""
        if not cves:
            return 'Unknown'
        
        # Check for known exploits (simplified - would use threat intel feeds)
        high_cvss_cves = [cve for cve in cves if cve.get('cvss_score', 0) >= 8.0]
        
        if high_cvss_cves:
            return 'High'
        elif len(cves) >= 3:
            return 'Medium'
        else:
            return 'Low'
    
    def _assess_business_impact(self, risk: Dict[str, Any], techniques: List[Dict[str, Any]]) -> str:
        """Assess potential business impact"""
        # High impact techniques
        high_impact_tactics = ['Impact', 'Exfiltration', 'Command and Control']
        
        severity = risk.get('severity', 'Medium')
        provider = risk.get('provider', '')
        
        # Check for high-impact MITRE techniques
        high_impact_techniques = [t for t in techniques if t.get('tactic') in high_impact_tactics]
        
        if severity == 'Critical' or high_impact_techniques:
            return 'High'
        elif severity == 'High' or provider in ['aws', 'azure', 'gcp']:
            return 'Medium'
        else:
            return 'Low'
    
    def _identify_attack_vectors(self, techniques: List[Dict[str, Any]]) -> List[str]:
        """Identify potential attack vectors"""
        vectors = []
        
        for technique in techniques:
            tactic = technique.get('tactic', '')
            if tactic == 'Initial Access':
                vectors.append('External network access')
            elif tactic == 'Lateral Movement':
                vectors.append('Internal network propagation')
            elif tactic == 'Persistence':
                vectors.append('System persistence mechanisms')
            elif tactic == 'Privilege Escalation':
                vectors.append('Privilege escalation')
        
        return list(set(vectors))
    
    def _suggest_detection_methods(self, techniques: List[Dict[str, Any]]) -> List[str]:
        """Suggest detection methods based on MITRE techniques"""
        detections = []
        
        for technique in techniques:
            detection = technique.get('detection', '')
            if detection:
                detections.append(detection)
        
        return list(set(detections))
    
    def _suggest_mitigations(self, cves: List[Dict[str, Any]], techniques: List[Dict[str, Any]]) -> List[str]:
        """Suggest mitigation strategies"""
        mitigations = []
        
        # CVE-based mitigations
        for cve in cves:
            if 'patch' in cve.get('description', '').lower():
                mitigations.append('Apply security patches and updates')
        
        # MITRE-based mitigations
        for technique in techniques:
            mitigation = technique.get('mitigation', '')
            if mitigation:
                mitigations.append(mitigation)
        
        # Generic mitigations
        mitigations.extend([
            'Implement network segmentation',
            'Enable comprehensive logging and monitoring',
            'Enforce principle of least privilege'
        ])
        
        return list(set(mitigations))
    
    def _aggregate_threat_analysis(self, correlations: List[ThreatCorrelation]) -> Dict[str, Any]:
        """Aggregate threat analysis across all correlations"""
        if not correlations:
            return {'total_correlations': 0}
        
        # Count threat levels
        threat_levels = defaultdict(int)
        for correlation in correlations:
            level = correlation.threat_context.get('threat_level', 'Unknown')
            threat_levels[level] += 1
        
        # Most common MITRE tactics
        tactic_counts = defaultdict(int)
        for correlation in correlations:
            for technique in correlation.mitre_tactics:
                tactic = technique.get('tactic', 'Unknown')
                tactic_counts[tactic] += 1
        
        # Most referenced CVEs
        cve_counts = defaultdict(int)
        for correlation in correlations:
            for cve in correlation.correlated_cves:
                cve_id = cve.get('cve_id', '')
                cve_counts[cve_id] += 1
        
        return {
            'total_correlations': len(correlations),
            'threat_level_distribution': dict(threat_levels),
            'top_mitre_tactics': dict(sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)[:5]),
            'top_referenced_cves': dict(sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:5]),
            'average_confidence': round(sum(c.correlation_confidence for c in correlations) / len(correlations), 2),
            'high_confidence_correlations': len([c for c in correlations if c.correlation_confidence >= 0.8])
        }
    
    def _generate_threat_landscape(self, correlations: List[ThreatCorrelation]) -> Dict[str, Any]:
        """Generate threat landscape view"""
        if not correlations:
            return {}
        
        # Create threat landscape matrix
        landscape = {
            'attack_phases': defaultdict(list),
            'threat_actors': [],
            'vulnerable_assets': defaultdict(int),
            'attack_patterns': []
        }
        
        # Map to MITRE ATT&CK kill chain
        for correlation in correlations:
            for technique in correlation.mitre_tactics:
                tactic = technique.get('tactic', 'Unknown')
                landscape['attack_phases'][tactic].append({
                    'technique': technique.get('name', ''),
                    'risk': correlation.risk_title,
                    'confidence': correlation.correlation_confidence
                })
        
        return dict(landscape)
    
    def _analyze_attack_paths(self, correlations: List[ThreatCorrelation]) -> Dict[str, Any]:
        """Analyze potential attack paths"""
        # Simplified attack path analysis
        attack_paths = []
        
        # Group techniques by kill chain phase
        phases = defaultdict(list)
        for correlation in correlations:
            for technique in correlation.mitre_tactics:
                tactic = technique.get('tactic', 'Unknown')
                phases[tactic].append({
                    'technique': technique.get('name', ''),
                    'risk': correlation.risk_title
                })
        
        # Create attack path scenarios
        if 'Initial Access' in phases and 'Execution' in phases:
            attack_paths.append({
                'path': 'Initial Access → Execution',
                'description': 'Attacker gains initial foothold and executes malicious code',
                'techniques_involved': len(phases['Initial Access']) + len(phases['Execution']),
                'risk_level': 'High'
            })
        
        return {
            'total_attack_paths': len(attack_paths),
            'attack_paths': attack_paths,
            'kill_chain_coverage': list(phases.keys())
        }
    
    def _assess_priority_threats(self, correlations: List[ThreatCorrelation]) -> List[Dict[str, Any]]:
        """Assess and prioritize threats"""
        priority_threats = []
        
        for correlation in correlations:
            threat_score = self._calculate_threat_priority_score(correlation)
            
            priority_threats.append({
                'risk_title': correlation.risk_title,
                'threat_level': correlation.threat_context.get('threat_level', 'Unknown'),
                'confidence': correlation.correlation_confidence,
                'priority_score': threat_score,
                'cve_count': len(correlation.correlated_cves),
                'mitre_techniques': len(correlation.mitre_tactics),
                'exploitation_likelihood': correlation.threat_context.get('exploitation_likelihood', 'Unknown')
            })
        
        # Sort by priority score
        priority_threats.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return priority_threats[:10]  # Top 10 priority threats
    
    def _calculate_threat_priority_score(self, correlation: ThreatCorrelation) -> float:
        """Calculate priority score for threat"""
        score = 0.0
        
        # Base score from confidence
        score += correlation.correlation_confidence * 30
        
        # Threat level weighting
        threat_level = correlation.threat_context.get('threat_level', 'Low')
        level_weights = {'Critical': 40, 'High': 25, 'Medium': 15, 'Low': 5}
        score += level_weights.get(threat_level, 5)
        
        # CVE impact
        max_cvss = max((cve.get('cvss_score', 0) for cve in correlation.correlated_cves), default=0)
        score += min(20, max_cvss * 2)
        
        # MITRE technique count
        score += min(10, len(correlation.mitre_tactics) * 2)
        
        return round(score, 1)
    
    def _assess_intelligence_freshness(self) -> Dict[str, Any]:
        """Assess freshness of threat intelligence data"""
        # Load update metadata
        try:
            if hasattr(self.storage, 'get_update_status'):
                update_status = self.storage.get_update_status()
            else:
                import os
                if os.path.exists('data/update_metadata.json'):
                    with open('data/update_metadata.json', 'r') as f:
                        update_status = json.load(f)
                else:
                    update_status = {}
            
            # Calculate freshness
            now = datetime.now()
            freshness = {}
            
            for source, data in update_status.items():
                if isinstance(data, dict) and 'last_update' in data:
                    last_update = datetime.fromisoformat(data['last_update'].replace('Z', '+00:00'))
                    hours_old = (now - last_update).total_seconds() / 3600
                    
                    if hours_old <= 6:
                        freshness[source] = 'Fresh'
                    elif hours_old <= 24:
                        freshness[source] = 'Recent'
                    elif hours_old <= 168:  # 1 week
                        freshness[source] = 'Stale'
                    else:
                        freshness[source] = 'Outdated'
                else:
                    freshness[source] = 'Unknown'
            
            return {
                'source_freshness': freshness,
                'overall_freshness': self._calculate_overall_freshness(freshness),
                'last_sync_time': update_status.get('last_sync', 'Unknown')
            }
            
        except Exception as e:
            self.logger.warning(f"Could not assess intelligence freshness: {e}")
            return {'error': 'Unable to assess freshness'}
    
    def _calculate_overall_freshness(self, freshness: Dict[str, str]) -> str:
        """Calculate overall freshness score"""
        if not freshness:
            return 'Unknown'
        
        fresh_count = sum(1 for status in freshness.values() if status == 'Fresh')
        total_count = len(freshness)
        
        if fresh_count / total_count >= 0.8:
            return 'Fresh'
        elif fresh_count / total_count >= 0.6:
            return 'Recent'
        else:
            return 'Stale'
    
    def _generate_correlation_recommendations(self, correlations: List[ThreatCorrelation]) -> List[str]:
        """Generate recommendations based on correlations"""
        recommendations = []
        
        if not correlations:
            recommendations.append("No threat correlations found. Consider expanding correlation rules.")
            return recommendations
        
        # High confidence correlations
        high_conf = [c for c in correlations if c.correlation_confidence >= 0.8]
        if high_conf:
            recommendations.append(f"Investigate {len(high_conf)} high-confidence threat correlations immediately")
        
        # Critical threats
        critical_threats = [c for c in correlations if c.threat_context.get('threat_level') == 'Critical']
        if critical_threats:
            recommendations.append(f"Address {len(critical_threats)} critical-level threats with highest priority")
        
        # CVE-related threats
        cve_correlations = [c for c in correlations if c.correlated_cves]
        if cve_correlations:
            recommendations.append("Review and patch systems for identified CVE vulnerabilities")
        
        # MITRE coverage gaps
        recommendations.append("Enhance detection capabilities for identified MITRE ATT&CK techniques")
        
        return recommendations
    
    def _load_threat_intelligence(self) -> Dict[str, Any]:
        """Load threat intelligence data"""
        try:
            if hasattr(self.storage, 'get_threat_intelligence'):
                return self.storage.get_threat_intelligence()
            
            import os
            if os.path.exists('data/threat_data.json'):
                with open('data/threat_data.json', 'r') as f:
                    return json.load(f)
            
            return {}
            
        except Exception as e:
            self.logger.warning(f"Could not load threat intelligence: {e}")
            return {}
    
    def _load_cve_database(self) -> Dict[str, Any]:
        """Load CVE database"""
        # Simplified CVE database
        return {
            "CVE-2024-3094": {
                "description": "Backdoor in XZ Utils library affecting SSH connections",
                "cvss_score": 10.0,
                "severity": "Critical",
                "published_date": "2024-03-29",
                "affected_products": ["xz", "liblzma"],
                "remediation": ["Update xz utils to patched version", "Monitor SSH connections"]
            },
            "CVE-2021-44228": {
                "description": "Log4Shell - Remote code execution in Apache Log4j",
                "cvss_score": 10.0,
                "severity": "Critical",
                "published_date": "2021-12-09",
                "affected_products": ["log4j", "java applications"],
                "remediation": ["Update Log4j to version 2.17.1+", "Disable JNDI lookups"]
            },
            "CVE-2023-34362": {
                "description": "SQL injection in MOVEit Transfer application",
                "cvss_score": 9.8,
                "severity": "Critical",
                "published_date": "2023-06-02",
                "affected_products": ["MOVEit Transfer"],
                "remediation": ["Apply security patches", "Review data access logs"]
            }
        }
    
    def _load_mitre_database(self) -> Dict[str, Any]:
        """Load MITRE ATT&CK database"""
        # Simplified MITRE database
        return {
            "T1021.004": {
                "name": "Remote Services: SSH",
                "tactic": "Lateral Movement",
                "description": "Adversaries may use SSH to log into accessible computers using credentials",
                "platforms": ["Linux", "macOS"],
                "detection": "Monitor for SSH connections and authentication logs",
                "mitigation": "Multi-factor authentication, network segmentation"
            },
            "T1078": {
                "name": "Valid Accounts",
                "tactic": "Defense Evasion",
                "description": "Adversaries may obtain and abuse credentials of existing accounts",
                "platforms": ["Windows", "Linux", "macOS"],
                "detection": "Monitor authentication logs for anomalous activity",
                "mitigation": "Privileged account management, account use policies"
            },
            "T1040": {
                "name": "Network Sniffing",
                "tactic": "Credential Access",
                "description": "Adversaries may sniff network traffic to capture information",
                "platforms": ["Linux", "Windows", "macOS"],
                "detection": "Monitor for promiscuous mode on network interfaces",
                "mitigation": "Encrypt network communications"
            },
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": "Adversaries may attempt to exploit weaknesses in public-facing applications",
                "platforms": ["Windows", "Linux", "macOS"],
                "detection": "Monitor application logs for exploitation attempts",
                "mitigation": "Application isolation, privileged account management"
            }
        }
    
    def _serialize_correlation(self, correlation: ThreatCorrelation) -> Dict[str, Any]:
        """Serialize correlation object for JSON output"""
        return {
            'risk_id': correlation.risk_id,
            'risk_title': correlation.risk_title,
            'correlated_cves': correlation.correlated_cves,
            'mitre_tactics': correlation.mitre_tactics,
            'correlation_confidence': correlation.correlation_confidence,
            'threat_context': correlation.threat_context
        }
    
    def _map_risk_to_mitre(self, risk: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map individual risk to MITRE techniques"""
        description = risk.get('description', '').lower()
        techniques = []
        
        # Simple mapping based on keywords
        if 'ssh' in description or 'port 22' in description:
            techniques.append(self.mitre_database.get('T1021.004', {}))
        
        if 'authentication' in description or 'access' in description:
            techniques.append(self.mitre_database.get('T1078', {}))
        
        if 'network' in description or 'sniff' in description:
            techniques.append(self.mitre_database.get('T1040', {}))
        
        if 'exploit' in description or 'vulnerability' in description:
            techniques.append(self.mitre_database.get('T1190', {}))
        
        return [t for t in techniques if t]  # Filter out empty techniques
    
    def _find_related_mitre_techniques(self, cve_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find MITRE techniques related to a CVE"""
        description = cve_data.get('description', '').lower()
        related_techniques = []
        
        # Map CVE to MITRE techniques based on description
        if 'remote' in description and 'execution' in description:
            related_techniques.append(self.mitre_database.get('T1190', {}))
        
        if 'ssh' in description:
            related_techniques.append(self.mitre_database.get('T1021.004', {}))
        
        return [t for t in related_techniques if t]
    
    def _assess_cve_threat_level(self, cve_data: Dict[str, Any]) -> str:
        """Assess threat level for a CVE"""
        cvss_score = cve_data.get('cvss_score', 0)
        
        if cvss_score >= 9.0:
            return 'Critical'
        elif cvss_score >= 7.0:
            return 'High'
        elif cvss_score >= 4.0:
            return 'Medium'
        else:
            return 'Low'
    
    def _find_exploitation_indicators(self, cve_id: str) -> List[str]:
        """Find indicators of exploitation for CVE"""
        # This would query threat intel feeds for exploitation indicators
        # For now, return static indicators for known CVEs
        indicators = {
            'CVE-2024-3094': ['Suspicious SSH activity', 'Unexpected process execution'],
            'CVE-2021-44228': ['JNDI lookup attempts', 'Log4j error messages'],
            'CVE-2023-34362': ['SQL injection patterns', 'Unusual database queries']
        }
        
        return indicators.get(cve_id, [])
    
    def _identify_high_risk_techniques(self, technique_coverage: Dict[str, List]) -> List[Dict[str, Any]]:
        """Identify high-risk MITRE techniques from coverage"""
        high_risk = []
        
        for technique_id, risks in technique_coverage.items():
            if technique_id in self.mitre_database:
                technique_data = self.mitre_database[technique_id]
                
                # Consider it high-risk if multiple risks map to it
                if len(risks) >= 2:
                    high_risk.append({
                        'technique_id': technique_id,
                        'name': technique_data.get('name', ''),
                        'risk_count': len(risks),
                        'tactic': technique_data.get('tactic', ''),
                        'severity_breakdown': self._analyze_technique_severity(risks)
                    })
        
        return high_risk
    
    def _analyze_technique_severity(self, risks: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze severity breakdown for technique risks"""
        severity_count = defaultdict(int)
        for risk in risks:
            severity = risk.get('severity', 'Medium')
            severity_count[severity] += 1
        return dict(severity_count)
    
    def _recommend_detection_gaps(self, uncovered_techniques: List[str]) -> List[str]:
        """Recommend detections for uncovered techniques"""
        recommendations = []
        
        # Sample recommendations for common techniques
        detection_recommendations = {
            'T1059': 'Implement command-line logging and analysis',
            'T1055': 'Monitor for process injection techniques',
            'T1003': 'Monitor credential dumping activities'
        }
        
        for technique in uncovered_techniques[:5]:  # Top 5
            if technique in detection_recommendations:
                recommendations.append(f"{technique}: {detection_recommendations[technique]}")
        
        return recommendations


# Global threat correlation engine
def get_threat_correlation_engine(storage_backend):
    """Get threat correlation engine instance"""
    return ThreatCorrelationEngine(storage_backend)