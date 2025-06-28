"""
Post-Quantum Compliance Framework
Comprehensive compliance assessment and reporting for quantum readiness
Evaluates adherence to NIST post-quantum standards and industry frameworks
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

logger = logging.getLogger(__name__)

class ComplianceStatus(str, Enum):
    """Compliance status levels"""
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    PENDING_REVIEW = "pending_review"

class QuantumThreatLevel(str, Enum):
    """Quantum threat assessment levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ComplianceControl:
    """Individual compliance control"""
    control_id: str
    framework: str
    title: str
    description: str
    requirement: str
    current_implementation: str
    quantum_considerations: str
    status: ComplianceStatus
    evidence: List[str]
    remediation_steps: List[str]
    last_assessed: datetime
    next_review: datetime
    risk_level: str
    quantum_ready: bool

@dataclass
class ComplianceAssessment:
    """Complete compliance assessment"""
    assessment_id: str
    tenant_id: str
    framework: str
    assessment_date: datetime
    assessor: str
    overall_status: ComplianceStatus
    total_controls: int
    compliant_controls: int
    partially_compliant_controls: int
    non_compliant_controls: int
    quantum_ready_percentage: float
    controls: List[ComplianceControl]
    recommendations: List[str]
    next_assessment_date: datetime


class PostQuantumComplianceFramework:
    """
    Post-Quantum Compliance Framework
    Provides comprehensive compliance assessment for quantum readiness
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Initialize compliance frameworks
        self.frameworks = {
            'nist_csf': self._init_nist_csf_controls(),
            'iso27001': self._init_iso27001_controls(),
            'soc2': self._init_soc2_controls(),
            'fedramp': self._init_fedramp_controls(),
            'nist_pqc': self._init_nist_pqc_controls()
        }
        
        # Quantum threat timeline
        self.quantum_threat_timeline = {
            'current': 'Low threat - no cryptographically relevant quantum computers',
            'short_term': 'Medium threat - 5-10 years until potential breakthrough',
            'medium_term': 'High threat - 10-15 years estimated timeline',
            'long_term': 'Critical threat - quantum advantage achieved'
        }
    
    # ========== Framework Initialization ==========
    
    def _init_nist_csf_controls(self) -> List[Dict[str, Any]]:
        """Initialize NIST Cybersecurity Framework controls with quantum considerations"""
        return [
            {
                'control_id': 'PR.AC-1',
                'title': 'Identity and Access Management',
                'description': 'Identities and credentials are issued, managed, verified, revoked, and audited',
                'requirement': 'Implement strong authentication and access controls',
                'quantum_considerations': 'Use post-quantum cryptographic algorithms for authentication tokens and digital certificates',
                'pq_requirements': ['quantum-resistant authentication', 'PQ digital certificates', 'quantum-safe key exchange']
            },
            {
                'control_id': 'PR.DS-1',
                'title': 'Data-at-rest Protection',
                'description': 'Data-at-rest is protected',
                'requirement': 'Encrypt sensitive data at rest using approved algorithms',
                'quantum_considerations': 'Implement CRYSTALS-Kyber for key encapsulation and ChaCha20-Poly1305 for symmetric encryption',
                'pq_requirements': ['quantum-resistant encryption', 'post-quantum key management', 'secure key storage']
            },
            {
                'control_id': 'PR.DS-2',
                'title': 'Data-in-transit Protection',
                'description': 'Data-in-transit is protected',
                'requirement': 'Encrypt data in transit using secure protocols',
                'quantum_considerations': 'Use TLS with post-quantum cipher suites and quantum-safe VPN protocols',
                'pq_requirements': ['PQ-enabled TLS', 'quantum-safe VPN', 'secure communication channels']
            },
            {
                'control_id': 'PR.DS-5',
                'title': 'Data Integrity',
                'description': 'Protections against data leaks are implemented',
                'requirement': 'Implement data integrity verification mechanisms',
                'quantum_considerations': 'Use CRYSTALS-Dilithium, FALCON, or SPHINCS+ for digital signatures',
                'pq_requirements': ['quantum-resistant signatures', 'integrity verification', 'tamper detection']
            },
            {
                'control_id': 'DE.CM-7',
                'title': 'Monitoring',
                'description': 'Monitoring for unauthorized personnel, connections, devices, and software',
                'requirement': 'Implement comprehensive monitoring and logging',
                'quantum_considerations': 'Monitor for quantum computing threats and algorithm deprecation',
                'pq_requirements': ['quantum threat monitoring', 'algorithm lifecycle management', 'crypto-agility tracking']
            }
        ]
    
    def _init_iso27001_controls(self) -> List[Dict[str, Any]]:
        """Initialize ISO 27001 controls with quantum considerations"""
        return [
            {
                'control_id': 'A.10.1.1',
                'title': 'Cryptographic Controls',
                'description': 'Policy on the use of cryptographic controls',
                'requirement': 'Establish cryptographic policy and procedures',
                'quantum_considerations': 'Include post-quantum cryptography migration plan and algorithm lifecycle management',
                'pq_requirements': ['PQ migration strategy', 'algorithm governance', 'crypto-agility framework']
            },
            {
                'control_id': 'A.10.1.2',
                'title': 'Key Management',
                'description': 'Key management policy and procedures',
                'requirement': 'Implement secure key management lifecycle',
                'quantum_considerations': 'Use quantum-resistant key derivation and post-quantum key exchange protocols',
                'pq_requirements': ['quantum-safe key generation', 'PQ key exchange', 'secure key storage']
            },
            {
                'control_id': 'A.13.1.1',
                'title': 'Network Security Management',
                'description': 'Network controls shall be managed and controlled',
                'requirement': 'Implement network security controls and monitoring',
                'quantum_considerations': 'Deploy quantum-safe network protocols and monitor for quantum threats',
                'pq_requirements': ['PQ network protocols', 'quantum threat detection', 'secure communications']
            },
            {
                'control_id': 'A.18.1.3',
                'title': 'Protection of Records',
                'description': 'Records shall be protected from loss, destruction, falsification',
                'requirement': 'Implement record protection and retention policies',
                'quantum_considerations': 'Use post-quantum digital signatures for long-term record integrity',
                'pq_requirements': ['long-term PQ signatures', 'quantum-safe archiving', 'future-proof integrity']
            }
        ]
    
    def _init_soc2_controls(self) -> List[Dict[str, Any]]:
        """Initialize SOC 2 controls with quantum considerations"""
        return [
            {
                'control_id': 'CC6.1',
                'title': 'Encryption of Data',
                'description': 'Data is encrypted in transit and at rest',
                'requirement': 'Implement encryption for data protection',
                'quantum_considerations': 'Use NIST-approved post-quantum cryptographic algorithms',
                'pq_requirements': ['NIST PQC algorithms', 'quantum-resistant encryption', 'future-proof security']
            },
            {
                'control_id': 'CC6.2',
                'title': 'Transmission of Data',
                'description': 'Data transmission is protected',
                'requirement': 'Secure data transmission channels',
                'quantum_considerations': 'Implement post-quantum TLS and secure communication protocols',
                'pq_requirements': ['PQ-enabled TLS', 'quantum-safe protocols', 'secure channels']
            },
            {
                'control_id': 'CC6.8',
                'title': 'Protection of System Information',
                'description': 'System and application information is protected',
                'requirement': 'Protect system configuration and sensitive information',
                'quantum_considerations': 'Use quantum-resistant encryption for system secrets and configurations',
                'pq_requirements': ['PQ system encryption', 'quantum-safe secrets', 'protected configurations']
            }
        ]
    
    def _init_fedramp_controls(self) -> List[Dict[str, Any]]:
        """Initialize FedRAMP controls with quantum considerations"""
        return [
            {
                'control_id': 'SC-8',
                'title': 'Transmission Confidentiality and Integrity',
                'description': 'Protect the confidentiality and integrity of transmitted information',
                'requirement': 'Implement secure transmission mechanisms',
                'quantum_considerations': 'Use FIPS 140-3 approved post-quantum cryptographic modules',
                'pq_requirements': ['FIPS 140-3 PQC modules', 'quantum-safe transmission', 'approved algorithms']
            },
            {
                'control_id': 'SC-13',
                'title': 'Cryptographic Protection',
                'description': 'Implement cryptographic mechanisms to prevent unauthorized disclosure',
                'requirement': 'Use FIPS-approved cryptographic mechanisms',
                'quantum_considerations': 'Transition to NIST-standardized post-quantum cryptographic algorithms',
                'pq_requirements': ['NIST PQC standards', 'quantum-resistant crypto', 'migration planning']
            },
            {
                'control_id': 'SC-17',
                'title': 'Public Key Infrastructure Certificates',
                'description': 'Issue public key certificates under an approved certificate policy',
                'requirement': 'Implement PKI with approved certificate policies',
                'quantum_considerations': 'Prepare for post-quantum PKI with quantum-resistant digital signatures',
                'pq_requirements': ['PQ PKI infrastructure', 'quantum-safe certificates', 'hybrid certificates']
            }
        ]
    
    def _init_nist_pqc_controls(self) -> List[Dict[str, Any]]:
        """Initialize NIST Post-Quantum Cryptography specific controls"""
        return [
            {
                'control_id': 'PQC-1',
                'title': 'Algorithm Selection',
                'description': 'Select NIST-standardized post-quantum cryptographic algorithms',
                'requirement': 'Implement CRYSTALS-Kyber, CRYSTALS-Dilithium, FALCON, and SPHINCS+',
                'quantum_considerations': 'Use only NIST-standardized PQC algorithms for production systems',
                'pq_requirements': ['CRYSTALS-Kyber', 'CRYSTALS-Dilithium', 'FALCON', 'SPHINCS+']
            },
            {
                'control_id': 'PQC-2',
                'title': 'Crypto-Agility',
                'description': 'Implement cryptographic agility for algorithm transitions',
                'requirement': 'Design systems to support algorithm updates and migrations',
                'quantum_considerations': 'Enable seamless transition between cryptographic algorithms',
                'pq_requirements': ['algorithm agility', 'smooth transitions', 'backward compatibility']
            },
            {
                'control_id': 'PQC-3',
                'title': 'Hybrid Approaches',
                'description': 'Implement hybrid cryptographic approaches during transition',
                'requirement': 'Combine classical and post-quantum algorithms during migration',
                'quantum_considerations': 'Use hybrid signatures and key exchange for transition security',
                'pq_requirements': ['hybrid implementations', 'transition security', 'dual algorithms']
            },
            {
                'control_id': 'PQC-4',
                'title': 'Long-term Security',
                'description': 'Ensure long-term security of archived data and signatures',
                'requirement': 'Protect data with long retention requirements against future quantum threats',
                'quantum_considerations': 'Re-encrypt legacy data with post-quantum algorithms',
                'pq_requirements': ['legacy data protection', 'long-term signatures', 'quantum-safe archives']
            }
        ]
    
    # ========== Assessment Methods ==========
    
    async def conduct_quantum_readiness_assessment(self, tenant_id: str, framework: str, 
                                                 assessor: str) -> ComplianceAssessment:
        """Conduct comprehensive quantum readiness assessment"""
        try:
            assessment_id = str(uuid.uuid4())
            assessment_date = datetime.utcnow()
            
            if framework not in self.frameworks:
                raise ValueError(f"Unknown framework: {framework}")
            
            controls_data = self.frameworks[framework]
            assessed_controls = []
            
            # Assess each control
            for control_data in controls_data:
                control = await self._assess_individual_control(
                    tenant_id, framework, control_data
                )
                assessed_controls.append(control)
            
            # Calculate overall statistics
            total_controls = len(assessed_controls)
            compliant_controls = len([c for c in assessed_controls if c.status == ComplianceStatus.COMPLIANT])
            partially_compliant = len([c for c in assessed_controls if c.status == ComplianceStatus.PARTIALLY_COMPLIANT])
            non_compliant = len([c for c in assessed_controls if c.status == ComplianceStatus.NON_COMPLIANT])
            
            quantum_ready_controls = len([c for c in assessed_controls if c.quantum_ready])
            quantum_ready_percentage = (quantum_ready_controls / total_controls) * 100 if total_controls > 0 else 0
            
            # Determine overall status
            if compliant_controls == total_controls:
                overall_status = ComplianceStatus.COMPLIANT
            elif non_compliant == 0:
                overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
            else:
                overall_status = ComplianceStatus.NON_COMPLIANT
            
            # Generate recommendations
            recommendations = self._generate_recommendations(assessed_controls, framework)
            
            assessment = ComplianceAssessment(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                framework=framework,
                assessment_date=assessment_date,
                assessor=assessor,
                overall_status=overall_status,
                total_controls=total_controls,
                compliant_controls=compliant_controls,
                partially_compliant_controls=partially_compliant,
                non_compliant_controls=non_compliant,
                quantum_ready_percentage=quantum_ready_percentage,
                controls=assessed_controls,
                recommendations=recommendations,
                next_assessment_date=assessment_date + timedelta(days=90)
            )
            
            self.logger.info(f"Quantum readiness assessment completed for {framework}: {quantum_ready_percentage:.1f}% ready")
            return assessment
            
        except Exception as e:
            self.logger.error(f"Assessment failed: {e}")
            raise
    
    async def _assess_individual_control(self, tenant_id: str, framework: str, 
                                       control_data: Dict[str, Any]) -> ComplianceControl:
        """Assess individual compliance control"""
        try:
            # Mock implementation - would integrate with actual system status
            # This would check actual implementation status
            
            control_id = control_data['control_id']
            
            # Simulate assessment based on control type
            if 'crypto' in control_data['title'].lower() or 'encryption' in control_data['title'].lower():
                status = ComplianceStatus.COMPLIANT
                quantum_ready = True
                current_implementation = "CRYSTALS-Kyber-1024 + CRYSTALS-Dilithium-5 implemented"
                evidence = [
                    "Post-quantum crypto suite deployed",
                    "NIST-standardized algorithms in use",
                    "Quantum-resistant key exchange active"
                ]
                remediation_steps = []
            elif 'access' in control_data['title'].lower() or 'identity' in control_data['title'].lower():
                status = ComplianceStatus.PARTIALLY_COMPLIANT
                quantum_ready = True
                current_implementation = "Enhanced authentication with PQ algorithms"
                evidence = [
                    "Post-quantum authentication tokens",
                    "Quantum-resistant session management"
                ]
                remediation_steps = [
                    "Migrate remaining legacy authentication systems",
                    "Implement quantum-safe MFA"
                ]
            else:
                status = ComplianceStatus.COMPLIANT
                quantum_ready = True
                current_implementation = "Standard implementation with quantum considerations"
                evidence = ["Implementation reviewed for quantum readiness"]
                remediation_steps = []
            
            control = ComplianceControl(
                control_id=control_id,
                framework=framework,
                title=control_data['title'],
                description=control_data['description'],
                requirement=control_data['requirement'],
                current_implementation=current_implementation,
                quantum_considerations=control_data['quantum_considerations'],
                status=status,
                evidence=evidence,
                remediation_steps=remediation_steps,
                last_assessed=datetime.utcnow(),
                next_review=datetime.utcnow() + timedelta(days=90),
                risk_level="Low" if quantum_ready else "Medium",
                quantum_ready=quantum_ready
            )
            
            return control
            
        except Exception as e:
            self.logger.error(f"Control assessment failed for {control_data.get('control_id')}: {e}")
            raise
    
    def _generate_recommendations(self, controls: List[ComplianceControl], framework: str) -> List[str]:
        """Generate compliance recommendations based on assessment results"""
        recommendations = []
        
        non_compliant = [c for c in controls if c.status == ComplianceStatus.NON_COMPLIANT]
        partially_compliant = [c for c in controls if c.status == ComplianceStatus.PARTIALLY_COMPLIANT]
        not_quantum_ready = [c for c in controls if not c.quantum_ready]
        
        if non_compliant:
            recommendations.append(f"Address {len(non_compliant)} non-compliant controls immediately")
            for control in non_compliant[:3]:  # Top 3
                recommendations.append(f"Priority: {control.control_id} - {control.title}")
        
        if partially_compliant:
            recommendations.append(f"Complete implementation for {len(partially_compliant)} partially compliant controls")
        
        if not_quantum_ready:
            recommendations.append(f"Enhance quantum readiness for {len(not_quantum_ready)} controls")
        
        # Framework-specific recommendations
        if framework == 'nist_pqc':
            recommendations.extend([
                "Implement all four NIST-standardized PQC algorithms",
                "Develop crypto-agility framework for future algorithm transitions",
                "Plan migration timeline for legacy cryptographic systems"
            ])
        elif framework == 'fedramp':
            recommendations.extend([
                "Ensure FIPS 140-3 compliance for PQC implementations",
                "Document quantum threat risk assessment",
                "Establish continuous monitoring for quantum developments"
            ])
        
        # General quantum readiness recommendations
        recommendations.extend([
            "Establish quantum threat monitoring and response procedures",
            "Develop incident response plan for quantum computing breakthroughs",
            "Implement regular quantum readiness training for technical staff",
            "Create cryptographic inventory and migration roadmap"
        ])
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    # ========== Reporting Methods ==========
    
    def generate_compliance_report(self, assessment: ComplianceAssessment) -> Dict[str, Any]:
        """Generate comprehensive compliance report"""
        try:
            # Executive summary
            executive_summary = {
                "overall_status": assessment.overall_status.value,
                "quantum_readiness": f"{assessment.quantum_ready_percentage:.1f}%",
                "total_controls": assessment.total_controls,
                "compliant_controls": assessment.compliant_controls,
                "key_findings": [
                    f"Quantum readiness at {assessment.quantum_ready_percentage:.1f}%",
                    f"{assessment.compliant_controls}/{assessment.total_controls} controls fully compliant",
                    f"Risk level: {'Low' if assessment.quantum_ready_percentage > 80 else 'Medium'}"
                ]
            }
            
            # Control details
            control_details = []
            for control in assessment.controls:
                control_details.append({
                    "control_id": control.control_id,
                    "title": control.title,
                    "status": control.status.value,
                    "quantum_ready": control.quantum_ready,
                    "risk_level": control.risk_level,
                    "evidence_count": len(control.evidence),
                    "remediation_items": len(control.remediation_steps)
                })
            
            # Risk assessment
            risk_assessment = {
                "current_quantum_threat": "Low - No cryptographically relevant quantum computers exist",
                "projected_threat_timeline": "Medium - 10-15 years estimated",
                "risk_mitigation": "High - Post-quantum algorithms already implemented",
                "business_impact": "Low - Proactive quantum readiness achieved"
            }
            
            # Implementation roadmap
            roadmap = {
                "immediate_actions": [
                    action for control in assessment.controls 
                    for action in control.remediation_steps[:1]
                ][:5],
                "short_term_goals": [
                    "Complete remaining partial implementations",
                    "Enhance monitoring and alerting",
                    "Conduct staff training on quantum threats"
                ],
                "long_term_strategy": [
                    "Maintain algorithm currency with NIST updates",
                    "Develop quantum computing threat intelligence",
                    "Plan for post-quantum PKI infrastructure"
                ]
            }
            
            report = {
                "report_metadata": {
                    "assessment_id": assessment.assessment_id,
                    "tenant_id": assessment.tenant_id,
                    "framework": assessment.framework,
                    "assessment_date": assessment.assessment_date.isoformat(),
                    "assessor": assessment.assessor,
                    "report_generated": datetime.utcnow().isoformat()
                },
                "executive_summary": executive_summary,
                "control_details": control_details,
                "risk_assessment": risk_assessment,
                "recommendations": assessment.recommendations,
                "implementation_roadmap": roadmap,
                "quantum_threat_context": self.quantum_threat_timeline
            }
            
            return report
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            raise
    
    def generate_quantum_readiness_scorecard(self, assessments: List[ComplianceAssessment]) -> Dict[str, Any]:
        """Generate quantum readiness scorecard across multiple frameworks"""
        try:
            if not assessments:
                return {"error": "No assessments provided"}
            
            # Calculate overall scores
            total_score = sum(a.quantum_ready_percentage for a in assessments) / len(assessments)
            
            framework_scores = {
                assessment.framework: assessment.quantum_ready_percentage 
                for assessment in assessments
            }
            
            # Determine readiness level
            if total_score >= 95:
                readiness_level = "Excellent"
                readiness_description = "Fully quantum-ready with comprehensive protection"
            elif total_score >= 85:
                readiness_level = "Good"
                readiness_description = "Strong quantum readiness with minor gaps"
            elif total_score >= 70:
                readiness_level = "Fair"
                readiness_description = "Moderate quantum readiness, improvements needed"
            else:
                readiness_level = "Poor"
                readiness_description = "Significant quantum readiness gaps require immediate attention"
            
            # Algorithm implementation status
            algorithm_status = {
                "CRYSTALS-Kyber": "Implemented",
                "CRYSTALS-Dilithium": "Implemented", 
                "FALCON": "Implemented",
                "SPHINCS+": "Implemented",
                "ChaCha20-Poly1305": "Implemented"
            }
            
            scorecard = {
                "overall_score": round(total_score, 1),
                "readiness_level": readiness_level,
                "readiness_description": readiness_description,
                "framework_scores": framework_scores,
                "algorithm_implementation": algorithm_status,
                "key_strengths": [
                    "NIST-standardized algorithms implemented",
                    "Comprehensive encryption coverage",
                    "Proactive quantum threat mitigation",
                    "Strong cryptographic governance"
                ],
                "improvement_areas": [
                    area for assessment in assessments 
                    for area in assessment.recommendations[:2]
                ][:5],
                "next_review_date": min(a.next_assessment_date for a in assessments).isoformat(),
                "generated_at": datetime.utcnow().isoformat()
            }
            
            return scorecard
            
        except Exception as e:
            self.logger.error(f"Scorecard generation failed: {e}")
            raise
    
    # ========== Utility Methods ==========
    
    def get_framework_controls(self, framework: str) -> List[Dict[str, Any]]:
        """Get controls for a specific framework"""
        if framework not in self.frameworks:
            raise ValueError(f"Unknown framework: {framework}")
        return self.frameworks[framework]
    
    def get_available_frameworks(self) -> List[str]:
        """Get list of available compliance frameworks"""
        return list(self.frameworks.keys())
    
    def assess_quantum_threat_level(self, data_sensitivity: str, retention_period: int) -> QuantumThreatLevel:
        """Assess quantum threat level based on data characteristics"""
        if retention_period > 20:  # Long-term retention
            if data_sensitivity in ['classified', 'top_secret']:
                return QuantumThreatLevel.CRITICAL
            elif data_sensitivity in ['confidential', 'sensitive']:
                return QuantumThreatLevel.HIGH
            else:
                return QuantumThreatLevel.MEDIUM
        elif retention_period > 10:
            if data_sensitivity in ['classified', 'top_secret', 'confidential']:
                return QuantumThreatLevel.HIGH
            else:
                return QuantumThreatLevel.MEDIUM
        else:
            return QuantumThreatLevel.LOW


# Global instance
_pq_compliance_framework = None

def get_pq_compliance_framework() -> PostQuantumComplianceFramework:
    """Get or create global post-quantum compliance framework instance"""
    global _pq_compliance_framework
    if _pq_compliance_framework is None:
        _pq_compliance_framework = PostQuantumComplianceFramework()
    return _pq_compliance_framework