"""
Unified AI Analytics Manager
Orchestrates threat intelligence, vector search, and LLM-powered security analysis
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from .engines.cloud_scanner import CloudScanner
from .engines.threat_intelligence import ThreatIntelligenceManager
from .engines.threat_correlation_engine import ThreatCorrelationEngine
from .engines.behavioral_pattern_analyzer import BehavioralPatternAnalyzer, SecurityEvent
from .engines.gpu_llm_integration import GPULLMIntegration, SecurityContext
from .engines.compliance_matrix_engine import ComplianceMatrixEngine
from .advanced_analytics import AdvancedAnalytics
from .performance_optimizer import PipelineOptimizer, get_performance_optimizer, cached, monitored
from .vector.weaviate_vector_store import WeaviateVectorStore

logger = logging.getLogger(__name__)

@dataclass
class AnalysisResult:
    """Result of AI-powered security analysis"""
    scan_id: str
    timestamp: str
    overall_score: int
    threat_intelligence: Dict[str, Any]
    correlations: List[Dict[str, Any]]
    recommendations: List[str]
    risk_assessment: Dict[str, Any]

class AIAnalyticsManager:
    """
    Unified manager for AI-powered security analytics
    Coordinates cloud scanning, threat intelligence, and vector-based correlation
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.cloud_scanner = CloudScanner()
        self.vector_store = WeaviateVectorStore()
        self.threat_intel = None
        self.correlation_engine = None
        self.behavioral_analyzer = None
        self.llm_integration = None
        self.compliance_engine = None
        self.advanced_analytics = None
        self.performance_optimizer = None
        self._initialized = False
        
    async def initialize(self):
        """Initialize all AI analytics components"""
        try:
            logger.info("Initializing AI Analytics Manager...")
            
            # Initialize performance optimizer first
            self.performance_optimizer = get_performance_optimizer(self.config.get("performance", {}))
            await self.performance_optimizer.initialize()
            
            # Initialize threat intelligence with vector store
            self.threat_intel = ThreatIntelligenceManager(self.vector_store)
            await self.threat_intel.initialize_threat_databases()
            
            # Initialize correlation engine
            self.correlation_engine = ThreatCorrelationEngine(
                self.vector_store, 
                self.threat_intel
            )
            
            # Initialize behavioral pattern analyzer
            self.behavioral_analyzer = BehavioralPatternAnalyzer(self.config)
            await self.behavioral_analyzer.initialize()
            
            # Initialize GPU-accelerated LLM integration with vector store
            self.llm_integration = GPULLMIntegration(self.config)
            await self.llm_integration.initialize(vector_store=self.vector_store)
            
            # Initialize compliance matrix engine
            self.compliance_engine = ComplianceMatrixEngine(self.config)
            await self.compliance_engine.initialize()
            
            # Initialize advanced analytics
            self.advanced_analytics = AdvancedAnalytics(self.config)
            await self.advanced_analytics.initialize()
            
            self._initialized = True
            logger.info("AI Analytics Manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize AI Analytics Manager: {e}")
            raise
    
    async def perform_comprehensive_analysis(
        self, 
        tenant_id: str,
        scan_targets: List[str],
        scan_options: Dict[str, bool]
    ) -> AnalysisResult:
        """
        Perform comprehensive AI-powered security analysis
        
        Args:
            tenant_id: Unique tenant identifier
            scan_targets: Cloud providers/services to scan
            scan_options: Scanning configuration options
            
        Returns:
            AnalysisResult with complete analysis
        """
        if not self._initialized:
            await self.initialize()
            
        scan_id = f"scan_{tenant_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        logger.info(f"Starting comprehensive analysis: {scan_id}")
        
        try:
            # Step 1: Cloud Security Scanning
            cloud_results = await self._perform_cloud_scanning(
                scan_targets, scan_options
            )
            
            # Step 2: Threat Intelligence Enrichment
            threat_data = await self._enrich_with_threat_intelligence(
                cloud_results
            )
            
            # Step 3: AI-Powered Correlation Analysis
            correlations = await self._perform_correlation_analysis(
                cloud_results, threat_data
            )
            
            # Step 4: Store Results in Vector Database
            await self._store_analysis_results(
                tenant_id, scan_id, cloud_results, threat_data, correlations
            )
            
            # Step 5: Generate Risk Assessment and Recommendations
            risk_assessment = await self._generate_risk_assessment(
                cloud_results, threat_data, correlations
            )
            
            recommendations = await self._generate_recommendations(
                cloud_results, threat_data, correlations, risk_assessment
            )
            
            # Calculate overall security score
            overall_score = self._calculate_overall_score(
                cloud_results, threat_data, risk_assessment
            )
            
            result = AnalysisResult(
                scan_id=scan_id,
                timestamp=datetime.now().isoformat(),
                overall_score=overall_score,
                threat_intelligence=threat_data,
                correlations=correlations,
                recommendations=recommendations,
                risk_assessment=risk_assessment
            )
            
            logger.info(f"Comprehensive analysis completed: {scan_id}")
            return result
            
        except Exception as e:
            logger.error(f"Analysis failed for {scan_id}: {e}")
            raise
    
    async def _perform_cloud_scanning(
        self, 
        scan_targets: List[str], 
        scan_options: Dict[str, bool]
    ) -> Dict[str, Any]:
        """Perform cloud security scanning across multiple providers"""
        results = {}
        
        for provider in scan_targets:
            try:
                provider_results = self.cloud_scanner.scan_provider(
                    provider, scan_options
                )
                results[provider] = provider_results
                logger.info(f"Cloud scan completed for {provider}")
                
            except Exception as e:
                logger.error(f"Cloud scan failed for {provider}: {e}")
                results[provider] = {"error": str(e), "risks": []}
        
        return results
    
    async def _enrich_with_threat_intelligence(
        self, 
        cloud_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enrich scan results with threat intelligence data"""
        try:
            threat_data = {
                "current_threats": await self.threat_intel.get_current_threats(),
                "vulnerability_matches": [],
                "attack_patterns": [],
                "iocs": []  # Indicators of Compromise
            }
            
            # Match scan results against threat intelligence
            for provider, provider_results in cloud_results.items():
                if "risks" in provider_results:
                    for risk in provider_results["risks"]:
                        # Find related threats for each risk
                        related_threats = await self.threat_intel.find_related_threats(
                            risk.get("title", ""),
                            risk.get("category", "")
                        )
                        
                        if related_threats:
                            threat_data["vulnerability_matches"].extend(related_threats)
            
            return threat_data
            
        except Exception as e:
            logger.error(f"Threat intelligence enrichment failed: {e}")
            return {"error": str(e)}
    
    async def _perform_correlation_analysis(
        self, 
        cloud_results: Dict[str, Any], 
        threat_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Perform AI-powered correlation analysis"""
        try:
            correlations = await self.correlation_engine.analyze_correlations(
                cloud_results, threat_data
            )
            
            # Add semantic similarity analysis using vector store
            semantic_correlations = await self._find_semantic_correlations(
                cloud_results
            )
            
            correlations.extend(semantic_correlations)
            return correlations
            
        except Exception as e:
            logger.error(f"Correlation analysis failed: {e}")
            return []
    
    async def _find_semantic_correlations(
        self, 
        cloud_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find semantic correlations using vector similarity"""
        correlations = []
        
        try:
            # Extract all risk descriptions for vector analysis
            risk_texts = []
            for provider, results in cloud_results.items():
                for risk in results.get("risks", []):
                    risk_texts.append({
                        "text": risk.get("description", ""),
                        "provider": provider,
                        "title": risk.get("title", ""),
                        "severity": risk.get("severity", "")
                    })
            
            # Find similar risks across providers using vector similarity
            for i, risk_a in enumerate(risk_texts):
                for j, risk_b in enumerate(risk_texts[i+1:], i+1):
                    if risk_a["provider"] != risk_b["provider"]:
                        similarity = await self.vector_store.calculate_similarity(
                            risk_a["text"], risk_b["text"]
                        )
                        
                        if similarity > 0.8:  # High similarity threshold
                            correlations.append({
                                "type": "semantic_similarity",
                                "similarity_score": similarity,
                                "risk_a": risk_a,
                                "risk_b": risk_b,
                                "insight": "Similar security issues detected across multiple cloud providers"
                            })
            
            return correlations
            
        except Exception as e:
            logger.error(f"Semantic correlation analysis failed: {e}")
            return []
    
    async def _store_analysis_results(
        self, 
        tenant_id: str,
        scan_id: str,
        cloud_results: Dict[str, Any],
        threat_data: Dict[str, Any],
        correlations: List[Dict[str, Any]]
    ):
        """Store analysis results in vector database"""
        try:
            analysis_document = {
                "tenant_id": tenant_id,
                "scan_id": scan_id,
                "timestamp": datetime.now().isoformat(),
                "cloud_results": cloud_results,
                "threat_intelligence": threat_data,
                "correlations": correlations
            }
            
            await self.vector_store.store_security_scan(analysis_document)
            logger.info(f"Analysis results stored for scan: {scan_id}")
            
        except Exception as e:
            logger.error(f"Failed to store analysis results: {e}")
    
    async def _generate_risk_assessment(
        self, 
        cloud_results: Dict[str, Any],
        threat_data: Dict[str, Any],
        correlations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate comprehensive risk assessment"""
        try:
            # Count risks by severity across all providers
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            total_risks = 0
            
            for provider, results in cloud_results.items():
                for risk in results.get("risks", []):
                    severity = risk.get("severity", "Medium")
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                    total_risks += 1
            
            # Calculate risk score based on severity weights
            risk_score = (
                severity_counts["Critical"] * 10 +
                severity_counts["High"] * 7 +
                severity_counts["Medium"] * 4 +
                severity_counts["Low"] * 1
            )
            
            # Factor in threat intelligence
            threat_factor = len(threat_data.get("vulnerability_matches", [])) * 0.1
            
            # Factor in correlations (multiple related issues increase risk)
            correlation_factor = len(correlations) * 0.05
            
            final_risk_score = min(100, risk_score + threat_factor + correlation_factor)
            
            return {
                "total_risks": total_risks,
                "severity_breakdown": severity_counts,
                "raw_risk_score": risk_score,
                "threat_factor": threat_factor,
                "correlation_factor": correlation_factor,
                "final_risk_score": final_risk_score,
                "risk_level": self._get_risk_level(final_risk_score)
            }
            
        except Exception as e:
            logger.error(f"Risk assessment generation failed: {e}")
            return {"error": str(e)}
    
    async def _generate_recommendations(
        self, 
        cloud_results: Dict[str, Any],
        threat_data: Dict[str, Any],
        correlations: List[Dict[str, Any]],
        risk_assessment: Dict[str, Any]
    ) -> List[str]:
        """Generate AI-powered security recommendations"""
        recommendations = []
        
        try:
            # Priority recommendations based on critical/high severity issues
            critical_issues = []
            for provider, results in cloud_results.items():
                for risk in results.get("risks", []):
                    if risk.get("severity") in ["Critical", "High"]:
                        critical_issues.append(risk)
            
            if critical_issues:
                recommendations.append(
                    f"URGENT: Address {len(critical_issues)} critical/high severity security issues immediately"
                )
            
            # Recommendations based on correlations
            if correlations:
                recommendations.append(
                    f"Review {len(correlations)} correlated security patterns that may indicate systemic vulnerabilities"
                )
            
            # Threat intelligence recommendations
            threat_matches = threat_data.get("vulnerability_matches", [])
            if threat_matches:
                recommendations.append(
                    f"Monitor {len(threat_matches)} security findings that match current threat intelligence"
                )
            
            # General recommendations based on risk level
            risk_level = risk_assessment.get("risk_level", "Medium")
            if risk_level == "Critical":
                recommendations.append("Implement immediate incident response procedures")
                recommendations.append("Consider engaging external security consultants")
            elif risk_level == "High":
                recommendations.append("Prioritize security remediation in next sprint")
                recommendations.append("Increase security monitoring frequency")
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Recommendation generation failed: {e}")
            return ["Error generating recommendations - manual review required"]
    
    def _calculate_overall_score(
        self, 
        cloud_results: Dict[str, Any],
        threat_data: Dict[str, Any],
        risk_assessment: Dict[str, Any]
    ) -> int:
        """Calculate overall security score (0-100, higher is better)"""
        try:
            base_score = 100
            
            # Deduct points for risks
            risk_deduction = risk_assessment.get("final_risk_score", 0)
            
            # Additional deductions for threat intelligence matches
            threat_matches = len(threat_data.get("vulnerability_matches", []))
            threat_deduction = min(20, threat_matches * 2)
            
            final_score = max(0, base_score - risk_deduction - threat_deduction)
            return int(final_score)
            
        except Exception as e:
            logger.error(f"Score calculation failed: {e}")
            return 0
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert numeric risk score to risk level"""
        if risk_score >= 70:
            return "Critical"
        elif risk_score >= 50:
            return "High"
        elif risk_score >= 25:
            return "Medium"
        else:
            return "Low"
    
    async def cleanup(self):
        """Clean up resources"""
        try:
            if hasattr(self.vector_store, 'cleanup'):
                await self.vector_store.cleanup()
            logger.info("AI Analytics Manager cleanup completed")
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
    
    @monitored("comprehensive_ai_analysis")
    @cached("analysis_results", ttl_seconds=1800)  # 30 minutes
    async def perform_enhanced_comprehensive_analysis(
        self,
        tenant_id: str,
        scan_targets: List[str],
        scan_options: Dict[str, bool],
        security_events: List[Dict[str, Any]] = None,
        compliance_frameworks: List[str] = None
    ) -> AnalysisResult:
        """
        Perform enhanced comprehensive AI-powered security analysis
        Integrates all Phase 3 capabilities including LLM analysis, behavioral patterns, and compliance
        
        Args:
            tenant_id: Unique tenant identifier
            scan_targets: Cloud providers/services to scan
            scan_options: Scanning configuration options
            security_events: Security events for behavioral analysis
            compliance_frameworks: Compliance frameworks to assess
            
        Returns:
            Enhanced AnalysisResult with comprehensive analysis
        """
        if not self._initialized:
            await self.initialize()
            
        scan_id = f"enhanced_scan_{tenant_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        logger.info(f"Starting enhanced comprehensive analysis: {scan_id}")
        
        try:
            # Step 1: Traditional Cloud Security Scanning
            cloud_results = await self._perform_cloud_scanning(scan_targets, scan_options)
            
            # Step 2: Enhanced Threat Intelligence Enrichment
            threat_data = await self._enhanced_threat_intelligence_enrichment(cloud_results)
            
            # Step 3: AI-Powered Correlation Analysis
            correlations = await self._perform_correlation_analysis(cloud_results, threat_data)
            
            # Step 4: Behavioral Pattern Analysis (if events provided)
            behavioral_patterns = []
            if security_events:
                behavioral_patterns = await self._analyze_behavioral_patterns(security_events)
            
            # Step 5: Dual LLM Analysis
            llm_analysis = await self._perform_dual_llm_analysis(
                cloud_results, threat_data, correlations, behavioral_patterns
            )
            
            # Step 6: Compliance Assessment (if frameworks specified)
            compliance_reports = {}
            if compliance_frameworks:
                compliance_reports = await self._perform_compliance_assessment(
                    compliance_frameworks, cloud_results, tenant_id
                )
            
            # Step 7: Advanced Analytics Generation
            advanced_analytics = await self._generate_advanced_analytics(
                cloud_results, threat_data, correlations, compliance_reports
            )
            
            # Step 8: Store Enhanced Results
            await self._store_enhanced_analysis_results(
                tenant_id, scan_id, {
                    "cloud_results": cloud_results,
                    "threat_data": threat_data,
                    "correlations": correlations,
                    "behavioral_patterns": behavioral_patterns,
                    "llm_analysis": llm_analysis,
                    "compliance_reports": compliance_reports,
                    "advanced_analytics": advanced_analytics
                }
            )
            
            # Step 9: Generate Enhanced Risk Assessment
            enhanced_risk_assessment = await self._generate_enhanced_risk_assessment(
                cloud_results, threat_data, correlations, behavioral_patterns, 
                llm_analysis, compliance_reports, advanced_analytics
            )
            
            # Step 10: Generate AI-Powered Recommendations
            ai_recommendations = await self._generate_ai_powered_recommendations(
                cloud_results, threat_data, correlations, behavioral_patterns,
                llm_analysis, compliance_reports, enhanced_risk_assessment
            )
            
            # Calculate Enhanced Overall Score
            enhanced_score = self._calculate_enhanced_overall_score(
                cloud_results, threat_data, enhanced_risk_assessment, 
                compliance_reports, llm_analysis
            )
            
            # Create Enhanced Result
            enhanced_result = AnalysisResult(
                scan_id=scan_id,
                timestamp=datetime.now().isoformat(),
                overall_score=enhanced_score,
                threat_intelligence=threat_data,
                correlations=correlations,
                recommendations=ai_recommendations,
                risk_assessment=enhanced_risk_assessment
            )
            
            # Add enhanced fields
            enhanced_result.behavioral_patterns = behavioral_patterns
            enhanced_result.llm_analysis = llm_analysis
            enhanced_result.compliance_reports = compliance_reports
            enhanced_result.advanced_analytics = advanced_analytics
            enhanced_result.analysis_version = "Phase3_Enhanced"
            
            logger.info(f"Enhanced comprehensive analysis completed: {scan_id}")
            return enhanced_result
            
        except Exception as e:
            logger.error(f"Enhanced analysis failed for {scan_id}: {e}")
            raise
    
    async def _enhanced_threat_intelligence_enrichment(self, cloud_results: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced threat intelligence enrichment with real-time feeds"""
        try:
            # Get current threat landscape
            current_threats = await self.threat_intel.get_current_threats()
            
            # Traditional enrichment
            base_threat_data = await self._enrich_with_threat_intelligence(cloud_results)
            
            # Enhanced enrichment with real-time data
            enhanced_threat_data = {
                **base_threat_data,
                "current_threat_landscape": current_threats,
                "real_time_indicators": current_threats.get("indicators_of_compromise", {}),
                "active_campaigns": current_threats.get("active_campaigns", []),
                "emerging_vulnerabilities": current_threats.get("emerging_vulnerabilities", []),
                "threat_actor_activity": current_threats.get("threat_actor_activity", [])
            }
            
            # Cross-reference with current risks
            for provider, provider_results in cloud_results.items():
                for risk in provider_results.get("risks", []):
                    # Find related current threats
                    related_current_threats = await self.threat_intel.find_related_threats(
                        risk.get("title", ""), risk.get("category", "")
                    )
                    
                    if related_current_threats:
                        enhanced_threat_data["vulnerability_matches"].extend(related_current_threats)
            
            return enhanced_threat_data
            
        except Exception as e:
            logger.error(f"Enhanced threat intelligence enrichment failed: {e}")
            return await self._enrich_with_threat_intelligence(cloud_results)
    
    async def _analyze_behavioral_patterns(self, security_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze behavioral patterns from security events"""
        try:
            # Convert events to SecurityEvent objects
            security_event_objects = []
            for event_data in security_events:
                security_event = SecurityEvent(
                    event_id=event_data.get("id", f"event_{len(security_event_objects)}"),
                    timestamp=datetime.fromisoformat(event_data.get("timestamp", datetime.now().isoformat())),
                    source=event_data.get("source", "unknown"),
                    event_type=event_data.get("type", "unknown"),
                    user_id=event_data.get("user_id"),
                    resource=event_data.get("resource", "unknown"),
                    action=event_data.get("action", "unknown"),
                    result=event_data.get("result", "unknown"),
                    metadata=event_data.get("metadata", {})
                )
                security_event_objects.append(security_event)
            
            # Analyze patterns
            patterns = await self.behavioral_analyzer.analyze_behavioral_patterns(security_event_objects)
            
            # Convert patterns to serializable format
            pattern_results = []
            for pattern in patterns:
                pattern_dict = {
                    "pattern_id": pattern.pattern_id,
                    "pattern_type": pattern.pattern_type,
                    "confidence": pattern.confidence,
                    "anomaly_score": pattern.anomaly_score,
                    "affected_entities": pattern.affected_entities,
                    "time_window": pattern.time_window,
                    "indicators": pattern.indicators,
                    "risk_level": pattern.risk_level,
                    "description": pattern.description,
                    "recommended_actions": pattern.recommended_actions
                }
                pattern_results.append(pattern_dict)
            
            return pattern_results
            
        except Exception as e:
            logger.error(f"Behavioral pattern analysis failed: {e}")
            return []
    
    async def _perform_dual_llm_analysis(
        self,
        cloud_results: Dict[str, Any],
        threat_data: Dict[str, Any],
        correlations: List[Dict[str, Any]],
        behavioral_patterns: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Perform dual LLM analysis using GPU acceleration"""
        try:
            # Create security context for LLM analysis
            security_context = SecurityContext(
                event_data=cloud_results,
                threat_intelligence=threat_data,
                compliance_context={},  # Will be populated if compliance assessment is done
                historical_patterns=behavioral_patterns,
                organization_context={
                    "analysis_timestamp": datetime.now().isoformat(),
                    "scan_scope": list(cloud_results.keys()),
                    "total_risks": sum(len(results.get("risks", [])) for results in cloud_results.values())
                }
            )
            
            # Perform dual LLM analysis
            analysis_types = ["threat_analysis", "code_analysis", "compliance_analysis", "risk_assessment"]
            llm_results = await self.llm_integration.perform_dual_llm_analysis(
                security_context, analysis_types
            )
            
            return {
                "llm_analysis_results": llm_results,
                "analysis_summary": self._summarize_llm_results(llm_results),
                "confidence_scores": self._extract_llm_confidence_scores(llm_results),
                "key_findings": self._extract_llm_key_findings(llm_results)
            }
            
        except Exception as e:
            logger.error(f"Dual LLM analysis failed: {e}")
            return {"error": str(e), "analysis_results": {}}
    
    async def _perform_compliance_assessment(
        self,
        frameworks: List[str],
        cloud_results: Dict[str, Any],
        tenant_id: str
    ) -> Dict[str, Any]:
        """Perform comprehensive compliance assessment"""
        try:
            # Prepare organization data from cloud results
            organization_data = {
                "tenant_id": tenant_id,
                "cloud_providers": list(cloud_results.keys()),
                "total_resources": sum(len(results.get("risks", [])) for results in cloud_results.values()),
                "security_controls": self._extract_security_controls(cloud_results),
                "policies": {},
                "monitoring_systems": [],
                "access_controls": {},
                "encryption_enabled": True,  # Simplified
                "backup_systems": []
            }
            
            # Prepare evidence sources
            evidence_sources = [
                {
                    "type": "system_logs",
                    "logs": [f"Security scan results from {provider}" for provider in cloud_results.keys()]
                },
                {
                    "type": "configuration",
                    "configurations": [f"Cloud configuration for {provider}" for provider in cloud_results.keys()]
                }
            ]
            
            # Perform assessment
            compliance_reports = await self.compliance_engine.perform_comprehensive_assessment(
                frameworks, organization_data, evidence_sources
            )
            
            return compliance_reports
            
        except Exception as e:
            logger.error(f"Compliance assessment failed: {e}")
            return {}
    
    async def _generate_advanced_analytics(
        self,
        cloud_results: Dict[str, Any],
        threat_data: Dict[str, Any],
        correlations: List[Dict[str, Any]],
        compliance_reports: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate advanced analytics including heatmaps and scorecards"""
        try:
            analytics_results = {}
            
            # Generate risk heatmap
            analysis_data = {
                "cloud_results": cloud_results,
                "threat_intelligence": threat_data,
                "correlations": correlations
            }
            
            risk_heatmap = await self.advanced_analytics.generate_risk_heatmap(
                analysis_data, dimensions=("severity", "category")
            )
            analytics_results["risk_heatmap"] = risk_heatmap
            
            # Generate compliance scorecards if compliance reports available
            if compliance_reports:
                compliance_scorecards = await self.advanced_analytics.create_compliance_scorecards(
                    compliance_reports
                )
                analytics_results["compliance_scorecards"] = compliance_scorecards
            
            # Generate executive dashboard
            executive_dashboard = await self.advanced_analytics.generate_executive_dashboard(
                analysis_data, compliance_reports, {"risk_trend": "stable"}
            )
            analytics_results["executive_dashboard"] = executive_dashboard
            
            return analytics_results
            
        except Exception as e:
            logger.error(f"Advanced analytics generation failed: {e}")
            return {}
    
    async def _store_enhanced_analysis_results(
        self,
        tenant_id: str,
        scan_id: str,
        enhanced_results: Dict[str, Any]
    ):
        """Store enhanced analysis results with all components"""
        try:
            analysis_document = {
                "tenant_id": tenant_id,
                "scan_id": scan_id,
                "timestamp": datetime.now().isoformat(),
                "analysis_version": "Phase3_Enhanced",
                **enhanced_results
            }
            
            await self.vector_store.store_security_scan(analysis_document)
            logger.info(f"Enhanced analysis results stored for scan: {scan_id}")
            
        except Exception as e:
            logger.error(f"Failed to store enhanced analysis results: {e}")
    
    async def _generate_enhanced_risk_assessment(
        self,
        cloud_results: Dict[str, Any],
        threat_data: Dict[str, Any],
        correlations: List[Dict[str, Any]],
        behavioral_patterns: List[Dict[str, Any]],
        llm_analysis: Dict[str, Any],
        compliance_reports: Dict[str, Any],
        advanced_analytics: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate enhanced risk assessment incorporating all analysis components"""
        try:
            # Base risk assessment
            base_assessment = await self._generate_risk_assessment(cloud_results, threat_data, correlations)
            
            # Behavioral risk factors
            behavioral_risk_factor = 0.0
            if behavioral_patterns:
                high_risk_patterns = [p for p in behavioral_patterns if p.get("risk_level") in ["High", "Critical"]]
                behavioral_risk_factor = min(25.0, len(high_risk_patterns) * 5.0)
            
            # LLM analysis risk factor
            llm_risk_factor = 0.0
            llm_results = llm_analysis.get("llm_analysis_results", {})
            if llm_results:
                # Average confidence across all LLM analyses
                confidences = [result.confidence for result in llm_results.values() if hasattr(result, 'confidence')]
                if confidences:
                    avg_confidence = sum(confidences) / len(confidences)
                    llm_risk_factor = avg_confidence * 15.0  # Up to 15 points from LLM analysis
            
            # Compliance risk factor
            compliance_risk_factor = 0.0
            if compliance_reports:
                non_compliant_frameworks = [
                    report for report in compliance_reports.values() 
                    if hasattr(report, 'overall_score') and report.overall_score < 0.7
                ]
                compliance_risk_factor = min(20.0, len(non_compliant_frameworks) * 10.0)
            
            # Advanced analytics risk factor
            analytics_risk_factor = 0.0
            if advanced_analytics.get("risk_heatmap", {}).get("statistics", {}).get("hotspots"):
                hotspots = advanced_analytics["risk_heatmap"]["statistics"]["hotspots"]
                analytics_risk_factor = min(10.0, len(hotspots) * 2.0)
            
            # Calculate enhanced final risk score
            base_score = base_assessment.get("final_risk_score", 0)
            enhanced_score = min(100.0, base_score + behavioral_risk_factor + llm_risk_factor + 
                               compliance_risk_factor + analytics_risk_factor)
            
            # Enhanced risk assessment
            enhanced_assessment = {
                **base_assessment,
                "enhanced_risk_score": enhanced_score,
                "risk_factors": {
                    "base_risk": base_score,
                    "behavioral_risk": behavioral_risk_factor,
                    "llm_analysis_risk": llm_risk_factor,
                    "compliance_risk": compliance_risk_factor,
                    "analytics_risk": analytics_risk_factor
                },
                "risk_components": {
                    "traditional_scanning": base_assessment,
                    "behavioral_analysis": {
                        "patterns_detected": len(behavioral_patterns),
                        "high_risk_patterns": len([p for p in behavioral_patterns if p.get("risk_level") in ["High", "Critical"]])
                    },
                    "ai_analysis": llm_analysis.get("analysis_summary", {}),
                    "compliance_status": self._summarize_compliance_status(compliance_reports),
                    "advanced_analytics_insights": advanced_analytics.get("risk_heatmap", {}).get("insights", [])
                },
                "overall_risk_level": self._get_enhanced_risk_level(enhanced_score),
                "confidence_level": self._calculate_assessment_confidence(
                    behavioral_patterns, llm_analysis, compliance_reports
                )
            }
            
            return enhanced_assessment
            
        except Exception as e:
            logger.error(f"Enhanced risk assessment generation failed: {e}")
            return await self._generate_risk_assessment(cloud_results, threat_data, correlations)
    
    async def _generate_ai_powered_recommendations(
        self,
        cloud_results: Dict[str, Any],
        threat_data: Dict[str, Any],
        correlations: List[Dict[str, Any]],
        behavioral_patterns: List[Dict[str, Any]],
        llm_analysis: Dict[str, Any],
        compliance_reports: Dict[str, Any],
        risk_assessment: Dict[str, Any]
    ) -> List[str]:
        """Generate AI-powered recommendations from comprehensive analysis"""
        try:
            recommendations = []
            
            # Base recommendations
            base_recommendations = await self._generate_recommendations(
                cloud_results, threat_data, correlations, risk_assessment
            )
            recommendations.extend(base_recommendations)
            
            # Behavioral pattern recommendations
            if behavioral_patterns:
                behavioral_recommendations = self._generate_behavioral_recommendations(behavioral_patterns)
                recommendations.extend(behavioral_recommendations)
            
            # LLM analysis recommendations
            llm_results = llm_analysis.get("llm_analysis_results", {})
            for model_result in llm_results.values():
                if hasattr(model_result, 'recommendations'):
                    recommendations.extend(model_result.recommendations)
            
            # Compliance recommendations
            if compliance_reports:
                compliance_recommendations = self._generate_compliance_recommendations(compliance_reports)
                recommendations.extend(compliance_recommendations)
            
            # AI-prioritized recommendations
            prioritized_recommendations = await self._prioritize_recommendations_with_ai(
                recommendations, risk_assessment
            )
            
            # Remove duplicates while preserving order
            seen = set()
            unique_recommendations = []
            for rec in prioritized_recommendations:
                if rec not in seen:
                    seen.add(rec)
                    unique_recommendations.append(rec)
            
            return unique_recommendations[:15]  # Top 15 recommendations
            
        except Exception as e:
            logger.error(f"AI-powered recommendation generation failed: {e}")
            return await self._generate_recommendations(cloud_results, threat_data, correlations, risk_assessment)
    
    def _calculate_enhanced_overall_score(
        self,
        cloud_results: Dict[str, Any],
        threat_data: Dict[str, Any],
        risk_assessment: Dict[str, Any],
        compliance_reports: Dict[str, Any],
        llm_analysis: Dict[str, Any]
    ) -> int:
        """Calculate enhanced overall score incorporating all analysis components"""
        try:
            # Base score
            base_score = self._calculate_overall_score(cloud_results, threat_data, risk_assessment)
            
            # Compliance score factor
            compliance_factor = 0
            if compliance_reports:
                compliance_scores = [
                    getattr(report, 'overall_score', 0.5) * 100 
                    for report in compliance_reports.values() 
                    if hasattr(report, 'overall_score')
                ]
                if compliance_scores:
                    avg_compliance = sum(compliance_scores) / len(compliance_scores)
                    compliance_factor = (avg_compliance - 50) * 0.3  # Adjust base score by compliance
            
            # LLM confidence factor
            llm_factor = 0
            llm_results = llm_analysis.get("llm_analysis_results", {})
            if llm_results:
                confidences = [
                    result.confidence for result in llm_results.values() 
                    if hasattr(result, 'confidence')
                ]
                if confidences:
                    avg_confidence = sum(confidences) / len(confidences)
                    llm_factor = (avg_confidence - 0.5) * 10  # Adjust by LLM confidence
            
            # Calculate final score
            enhanced_score = base_score + compliance_factor + llm_factor
            
            return max(0, min(100, int(enhanced_score)))
            
        except Exception as e:
            logger.error(f"Enhanced score calculation failed: {e}")
            return self._calculate_overall_score(cloud_results, threat_data, risk_assessment)
    
    def _extract_security_controls(self, cloud_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract security controls from cloud scan results"""
        controls = {}
        
        for provider, results in cloud_results.items():
            provider_controls = []
            for risk in results.get("risks", []):
                if "encryption" in risk.get("title", "").lower():
                    provider_controls.append("encryption")
                if "access" in risk.get("title", "").lower():
                    provider_controls.append("access_control")
                if "network" in risk.get("title", "").lower():
                    provider_controls.append("network_security")
            
            controls[provider] = list(set(provider_controls))
        
        return controls
    
    def _summarize_llm_results(self, llm_results: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize LLM analysis results"""
        summary = {
            "models_analyzed": len(llm_results),
            "total_findings": sum(len(result.findings) for result in llm_results.values() if hasattr(result, 'findings')),
            "avg_confidence": 0.0,
            "primary_insights": []
        }
        
        confidences = [result.confidence for result in llm_results.values() if hasattr(result, 'confidence')]
        if confidences:
            summary["avg_confidence"] = sum(confidences) / len(confidences)
        
        # Extract top insights
        all_findings = []
        for result in llm_results.values():
            if hasattr(result, 'findings'):
                all_findings.extend(result.findings)
        
        summary["primary_insights"] = all_findings[:5]  # Top 5 insights
        
        return summary
    
    def _extract_llm_confidence_scores(self, llm_results: Dict[str, Any]) -> Dict[str, float]:
        """Extract confidence scores from LLM results"""
        confidence_scores = {}
        
        for model_name, result in llm_results.items():
            if hasattr(result, 'confidence'):
                confidence_scores[model_name] = result.confidence
        
        return confidence_scores
    
    def _extract_llm_key_findings(self, llm_results: Dict[str, Any]) -> List[str]:
        """Extract key findings from LLM results"""
        key_findings = []
        
        for result in llm_results.values():
            if hasattr(result, 'findings'):
                key_findings.extend(result.findings[:3])  # Top 3 findings per model
        
        return key_findings[:10]  # Overall top 10 findings
    
    def _summarize_compliance_status(self, compliance_reports: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize compliance status across frameworks"""
        if not compliance_reports:
            return {}
        
        total_frameworks = len(compliance_reports)
        compliant_frameworks = len([
            report for report in compliance_reports.values() 
            if hasattr(report, 'overall_score') and report.overall_score >= 0.8
        ])
        
        avg_score = 0.0
        scores = [
            getattr(report, 'overall_score', 0) * 100 
            for report in compliance_reports.values() 
            if hasattr(report, 'overall_score')
        ]
        if scores:
            avg_score = sum(scores) / len(scores)
        
        return {
            "total_frameworks": total_frameworks,
            "compliant_frameworks": compliant_frameworks,
            "compliance_rate": (compliant_frameworks / total_frameworks) * 100 if total_frameworks > 0 else 0,
            "average_score": round(avg_score, 1)
        }
    
    def _get_enhanced_risk_level(self, risk_score: float) -> str:
        """Get enhanced risk level based on score"""
        if risk_score >= 80:
            return "Critical"
        elif risk_score >= 60:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        else:
            return "Low"
    
    def _calculate_assessment_confidence(
        self,
        behavioral_patterns: List[Dict[str, Any]],
        llm_analysis: Dict[str, Any],
        compliance_reports: Dict[str, Any]
    ) -> float:
        """Calculate overall assessment confidence"""
        confidence_factors = []
        
        # Behavioral analysis confidence
        if behavioral_patterns:
            pattern_confidences = [p.get("confidence", 0.5) for p in behavioral_patterns]
            avg_behavioral_confidence = sum(pattern_confidences) / len(pattern_confidences)
            confidence_factors.append(avg_behavioral_confidence)
        
        # LLM analysis confidence
        llm_results = llm_analysis.get("llm_analysis_results", {})
        if llm_results:
            llm_confidences = [
                result.confidence for result in llm_results.values() 
                if hasattr(result, 'confidence')
            ]
            if llm_confidences:
                avg_llm_confidence = sum(llm_confidences) / len(llm_confidences)
                confidence_factors.append(avg_llm_confidence)
        
        # Compliance assessment confidence (based on evidence quality)
        if compliance_reports:
            confidence_factors.append(0.8)  # High confidence for compliance assessments
        
        # Overall confidence
        if confidence_factors:
            return sum(confidence_factors) / len(confidence_factors)
        else:
            return 0.7  # Default moderate confidence
    
    def _generate_behavioral_recommendations(self, behavioral_patterns: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on behavioral patterns"""
        recommendations = []
        
        for pattern in behavioral_patterns:
            if pattern.get("risk_level") in ["High", "Critical"]:
                recommendations.extend(pattern.get("recommended_actions", []))
        
        return recommendations
    
    def _generate_compliance_recommendations(self, compliance_reports: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on compliance reports"""
        recommendations = []
        
        for report in compliance_reports.values():
            if hasattr(report, 'improvement_roadmap'):
                recommendations.extend(report.improvement_roadmap)
        
        return recommendations
    
    async def _prioritize_recommendations_with_ai(
        self,
        recommendations: List[str],
        risk_assessment: Dict[str, Any]
    ) -> List[str]:
        """Prioritize recommendations using AI analysis"""
        try:
            # Simple prioritization based on keywords and risk factors
            priority_keywords = ["critical", "urgent", "immediate", "security", "compliance"]
            
            scored_recommendations = []
            for rec in recommendations:
                score = 0
                rec_lower = rec.lower()
                
                # Keyword scoring
                for keyword in priority_keywords:
                    if keyword in rec_lower:
                        score += 1
                
                # Risk level scoring
                risk_level = risk_assessment.get("overall_risk_level", "Medium")
                if risk_level == "Critical":
                    score += 3
                elif risk_level == "High":
                    score += 2
                elif risk_level == "Medium":
                    score += 1
                
                scored_recommendations.append((score, rec))
            
            # Sort by score (descending) and return recommendations
            scored_recommendations.sort(key=lambda x: x[0], reverse=True)
            return [rec for score, rec in scored_recommendations]
            
        except Exception as e:
            logger.error(f"AI recommendation prioritization failed: {e}")
            return recommendations