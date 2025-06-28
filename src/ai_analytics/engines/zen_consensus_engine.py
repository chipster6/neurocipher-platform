#!/usr/bin/env python3
"""
Zen MCP Consensus Engine for NeuroCipher
Replaces the matrix-based dual LLM approach with zen-mcp-server's consensus pipeline
"""

import asyncio
import json
import logging
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

from ..zen_mcp_integration import ZenMCPIntegration

class ConsensusStance(Enum):
    """Consensus stance options for threat analysis"""
    FOR = "for"
    AGAINST = "against" 
    NEUTRAL = "neutral"

@dataclass
class ThreatConsensusResult:
    """Result of dual LLM consensus analysis"""
    threat_detected: bool
    confidence_score: float
    consensus_strength: float
    primary_analysis: Dict[str, Any]
    secondary_analysis: Dict[str, Any]
    consensus_reasoning: str
    recommended_actions: List[str]
    false_positive_likelihood: float
    escalation_required: bool

class ZenConsensusEngine:
    """
    Advanced consensus engine using zen-mcp-server for dual LLM threat analysis
    Replaces the matrix-based approach with more sophisticated consensus mechanisms
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.zen_integration = ZenMCPIntegration()
        self.logger = logging.getLogger(__name__)
        
        # Consensus thresholds
        self.high_confidence_threshold = 0.85
        self.consensus_agreement_threshold = 0.75
        self.escalation_threshold = 0.9
        
    async def initialize(self) -> bool:
        """Initialize the zen consensus engine"""
        try:
            initialized = await self.zen_integration.initialize_zen_server()
            if initialized:
                self.logger.info("✅ Zen Consensus Engine initialized successfully")
                return True
            else:
                self.logger.error("❌ Failed to initialize Zen MCP Server")
                return False
        except Exception as e:
            self.logger.error(f"Error initializing Zen Consensus Engine: {e}")
            return False
    
    async def analyze_threat_consensus(
        self, 
        security_data: Dict[str, Any],
        analysis_type: str = "comprehensive",
        stance_bias: Optional[ConsensusStance] = None
    ) -> ThreatConsensusResult:
        """
        Perform dual LLM consensus analysis on security data
        
        Args:
            security_data: Security scan results, logs, or threat indicators
            analysis_type: Type of analysis (comprehensive, quick, deep)
            stance_bias: Optional bias for consensus (for/against/neutral)
            
        Returns:
            ThreatConsensusResult with consensus findings
        """
        try:
            # Prepare security context for analysis
            security_context = self._prepare_security_context(security_data, analysis_type)
            
            # Stage 1: Primary threat analysis
            primary_analysis = await self._primary_threat_analysis(security_context, stance_bias)
            
            # Stage 2: Secondary validation analysis
            secondary_analysis = await self._secondary_validation_analysis(
                security_context, 
                primary_analysis,
                stance_bias
            )
            
            # Stage 3: Consensus resolution
            consensus_result = await self._resolve_consensus(
                primary_analysis,
                secondary_analysis,
                security_context
            )
            
            # Stage 4: Final validation and confidence scoring
            final_result = await self._finalize_consensus_result(
                consensus_result,
                primary_analysis,
                secondary_analysis,
                security_data
            )
            
            return final_result
            
        except Exception as e:
            self.logger.error(f"Error in threat consensus analysis: {e}")
            return self._create_error_result(str(e))
    
    async def analyze_vulnerability_consensus(
        self,
        vulnerability_data: Dict[str, Any],
        severity_threshold: str = "medium"
    ) -> ThreatConsensusResult:
        """
        Consensus analysis specifically for vulnerability assessment
        """
        try:
            vuln_prompt = f"""
            Analyze this vulnerability data for a cybersecurity platform:
            
            Vulnerability Data:
            {json.dumps(vulnerability_data, indent=2)}
            
            Severity Threshold: {severity_threshold}
            
            Assess:
            1. Is this a genuine security vulnerability?
            2. What is the actual risk level (considering CVSS, exploitability, context)?
            3. Is immediate action required?
            4. Could this be a false positive?
            5. What are the recommended remediation steps?
            
            Focus on practical cybersecurity impact for SMB environments.
            """
            
            # Use zen-mcp consensus tool for vulnerability analysis
            consensus_result = await self._execute_zen_consensus(
                vuln_prompt,
                stance=ConsensusStance.NEUTRAL,
                analysis_depth="high"
            )
            
            return self._parse_vulnerability_consensus(consensus_result, vulnerability_data)
            
        except Exception as e:
            self.logger.error(f"Error in vulnerability consensus: {e}")
            return self._create_error_result(str(e))
    
    async def analyze_incident_consensus(
        self,
        incident_data: Dict[str, Any],
        urgency_level: str = "normal"
    ) -> ThreatConsensusResult:
        """
        Consensus analysis for security incident response
        """
        try:
            incident_prompt = f"""
            Analyze this security incident for immediate response decisions:
            
            Incident Data:
            {json.dumps(incident_data, indent=2)}
            
            Urgency Level: {urgency_level}
            
            Determine:
            1. Is this a legitimate security incident?
            2. What is the threat severity and scope?
            3. What immediate containment actions are needed?
            4. Should this trigger automated response?
            5. What are the business impact considerations?
            
            Provide actionable recommendations for SMB incident response.
            """
            
            # Use elevated stance for incident analysis (bias toward action)
            consensus_result = await self._execute_zen_consensus(
                incident_prompt,
                stance=ConsensusStance.FOR if urgency_level == "high" else ConsensusStance.NEUTRAL,
                analysis_depth="max"
            )
            
            return self._parse_incident_consensus(consensus_result, incident_data)
            
        except Exception as e:
            self.logger.error(f"Error in incident consensus: {e}")
            return self._create_error_result(str(e))
    
    async def _primary_threat_analysis(
        self, 
        security_context: str,
        stance_bias: Optional[ConsensusStance]
    ) -> Dict[str, Any]:
        """Perform primary threat analysis using zen-mcp"""
        try:
            primary_prompt = f"""
            PRIMARY THREAT ANALYSIS:
            
            {security_context}
            
            As the primary security analyst, provide:
            1. Initial threat assessment
            2. Risk level evaluation
            3. Evidence analysis
            4. Confidence level in findings
            5. Recommended immediate actions
            
            Be thorough but decisive in your analysis.
            """
            
            result = await self._execute_zen_tool("thinkdeep", primary_prompt)
            
            return {
                "analysis": result.get("content", ""),
                "confidence": self._extract_confidence_score(result),
                "threat_level": self._extract_threat_level(result),
                "evidence_strength": self._extract_evidence_strength(result),
                "timestamp": time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Error in primary analysis: {e}")
            return {"error": str(e), "confidence": 0.0}
    
    async def _secondary_validation_analysis(
        self,
        security_context: str,
        primary_analysis: Dict[str, Any],
        stance_bias: Optional[ConsensusStance]
    ) -> Dict[str, Any]:
        """Perform secondary validation analysis"""
        try:
            secondary_prompt = f"""
            SECONDARY VALIDATION ANALYSIS:
            
            Original Security Context:
            {security_context}
            
            Primary Analysis Results:
            {json.dumps(primary_analysis, indent=2)}
            
            As the secondary validator, critically evaluate:
            1. Do you agree with the primary analysis?
            2. What alternative interpretations are possible?
            3. Are there any false positive indicators?
            4. What additional evidence would strengthen this assessment?
            5. Would you recommend different actions?
            
            Provide an independent assessment that challenges or confirms the primary findings.
            """
            
            result = await self._execute_zen_tool("analyze", secondary_prompt)
            
            return {
                "analysis": result.get("content", ""),
                "confidence": self._extract_confidence_score(result),
                "agreement_level": self._extract_agreement_level(result, primary_analysis),
                "alternative_interpretation": self._extract_alternatives(result),
                "timestamp": time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Error in secondary analysis: {e}")
            return {"error": str(e), "confidence": 0.0}
    
    async def _resolve_consensus(
        self,
        primary_analysis: Dict[str, Any],
        secondary_analysis: Dict[str, Any],
        security_context: str
    ) -> Dict[str, Any]:
        """Resolve consensus between primary and secondary analyses"""
        try:
            consensus_prompt = f"""
            CONSENSUS RESOLUTION:
            
            Primary Analysis:
            {json.dumps(primary_analysis, indent=2)}
            
            Secondary Analysis:
            {json.dumps(secondary_analysis, indent=2)}
            
            Original Context:
            {security_context}
            
            Resolve the consensus by:
            1. Identifying areas of agreement and disagreement
            2. Weighing the evidence and confidence levels
            3. Determining the final threat assessment
            4. Calculating overall confidence score
            5. Providing unified recommendations
            
            Make a definitive decision on threat status and required actions.
            """
            
            # Use zen-mcp consensus tool with neutral stance for final resolution
            result = await self._execute_zen_consensus(
                consensus_prompt,
                stance=ConsensusStance.NEUTRAL,
                analysis_depth="high"
            )
            
            return {
                "consensus": result.get("content", ""),
                "final_decision": self._extract_final_decision(result),
                "confidence_score": self._calculate_consensus_confidence(primary_analysis, secondary_analysis),
                "consensus_strength": self._calculate_consensus_strength(primary_analysis, secondary_analysis),
                "timestamp": time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Error resolving consensus: {e}")
            return {"error": str(e)}
    
    async def _execute_zen_consensus(
        self,
        prompt: str,
        stance: ConsensusStance,
        analysis_depth: str = "medium"
    ) -> Dict[str, Any]:
        """Execute zen-mcp consensus tool with specified parameters"""
        try:
            # Format for zen-mcp consensus tool
            consensus_prompt = f"""
            CONSENSUS_STANCE: {stance.value}
            ANALYSIS_DEPTH: {analysis_depth}
            
            {prompt}
            """
            
            # Execute through zen integration
            result = await self.zen_integration._execute_zen_tool("consensus", consensus_prompt)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error executing zen consensus: {e}")
            return {"error": str(e)}
    
    async def _execute_zen_tool(self, tool_name: str, prompt: str) -> Dict[str, Any]:
        """Execute zen-mcp tool"""
        return await self.zen_integration._execute_zen_tool(tool_name, prompt)
    
    def _prepare_security_context(self, security_data: Dict[str, Any], analysis_type: str) -> str:
        """Prepare security context for analysis"""
        context = f"""
        NEUROCIPHER SECURITY ANALYSIS
        Analysis Type: {analysis_type}
        Timestamp: {time.time()}
        
        Security Data:
        {json.dumps(security_data, indent=2)}
        
        Platform Context:
        - AI-powered cybersecurity platform for SMBs
        - Focus on practical threat assessment
        - Minimize false positives for business continuity
        - Prioritize actionable recommendations
        """
        
        return context
    
    def _extract_confidence_score(self, result: Dict[str, Any]) -> float:
        """Extract confidence score from analysis result"""
        # Parse confidence from result content
        content = result.get("content", "").lower()
        
        if "high confidence" in content or "very confident" in content:
            return 0.9
        elif "medium confidence" in content or "confident" in content:
            return 0.7
        elif "low confidence" in content or "uncertain" in content:
            return 0.4
        else:
            return 0.6  # Default moderate confidence
    
    def _extract_threat_level(self, result: Dict[str, Any]) -> str:
        """Extract threat level from analysis"""
        content = result.get("content", "").lower()
        
        if any(word in content for word in ["critical", "severe", "high risk"]):
            return "high"
        elif any(word in content for word in ["medium", "moderate", "warning"]):
            return "medium"
        elif any(word in content for word in ["low", "minor", "info"]):
            return "low"
        else:
            return "unknown"
    
    def _extract_evidence_strength(self, result: Dict[str, Any]) -> float:
        """Extract evidence strength from analysis"""
        content = result.get("content", "").lower()
        
        if "strong evidence" in content or "clear indicators" in content:
            return 0.9
        elif "moderate evidence" in content or "some indicators" in content:
            return 0.6
        elif "weak evidence" in content or "limited indicators" in content:
            return 0.3
        else:
            return 0.5
    
    def _extract_agreement_level(self, result: Dict[str, Any], primary_analysis: Dict[str, Any]) -> float:
        """Extract agreement level between analyses"""
        # Simplified agreement calculation
        return 0.8  # Mock implementation
    
    def _extract_alternatives(self, result: Dict[str, Any]) -> List[str]:
        """Extract alternative interpretations"""
        return ["Alternative interpretation 1", "Alternative interpretation 2"]  # Mock
    
    def _extract_final_decision(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract final consensus decision"""
        return {
            "threat_detected": True,  # Mock
            "action_required": True,
            "severity": "medium"
        }
    
    def _calculate_consensus_confidence(self, primary: Dict[str, Any], secondary: Dict[str, Any]) -> float:
        """Calculate overall consensus confidence"""
        primary_conf = primary.get("confidence", 0.5)
        secondary_conf = secondary.get("confidence", 0.5)
        
        # Weight based on agreement
        agreement = abs(primary_conf - secondary_conf)
        consensus_bonus = 1.0 - (agreement / 2.0)
        
        return min(0.95, (primary_conf + secondary_conf) / 2.0 * consensus_bonus)
    
    def _calculate_consensus_strength(self, primary: Dict[str, Any], secondary: Dict[str, Any]) -> float:
        """Calculate strength of consensus between analyses"""
        primary_conf = primary.get("confidence", 0.5)
        secondary_conf = secondary.get("confidence", 0.5)
        
        # Strong consensus when both analyses agree with high confidence
        agreement = 1.0 - abs(primary_conf - secondary_conf)
        avg_confidence = (primary_conf + secondary_conf) / 2.0
        
        return agreement * avg_confidence
    
    async def _finalize_consensus_result(
        self,
        consensus_result: Dict[str, Any],
        primary_analysis: Dict[str, Any],
        secondary_analysis: Dict[str, Any],
        original_data: Dict[str, Any]
    ) -> ThreatConsensusResult:
        """Finalize and structure the consensus result"""
        
        decision = consensus_result.get("final_decision", {})
        confidence = consensus_result.get("confidence_score", 0.5)
        consensus_strength = consensus_result.get("consensus_strength", 0.5)
        
        return ThreatConsensusResult(
            threat_detected=decision.get("threat_detected", False),
            confidence_score=confidence,
            consensus_strength=consensus_strength,
            primary_analysis=primary_analysis,
            secondary_analysis=secondary_analysis,
            consensus_reasoning=consensus_result.get("consensus", ""),
            recommended_actions=self._extract_recommended_actions(consensus_result),
            false_positive_likelihood=1.0 - confidence,
            escalation_required=confidence > self.escalation_threshold
        )
    
    def _extract_recommended_actions(self, result: Dict[str, Any]) -> List[str]:
        """Extract recommended actions from consensus result"""
        return ["Monitor system", "Update security policies", "Investigate further"]  # Mock
    
    def _create_error_result(self, error_message: str) -> ThreatConsensusResult:
        """Create error result for failed analysis"""
        return ThreatConsensusResult(
            threat_detected=False,
            confidence_score=0.0,
            consensus_strength=0.0,
            primary_analysis={"error": error_message},
            secondary_analysis={"error": error_message},
            consensus_reasoning=f"Analysis failed: {error_message}",
            recommended_actions=["Manual review required", "Check system logs"],
            false_positive_likelihood=1.0,
            escalation_required=True
        )
    
    def _parse_vulnerability_consensus(
        self, 
        consensus_result: Dict[str, Any], 
        vuln_data: Dict[str, Any]
    ) -> ThreatConsensusResult:
        """Parse consensus result for vulnerability analysis"""
        # Implementation would parse specific vulnerability assessment
        return self._create_mock_result("vulnerability")
    
    def _parse_incident_consensus(
        self, 
        consensus_result: Dict[str, Any], 
        incident_data: Dict[str, Any]
    ) -> ThreatConsensusResult:
        """Parse consensus result for incident analysis"""
        # Implementation would parse specific incident assessment
        return self._create_mock_result("incident")
    
    def _create_mock_result(self, analysis_type: str) -> ThreatConsensusResult:
        """Create mock result for testing"""
        return ThreatConsensusResult(
            threat_detected=True,
            confidence_score=0.85,
            consensus_strength=0.9,
            primary_analysis={"type": analysis_type, "confidence": 0.8},
            secondary_analysis={"type": analysis_type, "confidence": 0.9},
            consensus_reasoning=f"Mock {analysis_type} consensus analysis",
            recommended_actions=[f"Action for {analysis_type}"],
            false_positive_likelihood=0.15,
            escalation_required=False
        )

# Example usage
if __name__ == "__main__":
    async def main():
        engine = ZenConsensusEngine()
        
        if await engine.initialize():
            # Test threat consensus
            security_data = {
                "source_ip": "192.168.1.100",
                "suspicious_activity": "Multiple failed login attempts",
                "user_agent": "Automated scanner detected",
                "timestamp": time.time()
            }
            
            result = await engine.analyze_threat_consensus(security_data)
            
            print(f"Threat Detected: {result.threat_detected}")
            print(f"Confidence: {result.confidence_score:.2f}")
            print(f"Consensus Strength: {result.consensus_strength:.2f}")
            print(f"Recommended Actions: {result.recommended_actions}")
            
        else:
            print("Failed to initialize consensus engine")
    
    asyncio.run(main())