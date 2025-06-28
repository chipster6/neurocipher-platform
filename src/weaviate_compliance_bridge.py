#!/usr/bin/env python3
"""
Weaviate Compliance Intelligence Bridge
Transforms compliance scoring results into persistent vector database for analytics
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
import weaviate
from weaviate.batch import Batch
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class ComplianceScoreResult:
    """Structured compliance score result for Weaviate persistence"""
    provider: str
    control: str
    framework: str
    score: float
    client_id: str
    timestamp: str
    details: str
    component_scores: Dict[str, float] = field(default_factory=dict)
    evidence_summary: Dict[str, Any] = field(default_factory=dict)
    remediation_guidance: List[str] = field(default_factory=list)
    risk_factors: List[str] = field(default_factory=list)
    
    def to_weaviate_object(self) -> Dict[str, Any]:
        """Convert to Weaviate object format"""
        return {
            "provider": self.provider,
            "control": self.control,
            "framework": self.framework,
            "score": self.score,
            "clientId": self.client_id,
            "timestamp": self.timestamp,
            "details": self.details,
            "componentScores": json.dumps(self.component_scores),
            "evidenceSummary": json.dumps(self.evidence_summary),
            "remediationGuidance": "; ".join(self.remediation_guidance),
            "riskFactors": "; ".join(self.risk_factors),
            "scoreCategory": self._get_score_category(),
            "complianceStatus": self._get_compliance_status()
        }
    
    def _get_score_category(self) -> str:
        """Categorize score for easier filtering"""
        if self.score >= 90:
            return "excellent"
        elif self.score >= 80:
            return "good"
        elif self.score >= 70:
            return "acceptable"
        elif self.score >= 50:
            return "poor"
        else:
            return "critical"
    
    def _get_compliance_status(self) -> str:
        """Get compliance status based on score"""
        if self.score >= 90:
            return "compliant"
        elif self.score >= 70:
            return "partial"
        else:
            return "non_compliant"

class WeaviateComplianceBridge:
    """
    Bridge between compliance scoring functions and Weaviate vector database
    Enables historical tracking, analytics, and semantic search of compliance data
    """
    
    def __init__(self, weaviate_client: weaviate.Client):
        """
        Initialize Weaviate compliance bridge
        
        Args:
            weaviate_client: Configured Weaviate client instance
        """
        self.client = weaviate_client
        self.batch_size = 100
        self.ensure_schema()
        
        logger.info("Weaviate compliance bridge initialized")
    
    def ensure_schema(self):
        """Ensure required Weaviate classes exist"""
        try:
            # ComplianceScore class for individual control scores
            compliance_score_class = {
                "class": "ComplianceScore",
                "description": "Normalized compliance results per cloud provider and control category",
                "properties": [
                    {"name": "provider", "dataType": ["text"], "description": "Cloud provider (AWS, GCP, Azure)"},
                    {"name": "control", "dataType": ["text"], "description": "Compliance control ID (CC6.1, CC6.2, etc.)"},
                    {"name": "framework", "dataType": ["text"], "description": "Compliance framework (SOC2, ISO27001, etc.)"},
                    {"name": "score", "dataType": ["number"], "description": "Compliance score 0-100"},
                    {"name": "clientId", "dataType": ["text"], "description": "Multi-tenant client identifier"},
                    {"name": "timestamp", "dataType": ["date"], "description": "Score calculation timestamp"},
                    {"name": "details", "dataType": ["text"], "description": "Human-readable score explanation"},
                    {"name": "componentScores", "dataType": ["text"], "description": "JSON of component-level scores"},
                    {"name": "evidenceSummary", "dataType": ["text"], "description": "JSON of evidence data"},
                    {"name": "remediationGuidance", "dataType": ["text"], "description": "Remediation recommendations"},
                    {"name": "riskFactors", "dataType": ["text"], "description": "Identified risk factors"},
                    {"name": "scoreCategory", "dataType": ["text"], "description": "Score category (excellent, good, acceptable, poor, critical)"},
                    {"name": "complianceStatus", "dataType": ["text"], "description": "Compliance status (compliant, partial, non_compliant)"}
                ],
                "vectorizer": "text2vec-openai" if self._check_vectorizer_available() else "none"
            }
            
            # ComplianceTrend class for trend analysis
            compliance_trend_class = {
                "class": "ComplianceTrend",
                "description": "Historical compliance trends and analytics",
                "properties": [
                    {"name": "clientId", "dataType": ["text"], "description": "Multi-tenant client identifier"},
                    {"name": "provider", "dataType": ["text"], "description": "Cloud provider"},
                    {"name": "control", "dataType": ["text"], "description": "Compliance control ID"},
                    {"name": "framework", "dataType": ["text"], "description": "Compliance framework"},
                    {"name": "timeWindow", "dataType": ["text"], "description": "Time window (daily, weekly, monthly)"},
                    {"name": "startDate", "dataType": ["date"], "description": "Trend period start"},
                    {"name": "endDate", "dataType": ["date"], "description": "Trend period end"},
                    {"name": "averageScore", "dataType": ["number"], "description": "Average score for period"},
                    {"name": "minScore", "dataType": ["number"], "description": "Minimum score for period"},
                    {"name": "maxScore", "dataType": ["number"], "description": "Maximum score for period"},
                    {"name": "scoreVariance", "dataType": ["number"], "description": "Score variance"},
                    {"name": "trendDirection", "dataType": ["text"], "description": "improving, declining, stable"},
                    {"name": "dataPoints", "dataType": ["int"], "description": "Number of data points"},
                    {"name": "insights", "dataType": ["text"], "description": "AI-generated insights"}
                ],
                "vectorizer": "none"
            }
            
            # Create classes if they don't exist
            existing_classes = [c['class'] for c in self.client.schema.get()['classes']]
            
            if "ComplianceScore" not in existing_classes:
                self.client.schema.create_class(compliance_score_class)
                logger.info("Created ComplianceScore class in Weaviate")
            
            if "ComplianceTrend" not in existing_classes:
                self.client.schema.create_class(compliance_trend_class)
                logger.info("Created ComplianceTrend class in Weaviate")
                
        except Exception as e:
            logger.error(f"Failed to ensure Weaviate schema: {e}")
            raise
    
    def _check_vectorizer_available(self) -> bool:
        """Check if OpenAI vectorizer is available"""
        try:
            modules = self.client.get_meta()['modules']
            return any('text2vec-openai' in str(module) for module in modules.values())
        except:
            return False
    
    def persist_score(self, score_result: ComplianceScoreResult) -> str:
        """
        Persist individual compliance score to Weaviate
        
        Args:
            score_result: Structured compliance score result
            
        Returns:
            Weaviate object UUID
        """
        try:
            weaviate_object = score_result.to_weaviate_object()
            
            result = self.client.data_object.create(
                data_object=weaviate_object,
                class_name="ComplianceScore"
            )
            
            logger.debug(f"Persisted compliance score: {score_result.provider}/{score_result.control} = {score_result.score}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to persist compliance score: {e}")
            raise
    
    def persist_scores_batch(self, score_results: List[ComplianceScoreResult]) -> List[str]:
        """
        Persist multiple compliance scores in batch for performance
        
        Args:
            score_results: List of compliance score results
            
        Returns:
            List of Weaviate object UUIDs
        """
        try:
            batch_results = []
            
            with self.client.batch as batch:
                batch.batch_size = self.batch_size
                
                for score_result in score_results:
                    weaviate_object = score_result.to_weaviate_object()
                    
                    uuid = batch.add_data_object(
                        data_object=weaviate_object,
                        class_name="ComplianceScore"
                    )
                    batch_results.append(uuid)
            
            logger.info(f"Batch persisted {len(score_results)} compliance scores")
            return batch_results
            
        except Exception as e:
            logger.error(f"Failed to batch persist compliance scores: {e}")
            raise
    
    def query_scores(self, client_id: Optional[str] = None, 
                    provider: Optional[str] = None,
                    control: Optional[str] = None,
                    framework: Optional[str] = None,
                    min_score: Optional[float] = None,
                    max_score: Optional[float] = None,
                    since_date: Optional[datetime] = None,
                    limit: int = 100) -> List[Dict[str, Any]]:
        """
        Query compliance scores with filtering
        
        Args:
            client_id: Filter by tenant
            provider: Filter by cloud provider
            control: Filter by compliance control
            framework: Filter by compliance framework
            min_score: Minimum score filter
            max_score: Maximum score filter
            since_date: Filter scores since date
            limit: Maximum results to return
            
        Returns:
            List of compliance score objects
        """
        try:
            query = self.client.query.get("ComplianceScore", [
                "provider", "control", "framework", "score", "clientId",
                "timestamp", "details", "componentScores", "evidenceSummary",
                "remediationGuidance", "riskFactors", "scoreCategory", "complianceStatus"
            ])
            
            # Build where filter
            where_conditions = []
            
            if client_id:
                where_conditions.append({
                    "path": ["clientId"],
                    "operator": "Equal",
                    "valueText": client_id
                })
            
            if provider:
                where_conditions.append({
                    "path": ["provider"],
                    "operator": "Equal",
                    "valueText": provider
                })
            
            if control:
                where_conditions.append({
                    "path": ["control"],
                    "operator": "Equal",
                    "valueText": control
                })
            
            if framework:
                where_conditions.append({
                    "path": ["framework"],
                    "operator": "Equal",
                    "valueText": framework
                })
            
            if min_score is not None:
                where_conditions.append({
                    "path": ["score"],
                    "operator": "GreaterThanEqual",
                    "valueNumber": min_score
                })
            
            if max_score is not None:
                where_conditions.append({
                    "path": ["score"],
                    "operator": "LessThanEqual",
                    "valueNumber": max_score
                })
            
            if since_date:
                where_conditions.append({
                    "path": ["timestamp"],
                    "operator": "GreaterThan",
                    "valueDate": since_date.isoformat()
                })
            
            # Apply filters
            if len(where_conditions) == 1:
                query = query.with_where(where_conditions[0])
            elif len(where_conditions) > 1:
                query = query.with_where({
                    "operator": "And",
                    "operands": where_conditions
                })
            
            # Apply limit and execute
            result = query.with_limit(limit).do()
            
            if 'data' in result and 'Get' in result['data']:
                return result['data']['Get']['ComplianceScore']
            else:
                return []
                
        except Exception as e:
            logger.error(f"Failed to query compliance scores: {e}")
            return []
    
    def get_compliance_trends(self, client_id: str, 
                            time_window: str = "weekly",
                            lookback_days: int = 30) -> Dict[str, Any]:
        """
        Calculate compliance trends and analytics
        
        Args:
            client_id: Tenant identifier
            time_window: Aggregation window (daily, weekly, monthly)
            lookback_days: Days to look back for trend analysis
            
        Returns:
            Trend analysis results
        """
        try:
            since_date = datetime.now() - timedelta(days=lookback_days)
            
            # Get all scores for client in time window
            scores = self.query_scores(
                client_id=client_id,
                since_date=since_date,
                limit=1000
            )
            
            if not scores:
                return {"error": "No compliance data found"}
            
            # Analyze trends by provider and control
            trends = {}
            
            for score in scores:
                key = f"{score['provider']}/{score['control']}"
                if key not in trends:
                    trends[key] = {
                        'scores': [],
                        'timestamps': [],
                        'provider': score['provider'],
                        'control': score['control']
                    }
                
                trends[key]['scores'].append(score['score'])
                trends[key]['timestamps'].append(score['timestamp'])
            
            # Calculate trend metrics
            trend_analysis = {}
            
            for key, data in trends.items():
                scores = data['scores']
                if len(scores) < 2:
                    continue
                
                avg_score = sum(scores) / len(scores)
                min_score = min(scores)
                max_score = max(scores)
                score_variance = sum((x - avg_score) ** 2 for x in scores) / len(scores)
                
                # Determine trend direction
                recent_avg = sum(scores[-5:]) / min(5, len(scores))
                older_avg = sum(scores[:5]) / min(5, len(scores))
                
                if recent_avg > older_avg + 5:
                    trend_direction = "improving"
                elif recent_avg < older_avg - 5:
                    trend_direction = "declining"
                else:
                    trend_direction = "stable"
                
                trend_analysis[key] = {
                    'provider': data['provider'],
                    'control': data['control'],
                    'average_score': avg_score,
                    'min_score': min_score,
                    'max_score': max_score,
                    'score_variance': score_variance,
                    'trend_direction': trend_direction,
                    'data_points': len(scores),
                    'score_history': scores[-10:],  # Last 10 scores
                    'insights': self._generate_insights(scores, trend_direction, avg_score)
                }
            
            return {
                'client_id': client_id,
                'time_window': time_window,
                'analysis_period': f"{lookback_days} days",
                'total_controls_analyzed': len(trend_analysis),
                'trends': trend_analysis,
                'overall_health': self._calculate_overall_health(trend_analysis)
            }
            
        except Exception as e:
            logger.error(f"Failed to calculate compliance trends: {e}")
            return {"error": str(e)}
    
    def _generate_insights(self, scores: List[float], trend_direction: str, avg_score: float) -> str:
        """Generate AI-style insights from score data"""
        insights = []
        
        if trend_direction == "improving":
            insights.append("📈 Compliance scores are improving over time")
        elif trend_direction == "declining":
            insights.append("📉 Compliance scores are declining - attention needed")
        else:
            insights.append("📊 Compliance scores are stable")
        
        if avg_score >= 90:
            insights.append("✅ Excellent compliance posture maintained")
        elif avg_score >= 70:
            insights.append("⚠️ Partial compliance - room for improvement")
        else:
            insights.append("❌ Poor compliance - immediate action required")
        
        if len(scores) > 5:
            recent_variance = sum((x - sum(scores[-5:]) / 5) ** 2 for x in scores[-5:]) / 5
            if recent_variance > 100:
                insights.append("🔄 High score volatility detected")
        
        return "; ".join(insights)
    
    def _calculate_overall_health(self, trend_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall compliance health metrics"""
        if not trend_analysis:
            return {}
        
        all_scores = [trend['average_score'] for trend in trend_analysis.values()]
        improving_count = len([t for t in trend_analysis.values() if t['trend_direction'] == 'improving'])
        declining_count = len([t for t in trend_analysis.values() if t['trend_direction'] == 'declining'])
        
        return {
            'overall_average': sum(all_scores) / len(all_scores),
            'controls_improving': improving_count,
            'controls_declining': declining_count,
            'controls_stable': len(trend_analysis) - improving_count - declining_count,
            'health_score': (sum(all_scores) / len(all_scores)) * (1 + (improving_count - declining_count) / len(trend_analysis) * 0.1)
        }
    
    def semantic_search(self, query_text: str, client_id: Optional[str] = None, 
                       limit: int = 10) -> List[Dict[str, Any]]:
        """
        Semantic search of compliance scores using vector similarity
        
        Args:
            query_text: Natural language query
            client_id: Optional tenant filter
            limit: Maximum results
            
        Returns:
            List of relevant compliance scores
        """
        try:
            if not self._check_vectorizer_available():
                logger.warning("Semantic search requires OpenAI vectorizer - falling back to keyword search")
                return self._keyword_search(query_text, client_id, limit)
            
            query = self.client.query.get("ComplianceScore", [
                "provider", "control", "framework", "score", "details",
                "remediationGuidance", "riskFactors"
            ]).with_near_text({
                "concepts": [query_text]
            })
            
            if client_id:
                query = query.with_where({
                    "path": ["clientId"],
                    "operator": "Equal",
                    "valueText": client_id
                })
            
            result = query.with_limit(limit).do()
            
            if 'data' in result and 'Get' in result['data']:
                return result['data']['Get']['ComplianceScore']
            else:
                return []
                
        except Exception as e:
            logger.error(f"Semantic search failed: {e}")
            return []
    
    def _keyword_search(self, query_text: str, client_id: Optional[str], limit: int) -> List[Dict[str, Any]]:
        """Fallback keyword search when vectorizer is not available"""
        # Simple keyword matching on details field
        scores = self.query_scores(client_id=client_id, limit=limit * 2)
        
        query_words = query_text.lower().split()
        results = []
        
        for score in scores:
            details = score.get('details', '').lower()
            guidance = score.get('remediationGuidance', '').lower()
            
            relevance = sum(1 for word in query_words if word in details or word in guidance)
            
            if relevance > 0:
                score['_relevance'] = relevance
                results.append(score)
        
        # Sort by relevance and return top results
        results.sort(key=lambda x: x.get('_relevance', 0), reverse=True)
        return results[:limit]

def create_enhanced_scoring_wrapper(bridge: WeaviateComplianceBridge):
    """
    Create wrapper functions that enhance existing scoring functions with Weaviate persistence
    
    Args:
        bridge: Weaviate compliance bridge instance
        
    Returns:
        Dictionary of enhanced scoring functions
    """
    
    def enhanced_gcp_mfa_check(evidence: Dict[str, Any], client_id: str = "default") -> ComplianceScoreResult:
        """Enhanced GCP MFA check with Weaviate persistence"""
        from .compliance.mapping import ComplianceMappingMatrix
        
        # Use existing scoring logic
        mapper = ComplianceMappingMatrix()
        raw_score = mapper._check_gcp_mfa(evidence)
        
        # Extract component details for enhanced result
        component_scores = {}
        risk_factors = []
        remediation_guidance = []
        
        if 'login_challenges' in evidence:
            challenges = evidence['login_challenges']
            
            # 2FA enforcement analysis
            if 'enforcement_state' in challenges:
                enforcement = challenges['enforcement_state']
                if enforcement == 'ENFORCED':
                    component_scores['2fa_enforcement'] = 100.0
                elif enforcement == 'NOT_ENFORCED':
                    component_scores['2fa_enforcement'] = 0.0
                    risk_factors.append("2FA not enforced organization-wide")
                    remediation_guidance.append("Enable organization-wide 2FA enforcement")
            
            # Adoption rate analysis  
            if 'adoption_rate' in challenges:
                adoption = challenges['adoption_rate']
                component_scores['adoption_rate'] = adoption
                if adoption < 80:
                    risk_factors.append(f"Low 2FA adoption rate: {adoption}%")
                    remediation_guidance.append("Implement user training and mandatory 2FA setup")
            
            # Login challenges analysis
            if 'login_mfa_percentage' in challenges:
                login_mfa = challenges['login_mfa_percentage']
                component_scores['login_mfa_usage'] = login_mfa
                if login_mfa < 70:
                    risk_factors.append(f"Low MFA usage in logins: {login_mfa}%")
                    remediation_guidance.append("Review login patterns and enforce MFA for all access")
        
        # Generate detailed explanation
        details = f"GCP 2FA Analysis: "
        if component_scores.get('2fa_enforcement', 0) == 100:
            details += "✅ 2FA enforced, "
        else:
            details += "❌ 2FA not enforced, "
        
        details += f"Adoption: {component_scores.get('adoption_rate', 0):.0f}%, "
        details += f"Login MFA: {component_scores.get('login_mfa_usage', 0):.0f}%"
        
        # Create enhanced result
        score_result = ComplianceScoreResult(
            provider="GCP",
            control="CC6.1-MFA",
            framework="SOC2",
            score=raw_score,
            client_id=client_id,
            timestamp=datetime.now().isoformat(),
            details=details,
            component_scores=component_scores,
            evidence_summary=evidence,
            remediation_guidance=remediation_guidance,
            risk_factors=risk_factors
        )
        
        # Persist to Weaviate
        try:
            bridge.persist_score(score_result)
        except Exception as e:
            logger.error(f"Failed to persist GCP MFA score: {e}")
        
        return score_result
    
    def enhanced_gcp_iam_check(evidence: Dict[str, Any], client_id: str = "default") -> ComplianceScoreResult:
        """Enhanced GCP IAM check with Weaviate persistence"""
        from .compliance.mapping import ComplianceMappingMatrix
        
        mapper = ComplianceMappingMatrix()
        raw_score = mapper._check_gcp_iam_policies(evidence)
        
        component_scores = {}
        risk_factors = []
        remediation_guidance = []
        
        if 'iam_policies' in evidence:
            iam_data = evidence['iam_policies']
            
            # Analyze admin role usage
            if 'admin_roles_count' in iam_data:
                admin_count = iam_data['admin_roles_count']
                total_users = iam_data.get('total_users', 1)
                admin_percentage = (admin_count / total_users) * 100
                
                component_scores['admin_role_usage'] = max(0, 100 - admin_percentage * 2)  # Penalize high admin usage
                
                if admin_percentage > 20:
                    risk_factors.append(f"High admin role usage: {admin_percentage:.1f}%")
                    remediation_guidance.append("Review and reduce admin role assignments")
            
            # Analyze policy complexity
            if 'custom_policies_count' in iam_data:
                custom_count = iam_data['custom_policies_count']
                component_scores['policy_complexity'] = min(100, max(0, 100 - custom_count * 5))
                
                if custom_count > 10:
                    risk_factors.append(f"High number of custom policies: {custom_count}")
                    remediation_guidance.append("Consolidate and simplify custom IAM policies")
        
        details = f"GCP IAM Analysis: Admin roles: {component_scores.get('admin_role_usage', 0):.0f}/100, "
        details += f"Policy complexity: {component_scores.get('policy_complexity', 0):.0f}/100"
        
        score_result = ComplianceScoreResult(
            provider="GCP",
            control="CC6.2-IAM",
            framework="SOC2",
            score=raw_score,
            client_id=client_id,
            timestamp=datetime.now().isoformat(),
            details=details,
            component_scores=component_scores,
            evidence_summary=evidence,
            remediation_guidance=remediation_guidance,
            risk_factors=risk_factors
        )
        
        try:
            bridge.persist_score(score_result)
        except Exception as e:
            logger.error(f"Failed to persist GCP IAM score: {e}")
        
        return score_result
    
    return {
        'enhanced_gcp_mfa_check': enhanced_gcp_mfa_check,
        'enhanced_gcp_iam_check': enhanced_gcp_iam_check
    }

# Example usage and testing
if __name__ == "__main__":
    import os
    
    # Initialize Weaviate client
    weaviate_url = os.getenv('WEAVIATE_URL', 'http://localhost:8080')
    
    try:
        client = weaviate.Client(weaviate_url)
        bridge = WeaviateComplianceBridge(client)
        
        # Test with sample data
        sample_evidence = {
            'login_challenges': {
                'enforcement_state': 'ENFORCED',
                'adoption_rate': 85.0,
                'login_mfa_percentage': 78.0
            }
        }
        
        # Create enhanced scoring functions
        enhanced_functions = create_enhanced_scoring_wrapper(bridge)
        
        # Test enhanced GCP MFA scoring
        result = enhanced_functions['enhanced_gcp_mfa_check'](sample_evidence, "test_client")
        print(f"✅ GCP MFA Score: {result.score}")
        print(f"   Details: {result.details}")
        print(f"   Risk Factors: {result.risk_factors}")
        
        # Test querying
        scores = bridge.query_scores(client_id="test_client", limit=5)
        print(f"✅ Found {len(scores)} historical scores")
        
        # Test trend analysis
        trends = bridge.get_compliance_trends("test_client")
        print(f"✅ Trend analysis: {trends.get('total_controls_analyzed', 0)} controls")
        
        print("🎉 Weaviate compliance bridge test completed successfully!")
        
    except Exception as e:
        print(f"❌ Weaviate compliance bridge test failed: {e}")
        print("   Make sure Weaviate is running at http://localhost:8080")