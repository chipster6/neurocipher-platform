"""
GPU-Accelerated LLM Integration Engine
Dual LLM analysis system with GPU acceleration for advanced security analysis
"""

import asyncio
import json
import logging
import torch
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from datetime import datetime
import numpy as np
from transformers import (
    AutoTokenizer, AutoModelForCausalLM, AutoModelForSequenceClassification,
    pipeline, BitsAndBytesConfig
)
from accelerate import Accelerator
import openai
from concurrent.futures import ThreadPoolExecutor
import gc
from .gpu_detection import GPUDetectionManager, InferenceDevice
from ..vector.weaviate_vector_store import WeaviateVectorStore

logger = logging.getLogger(__name__)

@dataclass
class LLMAnalysisResult:
    """Result from LLM analysis"""
    model_name: str
    analysis_type: str
    confidence: float
    findings: List[str]
    risk_assessment: Dict[str, Any]
    recommendations: List[str]
    processing_time: float
    tokens_used: int

@dataclass
class SecurityContext:
    """Security context for LLM analysis"""
    event_data: Dict[str, Any]
    threat_intelligence: Dict[str, Any]
    compliance_context: Dict[str, Any]
    historical_patterns: List[Dict[str, Any]]
    organization_context: Dict[str, str]

class GPULLMIntegration:
    """
    Advanced GPU-accelerated LLM integration for security analysis
    Supports multiple LLM models running in parallel for comprehensive analysis
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.accelerator = None
        self.primary_model = None
        self.secondary_model = None
        self.classification_model = None
        self.tokenizers = {}
        self.pipelines = {}
        self.device = None
        self.openai_client = None
        self.max_context_length = 4096
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.gpu_manager = GPUDetectionManager(config)
        self.vector_store = None
        self.semantic_search_enabled = True
        
    async def initialize(self, vector_store: Optional[WeaviateVectorStore] = None):
        """Initialize GPU-accelerated LLM models with vector store integration"""
        try:
            logger.info("Initializing GPU-accelerated LLM integration...")
            
            # Initialize GPU detection and optimal configuration
            hardware_info = await self.gpu_manager.detect_hardware()
            optimal_config = hardware_info["optimal_config"]
            
            logger.info(f"Detected optimal device: {optimal_config.device}")
            logger.info(f"Hardware info: {hardware_info}")
            
            # Initialize accelerator for distributed/GPU processing
            self.accelerator = Accelerator()
            self.device = self.gpu_manager.get_torch_device()
            
            logger.info(f"Using device: {self.device}")
            
            # Initialize vector store for semantic search
            if vector_store:
                self.vector_store = vector_store
                logger.info("Vector store connected for semantic search")
            
            # Get model initialization kwargs from GPU manager
            model_kwargs = self.gpu_manager.get_model_kwargs()
            quantization_config = model_kwargs.get("quantization_config")
            
            # Initialize primary LLM (Code Llama for security code analysis)
            await self._initialize_primary_model(quantization_config)
            
            # Initialize secondary LLM (Mistral for threat analysis)
            await self._initialize_secondary_model(quantization_config)
            
            # Initialize classification model for threat categorization
            await self._initialize_classification_model()
            
            # Initialize OpenAI client for commercial model access
            await self._initialize_openai_client()
            
            # Initialize analysis pipelines
            await self._initialize_pipelines()
            
            logger.info("GPU-accelerated LLM integration initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize GPU LLM integration: {e}")
            raise
    
    async def _initialize_primary_model(self, quantization_config):
        """Initialize primary LLM model (Code Llama)"""
        try:
            model_name = self.config.get('primary_model', 'codellama/CodeLlama-7b-Instruct-hf')
            
            logger.info(f"Loading primary model: {model_name}")
            
            self.tokenizers['primary'] = AutoTokenizer.from_pretrained(model_name)
            
            self.primary_model = AutoModelForCausalLM.from_pretrained(
                model_name,
                quantization_config=quantization_config,
                device_map="auto",
                torch_dtype=torch.float16,
                trust_remote_code=True
            )
            
            # Prepare model with accelerator
            self.primary_model = self.accelerator.prepare(self.primary_model)
            
            logger.info("Primary model loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load primary model: {e}")
            # Fallback to smaller model if memory issues
            await self._initialize_fallback_primary_model()
    
    async def _initialize_secondary_model(self, quantization_config):
        """Initialize secondary LLM model (Mistral)"""
        try:
            model_name = self.config.get('secondary_model', 'mistralai/Mistral-7B-Instruct-v0.1')
            
            logger.info(f"Loading secondary model: {model_name}")
            
            self.tokenizers['secondary'] = AutoTokenizer.from_pretrained(model_name)
            
            self.secondary_model = AutoModelForCausalLM.from_pretrained(
                model_name,
                quantization_config=quantization_config,
                device_map="auto",
                torch_dtype=torch.float16,
                trust_remote_code=True
            )
            
            # Prepare model with accelerator
            self.secondary_model = self.accelerator.prepare(self.secondary_model)
            
            logger.info("Secondary model loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load secondary model: {e}")
            # Fallback to smaller model if memory issues
            await self._initialize_fallback_secondary_model()
    
    async def _initialize_classification_model(self):
        """Initialize classification model for threat categorization"""
        try:
            model_name = self.config.get('classification_model', 'microsoft/DialoGPT-medium')
            
            logger.info(f"Loading classification model: {model_name}")
            
            self.classification_model = AutoModelForSequenceClassification.from_pretrained(
                model_name,
                num_labels=5,  # Low, Medium, High, Critical, Unknown
                device_map="auto",
                torch_dtype=torch.float16
            )
            
            self.tokenizers['classification'] = AutoTokenizer.from_pretrained(model_name)
            
            logger.info("Classification model loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load classification model: {e}")
            self.classification_model = None
    
    async def _initialize_openai_client(self):
        """Initialize OpenAI client for commercial model access"""
        try:
            api_key = self.config.get('openai_api_key')
            if api_key:
                self.openai_client = openai.AsyncOpenAI(api_key=api_key)
                logger.info("OpenAI client initialized")
            else:
                logger.info("No OpenAI API key provided, skipping commercial model integration")
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}")
            self.openai_client = None
    
    async def _initialize_pipelines(self):
        """Initialize analysis pipelines"""
        try:
            # Security analysis pipeline
            self.pipelines['security_analysis'] = pipeline(
                "text-generation",
                model=self.primary_model,
                tokenizer=self.tokenizers['primary'],
                device=self.device,
                max_length=self.max_context_length,
                do_sample=True,
                temperature=0.7,
                top_p=0.9
            )
            
            # Threat classification pipeline
            if self.classification_model:
                self.pipelines['threat_classification'] = pipeline(
                    "text-classification",
                    model=self.classification_model,
                    tokenizer=self.tokenizers['classification'],
                    device=self.device
                )
            
            logger.info("Analysis pipelines initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize pipelines: {e}")
            self.pipelines = {}
    
    async def perform_dual_llm_analysis(
        self,
        security_context: SecurityContext,
        analysis_types: List[str] = None
    ) -> Dict[str, LLMAnalysisResult]:
        """
        Perform dual LLM analysis with vector-enhanced semantic search
        
        Args:
            security_context: Security context for analysis
            analysis_types: Types of analysis to perform
            
        Returns:
            Dictionary of analysis results from both models
        """
        if analysis_types is None:
            analysis_types = ['threat_analysis', 'code_analysis', 'compliance_analysis']
        
        try:
            logger.info(f"Starting dual LLM analysis with types: {analysis_types}")
            
            # Enhance security context with vector-based semantic search
            enhanced_context = await self._enhance_context_with_vectors(security_context)
            
            # Prepare analysis tasks
            tasks = []
            
            # Primary model analysis
            for analysis_type in analysis_types:
                if analysis_type in ['code_analysis', 'vulnerability_analysis']:
                    tasks.append(self._analyze_with_primary_model(enhanced_context, analysis_type))
                elif analysis_type in ['threat_analysis', 'compliance_analysis']:
                    tasks.append(self._analyze_with_secondary_model(enhanced_context, analysis_type))
            
            # Add OpenAI analysis if available
            if self.openai_client:
                tasks.append(self._analyze_with_openai(enhanced_context, analysis_types))
            
            # Run all analyses in parallel
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            analysis_results = {}
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Analysis task {i} failed: {result}")
                    continue
                
                if isinstance(result, LLMAnalysisResult):
                    key = f"{result.model_name}_{result.analysis_type}"
                    analysis_results[key] = result
            
            # Perform ensemble analysis with vector correlation
            ensemble_result = await self._perform_ensemble_analysis(analysis_results, enhanced_context)
            analysis_results['ensemble'] = ensemble_result
            
            # Store analysis results in vector database for future correlation
            await self._store_analysis_results_in_vectors(enhanced_context, analysis_results)
            
            logger.info(f"Dual LLM analysis completed with {len(analysis_results)} results")
            return analysis_results
            
        except Exception as e:
            logger.error(f"Dual LLM analysis failed: {e}")
            return {}
    
    async def _analyze_with_primary_model(
        self,
        context: SecurityContext,
        analysis_type: str
    ) -> LLMAnalysisResult:
        """Analyze with primary model (Code Llama)"""
        start_time = datetime.now()
        
        try:
            # Prepare prompt based on analysis type
            prompt = self._prepare_code_analysis_prompt(context, analysis_type)
            
            # Tokenize and generate
            inputs = self.tokenizers['primary'](
                prompt,
                return_tensors="pt",
                max_length=self.max_context_length,
                truncation=True,
                padding=True
            ).to(self.device)
            
            with torch.no_grad():
                outputs = self.primary_model.generate(
                    **inputs,
                    max_new_tokens=512,
                    do_sample=True,
                    temperature=0.7,
                    top_p=0.9,
                    pad_token_id=self.tokenizers['primary'].eos_token_id
                )
            
            # Decode response
            response = self.tokenizers['primary'].decode(
                outputs[0][inputs['input_ids'].shape[1]:],
                skip_special_tokens=True
            )
            
            # Parse analysis results
            findings, risk_assessment, recommendations = self._parse_code_analysis_response(response)
            
            processing_time = (datetime.now() - start_time).total_seconds()
            
            return LLMAnalysisResult(
                model_name="codellama",
                analysis_type=analysis_type,
                confidence=0.85,
                findings=findings,
                risk_assessment=risk_assessment,
                recommendations=recommendations,
                processing_time=processing_time,
                tokens_used=len(inputs['input_ids'][0]) + len(outputs[0])
            )
            
        except Exception as e:
            logger.error(f"Primary model analysis failed: {e}")
            processing_time = (datetime.now() - start_time).total_seconds()
            return LLMAnalysisResult(
                model_name="codellama",
                analysis_type=analysis_type,
                confidence=0.0,
                findings=[f"Analysis failed: {str(e)}"],
                risk_assessment={"error": True},
                recommendations=["Manual review required"],
                processing_time=processing_time,
                tokens_used=0
            )
    
    async def _analyze_with_secondary_model(
        self,
        context: SecurityContext,
        analysis_type: str
    ) -> LLMAnalysisResult:
        """Analyze with secondary model (Mistral)"""
        start_time = datetime.now()
        
        try:
            # Prepare prompt for threat analysis
            prompt = self._prepare_threat_analysis_prompt(context, analysis_type)
            
            # Tokenize and generate
            inputs = self.tokenizers['secondary'](
                prompt,
                return_tensors="pt",
                max_length=self.max_context_length,
                truncation=True,
                padding=True
            ).to(self.device)
            
            with torch.no_grad():
                outputs = self.secondary_model.generate(
                    **inputs,
                    max_new_tokens=512,
                    do_sample=True,
                    temperature=0.7,
                    top_p=0.9,
                    pad_token_id=self.tokenizers['secondary'].eos_token_id
                )
            
            # Decode response
            response = self.tokenizers['secondary'].decode(
                outputs[0][inputs['input_ids'].shape[1]:],
                skip_special_tokens=True
            )
            
            # Parse analysis results
            findings, risk_assessment, recommendations = self._parse_threat_analysis_response(response)
            
            processing_time = (datetime.now() - start_time).total_seconds()
            
            return LLMAnalysisResult(
                model_name="mistral",
                analysis_type=analysis_type,
                confidence=0.88,
                findings=findings,
                risk_assessment=risk_assessment,
                recommendations=recommendations,
                processing_time=processing_time,
                tokens_used=len(inputs['input_ids'][0]) + len(outputs[0])
            )
            
        except Exception as e:
            logger.error(f"Secondary model analysis failed: {e}")
            processing_time = (datetime.now() - start_time).total_seconds()
            return LLMAnalysisResult(
                model_name="mistral",
                analysis_type=analysis_type,
                confidence=0.0,
                findings=[f"Analysis failed: {str(e)}"],
                risk_assessment={"error": True},
                recommendations=["Manual review required"],
                processing_time=processing_time,
                tokens_used=0
            )
    
    async def _analyze_with_openai(
        self,
        context: SecurityContext,
        analysis_types: List[str]
    ) -> LLMAnalysisResult:
        """Analyze with OpenAI GPT model"""
        start_time = datetime.now()
        
        try:
            if not self.openai_client:
                raise Exception("OpenAI client not initialized")
            
            # Prepare comprehensive prompt
            prompt = self._prepare_openai_prompt(context, analysis_types)
            
            response = await self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are an expert cybersecurity analyst. Provide detailed security analysis."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.7
            )
            
            content = response.choices[0].message.content
            
            # Parse OpenAI response
            findings, risk_assessment, recommendations = self._parse_openai_response(content)
            
            processing_time = (datetime.now() - start_time).total_seconds()
            
            return LLMAnalysisResult(
                model_name="gpt-4",
                analysis_type="comprehensive",
                confidence=0.92,
                findings=findings,
                risk_assessment=risk_assessment,
                recommendations=recommendations,
                processing_time=processing_time,
                tokens_used=response.usage.total_tokens
            )
            
        except Exception as e:
            logger.error(f"OpenAI analysis failed: {e}")
            processing_time = (datetime.now() - start_time).total_seconds()
            return LLMAnalysisResult(
                model_name="gpt-4",
                analysis_type="comprehensive",
                confidence=0.0,
                findings=[f"Analysis failed: {str(e)}"],
                risk_assessment={"error": True},
                recommendations=["Manual review required"],
                processing_time=processing_time,
                tokens_used=0
            )
    
    def _prepare_code_analysis_prompt(self, context: SecurityContext, analysis_type: str) -> str:
        """Prepare prompt for code analysis"""
        event_summary = json.dumps(context.event_data, indent=2)[:1000]
        
        prompt = f"""
As a cybersecurity expert, analyze the following security event data for vulnerabilities and code-related security issues:

EVENT DATA:
{event_summary}

ANALYSIS TYPE: {analysis_type}

Please provide:
1. Security vulnerabilities identified
2. Code-related security issues
3. Risk level assessment (Low/Medium/High/Critical)
4. Specific recommendations for remediation

Focus on:
- Code injection vulnerabilities
- Authentication bypasses
- Authorization flaws
- Input validation issues
- Insecure configurations
"""
        return prompt
    
    def _prepare_threat_analysis_prompt(self, context: SecurityContext, analysis_type: str) -> str:
        """Prepare prompt for threat analysis"""
        event_summary = json.dumps(context.event_data, indent=2)[:1000]
        threat_intel = json.dumps(context.threat_intelligence, indent=2)[:500]
        
        prompt = f"""
As a threat intelligence analyst, analyze the following security data for threat patterns and indicators:

SECURITY EVENT:
{event_summary}

THREAT INTELLIGENCE CONTEXT:
{threat_intel}

ANALYSIS TYPE: {analysis_type}

Please analyze:
1. Threat actor patterns and TTPs
2. Attack progression indicators
3. MITRE ATT&CK technique mapping
4. Threat severity and urgency
5. Incident response recommendations

Provide detailed threat assessment with actionable intelligence.
"""
        return prompt
    
    def _prepare_openai_prompt(self, context: SecurityContext, analysis_types: List[str]) -> str:
        """Prepare comprehensive prompt for OpenAI"""
        return f"""
Perform comprehensive cybersecurity analysis on the following data:

SECURITY EVENTS: {json.dumps(context.event_data, indent=2)[:800]}
THREAT INTELLIGENCE: {json.dumps(context.threat_intelligence, indent=2)[:400]}
COMPLIANCE CONTEXT: {json.dumps(context.compliance_context, indent=2)[:400]}

Analysis Types Requested: {', '.join(analysis_types)}

Provide:
1. Executive summary of security posture
2. Critical findings and vulnerabilities
3. Threat actor attribution if applicable
4. Compliance implications
5. Prioritized remediation roadmap
6. Strategic security recommendations

Format as structured analysis with clear risk ratings.
"""
    
    def _parse_code_analysis_response(self, response: str) -> tuple:
        """Parse code analysis response"""
        findings = []
        recommendations = []
        risk_level = "Medium"
        
        # Simple parsing - in production, use more sophisticated NLP
        lines = response.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if 'vulnerability' in line.lower() or 'issue' in line.lower():
                findings.append(line)
            elif 'recommendation' in line.lower() or 'remediation' in line.lower():
                recommendations.append(line)
            elif any(risk in line.lower() for risk in ['critical', 'high', 'medium', 'low']):
                if 'critical' in line.lower():
                    risk_level = "Critical"
                elif 'high' in line.lower():
                    risk_level = "High"
                elif 'low' in line.lower():
                    risk_level = "Low"
        
        risk_assessment = {
            "risk_level": risk_level,
            "technical_impact": "High" if risk_level in ["Critical", "High"] else "Medium",
            "business_impact": "Medium"
        }
        
        return findings, risk_assessment, recommendations
    
    def _parse_threat_analysis_response(self, response: str) -> tuple:
        """Parse threat analysis response"""
        findings = []
        recommendations = []
        
        # Extract findings and recommendations
        if "findings" in response.lower():
            findings = [line.strip() for line in response.split('\n') if line.strip() and not line.startswith('#')]
        
        if "recommendation" in response.lower():
            recommendations = [line.strip() for line in response.split('\n') if 'recommend' in line.lower()]
        
        risk_assessment = {
            "threat_level": "High",
            "confidence": "Medium",
            "attack_complexity": "Medium"
        }
        
        return findings, risk_assessment, recommendations
    
    def _parse_openai_response(self, response: str) -> tuple:
        """Parse OpenAI response"""
        findings = []
        recommendations = []
        
        # More sophisticated parsing for structured OpenAI responses
        sections = response.split('\n\n')
        
        for section in sections:
            if any(keyword in section.lower() for keyword in ['finding', 'vulnerability', 'risk']):
                findings.append(section.strip())
            elif any(keyword in section.lower() for keyword in ['recommendation', 'remediation', 'action']):
                recommendations.append(section.strip())
        
        risk_assessment = {
            "overall_risk": "High",
            "confidence": "High",
            "urgency": "Medium"
        }
        
        return findings, risk_assessment, recommendations
    
    async def _enhance_context_with_vectors(self, context: SecurityContext) -> SecurityContext:
        """Enhance security context using vector-based semantic search"""
        try:
            if not self.vector_store or not self.semantic_search_enabled:
                logger.info("Vector enhancement skipped - vector store not available")
                return context
            
            logger.info("Enhancing context with vector-based semantic search...")
            
            # Extract searchable text from event data
            search_text = self._extract_search_text_from_context(context)
            
            # Perform semantic search for similar threats
            similar_threats = await self.vector_store.semantic_search(
                query=search_text,
                collection_name="threat_intelligence",
                limit=5,
                where_filter={"source": {"operator": "Equal", "valueText": "threat_db"}}
            )
            
            # Perform semantic search for similar compliance patterns
            similar_compliance = await self.vector_store.semantic_search(
                query=search_text,
                collection_name="compliance_patterns",
                limit=3,
                where_filter={"status": {"operator": "Equal", "valueText": "active"}}
            )
            
            # Perform semantic search for historical patterns
            historical_patterns = await self.vector_store.semantic_search(
                query=search_text,
                collection_name="security_events",
                limit=10,
                where_filter={"tenant_id": {"operator": "Equal", "valueText": context.organization_context.get("tenant_id", "")}}
            )
            
            # Create enhanced context with vector search results
            enhanced_context = SecurityContext(
                event_data=context.event_data,
                threat_intelligence={
                    **context.threat_intelligence,
                    "vector_similar_threats": [result.get("metadata", {}) for result in similar_threats],
                    "semantic_threat_correlation": True
                },
                compliance_context={
                    **context.compliance_context,
                    "vector_similar_compliance": [result.get("metadata", {}) for result in similar_compliance],
                    "compliance_patterns_found": len(similar_compliance)
                },
                historical_patterns=[
                    *context.historical_patterns,
                    *[result.get("metadata", {}) for result in historical_patterns]
                ],
                organization_context={
                    **context.organization_context,
                    "vector_enhanced": True,
                    "similar_incidents_count": len(historical_patterns)
                }
            )
            
            logger.info(f"Context enhanced with {len(similar_threats)} threat correlations, "
                       f"{len(similar_compliance)} compliance patterns, "
                       f"{len(historical_patterns)} historical patterns")
            
            return enhanced_context
            
        except Exception as e:
            logger.error(f"Vector context enhancement failed: {e}")
            return context
    
    def _extract_search_text_from_context(self, context: SecurityContext) -> str:
        """Extract searchable text from security context"""
        search_components = []
        
        # Extract from event data
        if context.event_data:
            event_text = json.dumps(context.event_data)
            search_components.append(event_text[:500])  # Limit to 500 chars
        
        # Extract from threat intelligence
        if context.threat_intelligence:
            threat_text = " ".join([
                str(v) for v in context.threat_intelligence.values() 
                if isinstance(v, (str, int, float))
            ])
            search_components.append(threat_text[:300])
        
        # Extract from compliance context
        if context.compliance_context:
            compliance_text = " ".join([
                str(v) for v in context.compliance_context.values()
                if isinstance(v, (str, int, float))
            ])
            search_components.append(compliance_text[:200])
        
        return " ".join(search_components)
    
    async def _store_analysis_results_in_vectors(
        self, 
        context: SecurityContext, 
        analysis_results: Dict[str, LLMAnalysisResult]
    ) -> bool:
        """Store analysis results in vector database for future semantic correlation"""
        try:
            if not self.vector_store or not self.semantic_search_enabled:
                logger.debug("Vector storage skipped - vector store not available")
                return False
            
            logger.info("Storing analysis results in vector database...")
            
            # Create a comprehensive analysis summary for vectorization
            ensemble_result = analysis_results.get('ensemble')
            if not ensemble_result:
                logger.warning("No ensemble result available for vector storage")
                return False
            
            # Prepare vector document
            vector_document = {
                "content": self._create_analysis_summary_text(context, ensemble_result),
                "metadata": {
                    "analysis_id": f"analysis_{datetime.now().timestamp()}",
                    "tenant_id": context.organization_context.get("tenant_id", "unknown"),
                    "timestamp": datetime.now().isoformat(),
                    "risk_level": ensemble_result.risk_assessment.get("combined_risk", "Medium"),
                    "confidence": ensemble_result.confidence,
                    "model_count": len(analysis_results) - 1,  # Exclude ensemble from count
                    "analysis_types": [result.analysis_type for result in analysis_results.values()],
                    "findings_count": len(ensemble_result.findings),
                    "recommendations_count": len(ensemble_result.recommendations),
                    "source": "llm_analysis",
                    "event_type": context.event_data.get("event_type", "security_event")
                }
            }
            
            # Store in security events collection for historical pattern matching
            await self.vector_store.add_documents(
                documents=[vector_document],
                collection_name="security_events"
            )
            
            # Store threat intelligence if high confidence and critical findings
            if ensemble_result.confidence > 0.8 and "Critical" in str(ensemble_result.risk_assessment):
                threat_document = {
                    "content": f"High-confidence threat analysis: {' '.join(ensemble_result.findings[:3])}",
                    "metadata": {
                        **vector_document["metadata"],
                        "threat_level": "high",
                        "validated": True,
                        "source": "threat_db"
                    }
                }
                
                await self.vector_store.add_documents(
                    documents=[threat_document],
                    collection_name="threat_intelligence"
                )
            
            logger.info("Analysis results successfully stored in vector database")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store analysis results in vector database: {e}")
            return False
    
    def _create_analysis_summary_text(self, context: SecurityContext, result: LLMAnalysisResult) -> str:
        """Create searchable text summary of analysis results"""
        summary_parts = []
        
        # Add event context
        if context.event_data:
            event_summary = f"Security event: {context.event_data.get('event_type', 'unknown')}"
            summary_parts.append(event_summary)
        
        # Add findings
        if result.findings:
            findings_text = "Findings: " + " | ".join(result.findings[:5])  # Top 5 findings
            summary_parts.append(findings_text)
        
        # Add risk assessment
        if result.risk_assessment:
            risk_text = f"Risk: {result.risk_assessment.get('combined_risk', 'Unknown')}"
            summary_parts.append(risk_text)
        
        # Add recommendations
        if result.recommendations:
            rec_text = "Recommendations: " + " | ".join(result.recommendations[:3])  # Top 3 recommendations
            summary_parts.append(rec_text)
        
        # Add threat intelligence context
        if context.threat_intelligence:
            threat_context = f"Threat context: {list(context.threat_intelligence.keys())}"
            summary_parts.append(threat_context)
        
        return " ".join(summary_parts)
    
    async def _perform_ensemble_analysis(
        self,
        results: Dict[str, LLMAnalysisResult],
        enhanced_context: Optional[SecurityContext] = None
    ) -> LLMAnalysisResult:
        """Perform ensemble analysis combining all model results"""
        start_time = datetime.now()
        
        try:
            # Combine findings from all models
            all_findings = []
            all_recommendations = []
            confidence_scores = []
            
            for result in results.values():
                all_findings.extend(result.findings)
                all_recommendations.extend(result.recommendations)
                confidence_scores.append(result.confidence)
            
            # Calculate ensemble confidence
            ensemble_confidence = np.mean(confidence_scores) if confidence_scores else 0.0
            
            # Deduplicate and rank findings
            unique_findings = list(set(all_findings))[:10]  # Top 10 unique findings
            unique_recommendations = list(set(all_recommendations))[:8]  # Top 8 recommendations
            
            # Create ensemble risk assessment
            risk_assessment = {
                "ensemble_confidence": ensemble_confidence,
                "model_consensus": len([r for r in results.values() if r.confidence > 0.7]),
                "total_models": len(results),
                "combined_risk": "High" if ensemble_confidence > 0.8 else "Medium"
            }
            
            processing_time = (datetime.now() - start_time).total_seconds()
            
            return LLMAnalysisResult(
                model_name="ensemble",
                analysis_type="comprehensive",
                confidence=ensemble_confidence,
                findings=unique_findings,
                risk_assessment=risk_assessment,
                recommendations=unique_recommendations,
                processing_time=processing_time,
                tokens_used=sum(r.tokens_used for r in results.values())
            )
            
        except Exception as e:
            logger.error(f"Ensemble analysis failed: {e}")
            processing_time = (datetime.now() - start_time).total_seconds()
            return LLMAnalysisResult(
                model_name="ensemble",
                analysis_type="comprehensive",
                confidence=0.0,
                findings=["Ensemble analysis failed"],
                risk_assessment={"error": True},
                recommendations=["Manual review of individual model results required"],
                processing_time=processing_time,
                tokens_used=0
            )
    
    async def _initialize_fallback_primary_model(self):
        """Initialize fallback primary model if main model fails"""
        try:
            logger.info("Initializing fallback primary model...")
            model_name = "microsoft/DialoGPT-small"
            
            self.tokenizers['primary'] = AutoTokenizer.from_pretrained(model_name)
            self.primary_model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16,
                device_map="auto"
            )
            
            logger.info("Fallback primary model initialized")
            
        except Exception as e:
            logger.error(f"Fallback primary model initialization failed: {e}")
            self.primary_model = None
    
    async def _initialize_fallback_secondary_model(self):
        """Initialize fallback secondary model if main model fails"""
        try:
            logger.info("Initializing fallback secondary model...")
            model_name = "microsoft/DialoGPT-small"
            
            self.tokenizers['secondary'] = AutoTokenizer.from_pretrained(model_name)
            self.secondary_model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16,
                device_map="auto"
            )
            
            logger.info("Fallback secondary model initialized")
            
        except Exception as e:
            logger.error(f"Fallback secondary model initialization failed: {e}")
            self.secondary_model = None
    
    async def cleanup(self):
        """Clean up GPU resources"""
        try:
            # Clear CUDA cache
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
            
            # Delete models to free memory
            del self.primary_model
            del self.secondary_model
            del self.classification_model
            
            # Force garbage collection
            gc.collect()
            
            logger.info("GPU LLM integration cleanup completed")
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get status of all loaded models"""
        return {
            "primary_model_loaded": self.primary_model is not None,
            "secondary_model_loaded": self.secondary_model is not None,
            "classification_model_loaded": self.classification_model is not None,
            "openai_available": self.openai_client is not None,
            "gpu_available": torch.cuda.is_available(),
            "device": str(self.device) if self.device else "cpu",
            "models_in_memory": len([m for m in [self.primary_model, self.secondary_model, self.classification_model] if m is not None])
        }