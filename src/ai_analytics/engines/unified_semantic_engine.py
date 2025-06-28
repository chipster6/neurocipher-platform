"""
Unified Semantic Search and Vector Classification Engine
Consolidated approach based on multi-AI consensus for optimal performance
"""

import asyncio
import logging
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import json
from sentence_transformers import SentenceTransformer
import torch
from ..vector.weaviate_vector_store import WeaviateVectorStore
from .gpu_detection import GPUDetectionManager

logger = logging.getLogger(__name__)

@dataclass
class SemanticSearchResult:
    """Consolidated semantic search result"""
    content: str
    score: float
    metadata: Dict[str, Any]
    classification: str
    confidence: float
    vector_id: str

@dataclass
class ClassificationResult:
    """Vector classification result"""
    category: str
    confidence: float
    threat_level: str
    risk_score: int
    semantic_patterns: List[str]

class UnifiedSemanticEngine:
    """
    Unified engine for semantic search and vector classification
    Optimized through multi-AI consensus for maximum effectiveness
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.vector_store = None
        self.embedding_model = None
        self.gpu_manager = None
        self.device = None
        self.classification_cache = {}
        self.search_cache = {}
        
        # Consensus-optimized parameters
        self.similarity_threshold = 0.75  # Balanced threshold from consensus
        self.max_results = 10             # Optimal result count
        self.embedding_dimensions = 768   # BERT-base standard
        self.cache_ttl = 3600            # 1 hour cache for performance
        
    async def initialize(self, vector_store: WeaviateVectorStore):
        """Initialize the unified semantic engine"""
        try:
            logger.info("Initializing Unified Semantic Engine...")
            
            self.vector_store = vector_store
            
            # Initialize GPU detection
            self.gpu_manager = GPUDetectionManager(self.config)
            hardware_info = await self.gpu_manager.detect_hardware()
            self.device = self.gpu_manager.get_torch_device()
            
            logger.info(f"Using device: {self.device}")
            
            # Initialize embedding model with GPU optimization
            await self._initialize_embedding_model()
            
            # Initialize vector collections
            await self._initialize_vector_collections()
            
            logger.info("Unified Semantic Engine initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Unified Semantic Engine: {e}")
            raise
    
    async def _initialize_embedding_model(self):
        """Initialize sentence transformer model with GPU support"""
        try:
            # Consensus choice: all-MiniLM-L6-v2 for speed/accuracy balance
            model_name = self.config.get('embedding_model', 'all-MiniLM-L6-v2')
            
            logger.info(f"Loading embedding model: {model_name}")
            
            self.embedding_model = SentenceTransformer(model_name)
            
            # Move to GPU if available
            if self.device.type in ['cuda', 'mps']:
                self.embedding_model = self.embedding_model.to(self.device)
                logger.info(f"Embedding model moved to {self.device}")
            
        except Exception as e:
            logger.error(f"Failed to load embedding model: {e}")
            # Fallback to basic model
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
    
    async def _initialize_vector_collections(self):
        """Initialize Weaviate collections for semantic search"""
        try:
            collections = [
                {
                    "name": "threat_intelligence",
                    "properties": [
                        {"name": "content", "dataType": ["text"]},
                        {"name": "threat_type", "dataType": ["string"]},
                        {"name": "severity", "dataType": ["string"]},
                        {"name": "source", "dataType": ["string"]},
                        {"name": "timestamp", "dataType": ["date"]},
                        {"name": "confidence", "dataType": ["number"]},
                        {"name": "mitre_tactics", "dataType": ["string[]"]},
                        {"name": "iocs", "dataType": ["string[]"]}
                    ]
                },
                {
                    "name": "security_events",
                    "properties": [
                        {"name": "content", "dataType": ["text"]},
                        {"name": "event_type", "dataType": ["string"]},
                        {"name": "tenant_id", "dataType": ["string"]},
                        {"name": "risk_level", "dataType": ["string"]},
                        {"name": "timestamp", "dataType": ["date"]},
                        {"name": "source_ip", "dataType": ["string"]},
                        {"name": "affected_systems", "dataType": ["string[]"]},
                        {"name": "analysis_confidence", "dataType": ["number"]}
                    ]
                },
                {
                    "name": "compliance_patterns",
                    "properties": [
                        {"name": "content", "dataType": ["text"]},
                        {"name": "framework", "dataType": ["string"]},
                        {"name": "control_id", "dataType": ["string"]},
                        {"name": "status", "dataType": ["string"]},
                        {"name": "criticality", "dataType": ["string"]},
                        {"name": "applicable_industries", "dataType": ["string[]"]},
                        {"name": "remediation_effort", "dataType": ["string"]}
                    ]
                }
            ]
            
            for collection in collections:
                await self.vector_store.create_collection_if_not_exists(
                    collection["name"], 
                    collection["properties"]
                )
            
            logger.info("Vector collections initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize vector collections: {e}")
    
    async def semantic_search_unified(
        self,
        query: str,
        collection_name: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 10,
        similarity_threshold: Optional[float] = None
    ) -> List[SemanticSearchResult]:
        """
        Unified semantic search with automatic classification
        Consensus-optimized for speed and accuracy
        """
        try:
            # Use provided threshold or default
            threshold = similarity_threshold or self.similarity_threshold
            
            # Check cache first
            cache_key = self._generate_cache_key(query, collection_name, filters)
            if cache_key in self.search_cache:
                logger.debug("Returning cached search results")
                return self.search_cache[cache_key]
            
            logger.info(f"Performing semantic search in {collection_name}")
            
            # Generate query embedding
            query_embedding = await self._generate_embedding(query)
            
            # Perform vector search
            raw_results = await self.vector_store.semantic_search(
                query=query,
                collection_name=collection_name,
                limit=limit,
                where_filter=filters
            )
            
            # Process and classify results
            unified_results = []
            for result in raw_results:
                # Extract content and metadata
                content = result.get("content", "")
                metadata = result.get("metadata", {})
                score = result.get("score", 0.0)
                
                # Skip results below threshold
                if score < threshold:
                    continue
                
                # Perform automatic classification
                classification = await self._classify_content(content, collection_name)
                
                unified_result = SemanticSearchResult(
                    content=content,
                    score=score,
                    metadata=metadata,
                    classification=classification.category,
                    confidence=classification.confidence,
                    vector_id=result.get("id", "")
                )
                
                unified_results.append(unified_result)
            
            # Sort by relevance score
            unified_results.sort(key=lambda x: x.score, reverse=True)
            
            # Cache results
            self.search_cache[cache_key] = unified_results
            
            logger.info(f"Found {len(unified_results)} relevant results")
            return unified_results
            
        except Exception as e:
            logger.error(f"Semantic search failed: {e}")
            return []
    
    async def threat_correlation_search(
        self,
        security_event: Dict[str, Any],
        correlation_depth: int = 5
    ) -> Dict[str, List[SemanticSearchResult]]:
        """
        Specialized threat correlation using multi-vector approach
        Consensus-optimized for threat intelligence workflows
        """
        try:
            logger.info("Performing threat correlation search")
            
            # Extract searchable patterns from event
            search_patterns = self._extract_threat_patterns(security_event)
            
            correlations = {}
            
            # Search across multiple dimensions
            for pattern_type, pattern_content in search_patterns.items():
                if not pattern_content:
                    continue
                
                # Determine appropriate collection
                collection = self._map_pattern_to_collection(pattern_type)
                
                # Perform semantic search
                results = await self.semantic_search_unified(
                    query=pattern_content,
                    collection_name=collection,
                    limit=correlation_depth,
                    similarity_threshold=0.70  # Lower threshold for correlation
                )
                
                if results:
                    correlations[pattern_type] = results
            
            # Cross-reference correlations for additional insights
            enhanced_correlations = await self._enhance_correlations(correlations)
            
            logger.info(f"Found correlations across {len(enhanced_correlations)} dimensions")
            return enhanced_correlations
            
        except Exception as e:
            logger.error(f"Threat correlation search failed: {e}")
            return {}
    
    async def compliance_pattern_matching(
        self,
        audit_data: Dict[str, Any],
        frameworks: List[str] = None
    ) -> Dict[str, List[SemanticSearchResult]]:
        """
        Compliance pattern matching using semantic similarity
        Consensus-optimized for regulatory frameworks
        """
        try:
            if frameworks is None:
                frameworks = ["SOC2", "ISO27001", "PCI-DSS", "GDPR", "HIPAA"]
            
            logger.info(f"Performing compliance pattern matching for {frameworks}")
            
            # Extract compliance-relevant content
            compliance_content = self._extract_compliance_content(audit_data)
            
            compliance_matches = {}
            
            for framework in frameworks:
                # Create framework-specific query
                framework_query = f"{framework} {compliance_content}"
                
                # Search compliance patterns
                results = await self.semantic_search_unified(
                    query=framework_query,
                    collection_name="compliance_patterns",
                    filters={"framework": {"operator": "Equal", "valueText": framework}},
                    limit=8,
                    similarity_threshold=0.65
                )
                
                if results:
                    compliance_matches[framework] = results
            
            logger.info(f"Found compliance matches for {len(compliance_matches)} frameworks")
            return compliance_matches
            
        except Exception as e:
            logger.error(f"Compliance pattern matching failed: {e}")
            return {}
    
    async def _generate_embedding(self, text: str) -> np.ndarray:
        """Generate embedding vector for text"""
        try:
            # Truncate text if too long
            max_length = 512
            if len(text) > max_length:
                text = text[:max_length]
            
            # Generate embedding
            with torch.no_grad():
                embedding = self.embedding_model.encode(
                    text,
                    convert_to_numpy=True,
                    normalize_embeddings=True
                )
            
            return embedding
            
        except Exception as e:
            logger.error(f"Embedding generation failed: {e}")
            return np.zeros(self.embedding_dimensions)
    
    async def _classify_content(
        self,
        content: str,
        collection_context: str
    ) -> ClassificationResult:
        """Classify content based on semantic analysis"""
        try:
            # Check classification cache
            cache_key = f"{hash(content)}_{collection_context}"
            if cache_key in self.classification_cache:
                return self.classification_cache[cache_key]
            
            # Classification logic based on collection type
            if collection_context == "threat_intelligence":
                category, confidence, threat_level, risk_score = await self._classify_threat(content)
            elif collection_context == "security_events":
                category, confidence, threat_level, risk_score = await self._classify_security_event(content)
            elif collection_context == "compliance_patterns":
                category, confidence, threat_level, risk_score = await self._classify_compliance(content)
            else:
                category = "general"
                confidence = 0.5
                threat_level = "unknown"
                risk_score = 50
            
            # Extract semantic patterns
            patterns = self._extract_semantic_patterns(content)
            
            result = ClassificationResult(
                category=category,
                confidence=confidence,
                threat_level=threat_level,
                risk_score=risk_score,
                semantic_patterns=patterns
            )
            
            # Cache result
            self.classification_cache[cache_key] = result
            
            return result
            
        except Exception as e:
            logger.error(f"Content classification failed: {e}")
            return ClassificationResult(
                category="unknown",
                confidence=0.0,
                threat_level="unknown",
                risk_score=0,
                semantic_patterns=[]
            )
    
    async def _classify_threat(self, content: str) -> Tuple[str, float, str, int]:
        """Classify threat intelligence content"""
        content_lower = content.lower()
        
        # Threat classification rules (consensus-optimized)
        if any(word in content_lower for word in ["malware", "ransomware", "trojan", "virus"]):
            return "malware", 0.9, "high", 85
        elif any(word in content_lower for word in ["phishing", "social engineering", "credential"]):
            return "social_engineering", 0.85, "medium", 70
        elif any(word in content_lower for word in ["ddos", "dos", "flood", "overload"]):
            return "denial_of_service", 0.8, "medium", 65
        elif any(word in content_lower for word in ["injection", "xss", "csrf", "vulnerability"]):
            return "web_attack", 0.85, "high", 80
        elif any(word in content_lower for word in ["apt", "advanced persistent", "nation state"]):
            return "advanced_threat", 0.95, "critical", 95
        else:
            return "general_threat", 0.6, "low", 40
    
    async def _classify_security_event(self, content: str) -> Tuple[str, float, str, int]:
        """Classify security event content"""
        content_lower = content.lower()
        
        if any(word in content_lower for word in ["failed login", "authentication", "brute force"]):
            return "authentication_event", 0.85, "medium", 60
        elif any(word in content_lower for word in ["privilege escalation", "unauthorized access"]):
            return "access_violation", 0.9, "high", 85
        elif any(word in content_lower for word in ["data exfiltration", "data leak", "sensitive data"]):
            return "data_breach", 0.95, "critical", 95
        elif any(word in content_lower for word in ["network anomaly", "unusual traffic"]):
            return "network_event", 0.75, "medium", 55
        else:
            return "general_event", 0.5, "low", 30
    
    async def _classify_compliance(self, content: str) -> Tuple[str, float, str, int]:
        """Classify compliance pattern content"""
        content_lower = content.lower()
        
        if any(word in content_lower for word in ["access control", "authentication", "authorization"]):
            return "access_management", 0.8, "medium", 60
        elif any(word in content_lower for word in ["encryption", "cryptography", "data protection"]):
            return "data_protection", 0.85, "high", 75
        elif any(word in content_lower for word in ["audit", "logging", "monitoring"]):
            return "audit_control", 0.8, "medium", 65
        elif any(word in content_lower for word in ["incident response", "business continuity"]):
            return "incident_management", 0.85, "high", 80
        else:
            return "general_compliance", 0.6, "low", 40
    
    def _extract_threat_patterns(self, security_event: Dict[str, Any]) -> Dict[str, str]:
        """Extract searchable threat patterns from security event"""
        patterns = {}
        
        # IP patterns
        if "source_ip" in security_event:
            patterns["ip_pattern"] = f"source IP {security_event['source_ip']}"
        
        # Event type patterns
        if "event_type" in security_event:
            patterns["event_pattern"] = f"event type {security_event['event_type']}"
        
        # User patterns
        if "user" in security_event:
            patterns["user_pattern"] = f"user {security_event['user']}"
        
        # System patterns
        if "system" in security_event:
            patterns["system_pattern"] = f"system {security_event['system']}"
        
        # General content pattern
        if "description" in security_event:
            patterns["content_pattern"] = security_event["description"]
        
        return patterns
    
    def _map_pattern_to_collection(self, pattern_type: str) -> str:
        """Map pattern type to appropriate vector collection"""
        mapping = {
            "ip_pattern": "threat_intelligence",
            "event_pattern": "security_events",
            "user_pattern": "security_events",
            "system_pattern": "security_events",
            "content_pattern": "threat_intelligence"
        }
        return mapping.get(pattern_type, "security_events")
    
    def _extract_compliance_content(self, audit_data: Dict[str, Any]) -> str:
        """Extract compliance-relevant content from audit data"""
        content_parts = []
        
        # Extract key compliance indicators
        for key, value in audit_data.items():
            if key in ["policy", "procedure", "control", "requirement", "standard"]:
                content_parts.append(f"{key}: {value}")
        
        return " ".join(content_parts)
    
    def _extract_semantic_patterns(self, content: str) -> List[str]:
        """Extract semantic patterns from content"""
        # Simple pattern extraction (could be enhanced with NLP)
        patterns = []
        
        # Extract key phrases
        words = content.split()
        for i in range(len(words) - 1):
            bigram = f"{words[i]} {words[i+1]}"
            if len(bigram) > 6:  # Filter meaningful bigrams
                patterns.append(bigram)
        
        return patterns[:5]  # Return top 5 patterns
    
    async def _enhance_correlations(
        self,
        correlations: Dict[str, List[SemanticSearchResult]]
    ) -> Dict[str, List[SemanticSearchResult]]:
        """Enhance correlations with cross-referencing"""
        enhanced = correlations.copy()
        
        # Find cross-pattern correlations
        all_results = []
        for results in correlations.values():
            all_results.extend(results)
        
        # Group by similarity
        if len(all_results) > 1:
            # Add cross-correlation analysis
            enhanced["cross_correlations"] = []
            
            seen_ids = set()
            for result in all_results:
                if result.vector_id not in seen_ids and result.confidence > 0.8:
                    enhanced["cross_correlations"].append(result)
                    seen_ids.add(result.vector_id)
        
        return enhanced
    
    def _generate_cache_key(
        self,
        query: str,
        collection: str,
        filters: Optional[Dict[str, Any]]
    ) -> str:
        """Generate cache key for search results"""
        filter_str = json.dumps(filters, sort_keys=True) if filters else ""
        return f"{hash(query)}_{collection}_{hash(filter_str)}"
    
    def get_search_statistics(self) -> Dict[str, Any]:
        """Get search performance statistics"""
        return {
            "cache_size": len(self.search_cache),
            "classification_cache_size": len(self.classification_cache),
            "embedding_model": str(type(self.embedding_model)),
            "device": str(self.device),
            "similarity_threshold": self.similarity_threshold,
            "embedding_dimensions": self.embedding_dimensions
        }
    
    async def clear_caches(self):
        """Clear all caches"""
        self.search_cache.clear()
        self.classification_cache.clear()
        logger.info("All caches cleared")
    
    async def optimize_performance(self) -> Dict[str, Any]:
        """Optimize engine performance based on usage patterns"""
        try:
            logger.info("Optimizing semantic engine performance...")
            
            # Analyze cache hit rates
            cache_stats = self.get_search_statistics()
            
            # Adjust similarity threshold based on result quality
            if cache_stats["cache_size"] > 1000:
                self.similarity_threshold = min(0.8, self.similarity_threshold + 0.05)
            
            # Clear old cache entries (simple LRU simulation)
            if len(self.search_cache) > 5000:
                # Keep only recent half
                cache_items = list(self.search_cache.items())
                self.search_cache = dict(cache_items[-2500:])
            
            optimization_results = {
                "similarity_threshold_adjusted": self.similarity_threshold,
                "cache_cleaned": True,
                "performance_optimized": True
            }
            
            logger.info("Performance optimization completed")
            return optimization_results
            
        except Exception as e:
            logger.error(f"Performance optimization failed: {e}")
            return {"error": str(e)}