"""
Post-Quantum Vector Store Security
Enhanced Weaviate vector operations with quantum-resistant encryption
Secures vector embeddings, metadata, and search operations against quantum attacks
"""

import os
import json
import logging
import asyncio
from typing import Dict, Any, Optional, List, Union, Tuple
from datetime import datetime
import uuid
import numpy as np

from ..security.post_quantum_crypto import get_pq_suite, pq_encrypt, pq_decrypt, pq_sign_data, pq_verify_data

logger = logging.getLogger(__name__)

try:
    import weaviate
    from weaviate.auth import AuthApiKey
    WEAVIATE_AVAILABLE = True
except ImportError:
    logger.warning("Weaviate not available - vector store functionality limited")
    WEAVIATE_AVAILABLE = False


class PostQuantumVectorStore:
    """
    Quantum-Resistant Vector Store Implementation
    Provides secure vector storage with post-quantum encryption for embeddings and metadata
    """
    
    def __init__(self, weaviate_url: str = None, api_key: str = None, enable_pq_crypto: bool = True):
        self.weaviate_url = weaviate_url or os.getenv('WEAVIATE_URL', 'http://localhost:8080')
        self.api_key = api_key or os.getenv('WEAVIATE_API_KEY')
        self.enable_pq_crypto = enable_pq_crypto
        self.pq_suite = None
        self.client = None
        
        # Initialize post-quantum crypto suite
        if self.enable_pq_crypto:
            try:
                self.pq_suite = get_pq_suite()
                logger.info("Post-quantum cryptography enabled for vector store")
            except Exception as e:
                logger.error(f"Failed to initialize post-quantum crypto for vector store: {e}")
                self.enable_pq_crypto = False
        
        # Vector encryption contexts
        self.encryption_contexts = {
            'embeddings': 'vector_embeddings',
            'metadata': 'vector_metadata',
            'search_queries': 'search_operations',
            'similarity_results': 'similarity_data'
        }
        
        # Initialize Weaviate client
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Weaviate client with post-quantum security headers"""
        if not WEAVIATE_AVAILABLE:
            logger.error("Weaviate not available - cannot initialize client")
            return
        
        try:
            # Enhanced headers for post-quantum security
            additional_headers = {
                'X-Post-Quantum': 'enabled' if self.enable_pq_crypto else 'disabled',
                'X-Encryption-Suite': 'CRYSTALS-Kyber-1024,CRYSTALS-Dilithium-5,FALCON-1024,SPHINCS-256s',
                'X-Quantum-Resistant': 'true' if self.enable_pq_crypto else 'false'
            }
            
            if self.api_key:
                auth_config = AuthApiKey(api_key=self.api_key)
                self.client = weaviate.Client(
                    url=self.weaviate_url,
                    auth_client_secret=auth_config,
                    additional_headers=additional_headers
                )
            else:
                self.client = weaviate.Client(
                    url=self.weaviate_url,
                    additional_headers=additional_headers
                )
            
            # Test connection
            if self.client.is_ready():
                logger.info("Weaviate client initialized with post-quantum configuration")
                self._setup_quantum_schemas()
            else:
                logger.error("Weaviate client not ready")
                self.client = None
                
        except Exception as e:
            logger.error(f"Failed to initialize Weaviate client: {e}")
            self.client = None
    
    def _setup_quantum_schemas(self):
        """Setup Weaviate schemas for quantum-resistant storage"""
        try:
            # Define quantum-secure document schema
            quantum_document_schema = {
                "class": "QuantumSecureDocument",
                "description": "Documents with quantum-resistant encryption",
                "properties": [
                    {
                        "name": "documentId",
                        "dataType": ["string"],
                        "description": "Unique document identifier"
                    },
                    {
                        "name": "tenantId",
                        "dataType": ["string"],
                        "description": "Tenant identifier for multi-tenancy"
                    },
                    {
                        "name": "encryptedContent",
                        "dataType": ["text"],
                        "description": "Post-quantum encrypted document content"
                    },
                    {
                        "name": "encryptedMetadata",
                        "dataType": ["text"],
                        "description": "Post-quantum encrypted metadata"
                    },
                    {
                        "name": "signatureInfo",
                        "dataType": ["text"],
                        "description": "Post-quantum digital signature for verification"
                    },
                    {
                        "name": "encryptionAlgorithm",
                        "dataType": ["string"],
                        "description": "Encryption algorithm used"
                    },
                    {
                        "name": "signatureAlgorithm",
                        "dataType": ["string"],
                        "description": "Signature algorithm used"
                    },
                    {
                        "name": "quantumSecured",
                        "dataType": ["boolean"],
                        "description": "Whether document is quantum-secured"
                    },
                    {
                        "name": "createdAt",
                        "dataType": ["date"],
                        "description": "Creation timestamp"
                    },
                    {
                        "name": "category",
                        "dataType": ["string"],
                        "description": "Document category"
                    }
                ],
                "vectorizer": "text2vec-openai"  # Can be customized
            }
            
            # Define quantum threat intelligence schema
            quantum_threat_schema = {
                "class": "QuantumThreatIntelligence",
                "description": "Threat intelligence with quantum-resistant encryption",
                "properties": [
                    {
                        "name": "threatId",
                        "dataType": ["string"],
                        "description": "Unique threat identifier"
                    },
                    {
                        "name": "tenantId",
                        "dataType": ["string"],
                        "description": "Tenant identifier"
                    },
                    {
                        "name": "encryptedThreatData",
                        "dataType": ["text"],
                        "description": "Encrypted threat information"
                    },
                    {
                        "name": "signatureInfo",
                        "dataType": ["text"],
                        "description": "Digital signature for integrity"
                    },
                    {
                        "name": "threatLevel",
                        "dataType": ["int"],
                        "description": "Threat severity level"
                    },
                    {
                        "name": "category",
                        "dataType": ["string"],
                        "description": "Threat category"
                    },
                    {
                        "name": "source",
                        "dataType": ["string"],
                        "description": "Intelligence source"
                    },
                    {
                        "name": "quantumSecured",
                        "dataType": ["boolean"],
                        "description": "Quantum security status"
                    },
                    {
                        "name": "detectedAt",
                        "dataType": ["date"],
                        "description": "Detection timestamp"
                    }
                ],
                "vectorizer": "text2vec-openai"
            }
            
            # Create schemas if they don't exist
            existing_schemas = [schema['class'] for schema in self.client.schema.get()['classes']]
            
            if "QuantumSecureDocument" not in existing_schemas:
                self.client.schema.create_class(quantum_document_schema)
                logger.info("Created QuantumSecureDocument schema")
            
            if "QuantumThreatIntelligence" not in existing_schemas:
                self.client.schema.create_class(quantum_threat_schema)
                logger.info("Created QuantumThreatIntelligence schema")
                
        except Exception as e:
            logger.error(f"Failed to setup quantum schemas: {e}")
    
    # ========== Encryption/Decryption Methods ==========
    
    async def encrypt_vector_data(self, content: str, metadata: Dict[str, Any], 
                                context: str) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
        """Encrypt vector data with post-quantum algorithms"""
        try:
            if not self.enable_pq_crypto:
                # Fallback - base64 encoding (not secure)
                import base64
                return (
                    {"content": base64.b64encode(content.encode()).decode(), "encrypted": False},
                    {"metadata": base64.b64encode(json.dumps(metadata).encode()).decode(), "encrypted": False},
                    {"signature": "none"}
                )
            
            # Encrypt content
            encrypted_content = pq_encrypt(content, f"{context}_content")
            
            # Encrypt metadata
            metadata_json = json.dumps(metadata, default=str)
            encrypted_metadata = pq_encrypt(metadata_json, f"{context}_metadata")
            
            # Create combined signature for integrity
            combined_data = content + metadata_json
            signature_info = pq_sign_data(combined_data.encode('utf-8'), 'dilithium')
            
            return encrypted_content, encrypted_metadata, signature_info
            
        except Exception as e:
            logger.error(f"Vector data encryption failed: {e}")
            raise
    
    async def decrypt_vector_data(self, encrypted_content: Dict[str, str], 
                                encrypted_metadata: Dict[str, str], 
                                signature_info: Dict[str, str]) -> Tuple[str, Dict[str, Any]]:
        """Decrypt vector data with post-quantum algorithms"""
        try:
            if not encrypted_content.get("encrypted", True):
                # Handle unencrypted fallback
                import base64
                content = base64.b64decode(encrypted_content["content"]).decode()
                metadata = json.loads(base64.b64decode(encrypted_metadata["metadata"]).decode())
                return content, metadata
            
            # Decrypt content
            content_bytes = pq_decrypt(encrypted_content)
            content = content_bytes.decode('utf-8')
            
            # Decrypt metadata
            metadata_bytes = pq_decrypt(encrypted_metadata)
            metadata = json.loads(metadata_bytes.decode('utf-8'))
            
            # Verify signature
            if signature_info.get("signature") != "none":
                combined_data = content + json.dumps(metadata, default=str)
                if not pq_verify_data(combined_data.encode('utf-8'), signature_info):
                    logger.error("Vector data signature verification failed")
                    raise ValueError("Vector data integrity check failed")
            
            return content, metadata
            
        except Exception as e:
            logger.error(f"Vector data decryption failed: {e}")
            raise
    
    # ========== Document Operations ==========
    
    async def store_secure_document(self, tenant_id: str, document_id: str, 
                                  content: str, metadata: Dict[str, Any], 
                                  category: str = "general") -> bool:
        """Store document with post-quantum encryption"""
        try:
            if not self.client:
                logger.error("Weaviate client not available")
                return False
            
            # Encrypt document data
            encrypted_content, encrypted_metadata, signature_info = await self.encrypt_vector_data(
                content, metadata, self.encryption_contexts['embeddings']
            )
            
            # Prepare data object
            data_object = {
                "documentId": document_id,
                "tenantId": tenant_id,
                "encryptedContent": json.dumps(encrypted_content),
                "encryptedMetadata": json.dumps(encrypted_metadata),
                "signatureInfo": json.dumps(signature_info),
                "encryptionAlgorithm": "kyber_1024_chacha20" if self.enable_pq_crypto else "none",
                "signatureAlgorithm": "dilithium_5" if self.enable_pq_crypto else "none",
                "quantumSecured": self.enable_pq_crypto,
                "createdAt": datetime.utcnow().isoformat(),
                "category": category
            }
            
            # Store in Weaviate
            result = self.client.data_object.create(
                data_object=data_object,
                class_name="QuantumSecureDocument",
                uuid=document_id
            )
            
            logger.info(f"Quantum-secured document stored: {document_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store secure document: {e}")
            return False
    
    async def retrieve_secure_document(self, tenant_id: str, document_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve and decrypt document"""
        try:
            if not self.client:
                logger.error("Weaviate client not available")
                return None
            
            # Retrieve from Weaviate
            result = self.client.data_object.get_by_id(
                uuid=document_id,
                class_name="QuantumSecureDocument"
            )
            
            if not result:
                return None
            
            properties = result.get('properties', {})
            
            # Verify tenant access
            if properties.get('tenantId') != tenant_id:
                logger.warning(f"Tenant access denied for document {document_id}")
                return None
            
            # Decrypt document data
            encrypted_content = json.loads(properties['encryptedContent'])
            encrypted_metadata = json.loads(properties['encryptedMetadata'])
            signature_info = json.loads(properties['signatureInfo'])
            
            content, metadata = await self.decrypt_vector_data(
                encrypted_content, encrypted_metadata, signature_info
            )
            
            return {
                "document_id": document_id,
                "content": content,
                "metadata": metadata,
                "category": properties.get('category'),
                "created_at": properties.get('createdAt'),
                "quantum_secured": properties.get('quantumSecured', False)
            }
            
        except Exception as e:
            logger.error(f"Failed to retrieve secure document: {e}")
            return None
    
    async def search_secure_documents(self, tenant_id: str, query: str, 
                                    category: Optional[str] = None, 
                                    limit: int = 10) -> List[Dict[str, Any]]:
        """Search documents with quantum-resistant security"""
        try:
            if not self.client:
                logger.error("Weaviate client not available")
                return []
            
            # Build search query
            where_filter = {
                "path": ["tenantId"],
                "operator": "Equal",
                "valueString": tenant_id
            }
            
            if category:
                where_filter = {
                    "operator": "And",
                    "operands": [
                        where_filter,
                        {
                            "path": ["category"],
                            "operator": "Equal",
                            "valueString": category
                        }
                    ]
                }
            
            # Perform search
            result = (
                self.client.query
                .get("QuantumSecureDocument", [
                    "documentId", "encryptedContent", "encryptedMetadata", 
                    "signatureInfo", "category", "createdAt", "quantumSecured"
                ])
                .with_near_text({"concepts": [query]})
                .with_where(where_filter)
                .with_limit(limit)
                .do()
            )
            
            documents = []
            if 'data' in result and 'Get' in result['data']:
                for doc in result['data']['Get']['QuantumSecureDocument']:
                    try:
                        # Decrypt document data
                        encrypted_content = json.loads(doc['encryptedContent'])
                        encrypted_metadata = json.loads(doc['encryptedMetadata'])
                        signature_info = json.loads(doc['signatureInfo'])
                        
                        content, metadata = await self.decrypt_vector_data(
                            encrypted_content, encrypted_metadata, signature_info
                        )
                        
                        documents.append({
                            "document_id": doc['documentId'],
                            "content": content[:500] + "..." if len(content) > 500 else content,  # Truncate for search results
                            "metadata": metadata,
                            "category": doc.get('category'),
                            "created_at": doc.get('createdAt'),
                            "quantum_secured": doc.get('quantumSecured', False)
                        })
                        
                    except Exception as e:
                        logger.error(f"Failed to decrypt search result {doc.get('documentId')}: {e}")
                        continue
            
            logger.info(f"Quantum search completed: {len(documents)} results for tenant {tenant_id}")
            return documents
            
        except Exception as e:
            logger.error(f"Quantum search failed: {e}")
            return []
    
    # ========== Threat Intelligence Operations ==========
    
    async def store_threat_intelligence(self, tenant_id: str, threat_id: str,
                                      threat_data: Dict[str, Any], 
                                      threat_level: int = 3,
                                      category: str = "general",
                                      source: str = "system") -> bool:
        """Store threat intelligence with quantum encryption"""
        try:
            if not self.client:
                logger.error("Weaviate client not available")
                return False
            
            # Encrypt threat data
            threat_json = json.dumps(threat_data, default=str)
            encrypted_threat = pq_encrypt(threat_json, self.encryption_contexts['metadata'])
            signature_info = pq_sign_data(threat_json.encode('utf-8'), 'dilithium')
            
            # Prepare data object
            data_object = {
                "threatId": threat_id,
                "tenantId": tenant_id,
                "encryptedThreatData": json.dumps(encrypted_threat),
                "signatureInfo": json.dumps(signature_info),
                "threatLevel": threat_level,
                "category": category,
                "source": source,
                "quantumSecured": self.enable_pq_crypto,
                "detectedAt": datetime.utcnow().isoformat()
            }
            
            # Store in Weaviate
            result = self.client.data_object.create(
                data_object=data_object,
                class_name="QuantumThreatIntelligence",
                uuid=threat_id
            )
            
            logger.info(f"Quantum-secured threat intelligence stored: {threat_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store threat intelligence: {e}")
            return False
    
    async def search_threat_intelligence(self, tenant_id: str, query: str,
                                       min_threat_level: int = 1,
                                       category: Optional[str] = None,
                                       limit: int = 20) -> List[Dict[str, Any]]:
        """Search threat intelligence with quantum security"""
        try:
            if not self.client:
                logger.error("Weaviate client not available")
                return []
            
            # Build where filter
            where_filter = {
                "operator": "And",
                "operands": [
                    {
                        "path": ["tenantId"],
                        "operator": "Equal",
                        "valueString": tenant_id
                    },
                    {
                        "path": ["threatLevel"],
                        "operator": "GreaterThanEqual",
                        "valueInt": min_threat_level
                    }
                ]
            }
            
            if category:
                where_filter["operands"].append({
                    "path": ["category"],
                    "operator": "Equal",
                    "valueString": category
                })
            
            # Perform search
            result = (
                self.client.query
                .get("QuantumThreatIntelligence", [
                    "threatId", "encryptedThreatData", "signatureInfo", 
                    "threatLevel", "category", "source", "detectedAt", "quantumSecured"
                ])
                .with_near_text({"concepts": [query]})
                .with_where(where_filter)
                .with_limit(limit)
                .do()
            )
            
            threats = []
            if 'data' in result and 'Get' in result['data']:
                for threat in result['data']['Get']['QuantumThreatIntelligence']:
                    try:
                        # Decrypt threat data
                        encrypted_threat = json.loads(threat['encryptedThreatData'])
                        signature_info = json.loads(threat['signatureInfo'])
                        
                        threat_bytes = pq_decrypt(encrypted_threat)
                        threat_data = json.loads(threat_bytes.decode('utf-8'))
                        
                        # Verify signature
                        if not pq_verify_data(threat_bytes, signature_info):
                            logger.error(f"Threat intelligence signature verification failed: {threat['threatId']}")
                            continue
                        
                        threats.append({
                            "threat_id": threat['threatId'],
                            "threat_data": threat_data,
                            "threat_level": threat.get('threatLevel'),
                            "category": threat.get('category'),
                            "source": threat.get('source'),
                            "detected_at": threat.get('detectedAt'),
                            "quantum_secured": threat.get('quantumSecured', False)
                        })
                        
                    except Exception as e:
                        logger.error(f"Failed to decrypt threat intelligence {threat.get('threatId')}: {e}")
                        continue
            
            return threats
            
        except Exception as e:
            logger.error(f"Threat intelligence search failed: {e}")
            return []
    
    # ========== Status and Monitoring ==========
    
    async def get_vector_store_status(self) -> Dict[str, Any]:
        """Get comprehensive vector store status"""
        try:
            status = {
                "vector_store": {
                    "enabled": self.client is not None,
                    "url": self.weaviate_url,
                    "quantum_secured": self.enable_pq_crypto,
                    "ready": self.client.is_ready() if self.client else False
                },
                "encryption": {
                    "post_quantum_enabled": self.enable_pq_crypto,
                    "algorithms": {
                        "key_encapsulation": "CRYSTALS-Kyber-1024",
                        "signatures": ["CRYSTALS-Dilithium-5", "FALCON-1024", "SPHINCS+-256s"],
                        "symmetric": "ChaCha20-Poly1305"
                    } if self.enable_pq_crypto else None
                },
                "schemas": [],
                "statistics": {
                    "total_documents": 0,
                    "quantum_secured_documents": 0,
                    "threat_intelligence_entries": 0
                }
            }
            
            if self.client and self.client.is_ready():
                # Get schema information
                schema_info = self.client.schema.get()
                status["schemas"] = [cls["class"] for cls in schema_info.get("classes", [])]
                
                # Get document counts
                try:
                    doc_result = self.client.query.aggregate("QuantumSecureDocument").with_meta_count().do()
                    if 'data' in doc_result and 'Aggregate' in doc_result['data']:
                        status["statistics"]["total_documents"] = doc_result['data']['Aggregate']['QuantumSecureDocument'][0]['meta']['count']
                    
                    threat_result = self.client.query.aggregate("QuantumThreatIntelligence").with_meta_count().do()
                    if 'data' in threat_result and 'Aggregate' in threat_result['data']:
                        status["statistics"]["threat_intelligence_entries"] = threat_result['data']['Aggregate']['QuantumThreatIntelligence'][0]['meta']['count']
                except:
                    pass  # Schemas might not exist yet
            
            status["checked_at"] = datetime.utcnow().isoformat()
            return status
            
        except Exception as e:
            logger.error(f"Failed to get vector store status: {e}")
            return {
                "error": str(e),
                "vector_store": {"enabled": False},
                "encryption": {"post_quantum_enabled": False}
            }
    
    async def cleanup_expired_vectors(self, days_old: int = 90) -> int:
        """Clean up old vector data"""
        try:
            if not self.client:
                return 0
            
            cutoff_date = (datetime.utcnow() - timedelta(days=days_old)).isoformat()
            
            # Delete old documents
            where_filter = {
                "path": ["createdAt"],
                "operator": "LessThan",
                "valueDate": cutoff_date
            }
            
            deleted_count = 0
            
            # This would require implementing batch deletion
            # For now, we'll just return 0
            logger.info(f"Vector cleanup completed: {deleted_count} items removed")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Vector cleanup failed: {e}")
            return 0


# Global instance management
_pq_vector_store = None

def get_pq_vector_store(weaviate_url: str = None, api_key: str = None) -> PostQuantumVectorStore:
    """Get or create global post-quantum vector store instance"""
    global _pq_vector_store
    if _pq_vector_store is None:
        _pq_vector_store = PostQuantumVectorStore(
            weaviate_url=weaviate_url,
            api_key=api_key,
            enable_pq_crypto=True
        )
    return _pq_vector_store