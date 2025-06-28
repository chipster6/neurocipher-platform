"""
Post-Quantum Integration Module
Central integration point for all post-quantum cryptographic capabilities
Provides unified interface for enterprise quantum-resistant security
"""

import logging
import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime

from .security.post_quantum_crypto import get_pq_suite
from .security.post_quantum_auth import get_pq_auth_manager
from .security.post_quantum_config import get_pq_config_manager
from .persistence.post_quantum_db_manager import get_pq_db_manager
from .ai_analytics.post_quantum_vector_store import get_pq_vector_store
from .compliance.post_quantum_compliance import get_pq_compliance_framework

logger = logging.getLogger(__name__)


class PostQuantumIntegrationManager:
    """
    Central manager for all post-quantum cryptographic capabilities
    Provides unified interface for quantum-resistant security across the platform
    """
    
    def __init__(self, database_url: str, secret_key: str):
        self.database_url = database_url
        self.secret_key = secret_key
        self.logger = logging.getLogger(__name__)
        
        # Component instances
        self.pq_suite = None
        self.pq_auth_manager = None
        self.pq_config_manager = None
        self.pq_db_manager = None
        self.pq_vector_store = None
        self.pq_compliance_framework = None
        
        # Initialization status
        self.initialized = False
        self.initialization_errors = []
    
    async def initialize_all_components(self) -> Dict[str, Any]:
        """Initialize all post-quantum components"""
        try:
            self.logger.info("Initializing post-quantum cryptographic system...")
            
            # Initialize configuration manager first
            self.pq_config_manager = get_pq_config_manager()
            self.logger.info("✅ Post-quantum configuration manager initialized")
            
            # Initialize core cryptographic suite
            self.pq_suite = get_pq_suite()
            self.logger.info("✅ Post-quantum crypto suite initialized")
            
            # Initialize database manager
            self.pq_db_manager = get_pq_db_manager(self.database_url)
            await self.pq_db_manager.initialize_pq_tables()
            self.logger.info("✅ Post-quantum database manager initialized")
            
            # Initialize authentication manager
            self.pq_auth_manager = get_pq_auth_manager(self.secret_key, self.pq_db_manager)
            self.logger.info("✅ Post-quantum authentication manager initialized")
            
            # Initialize vector store
            try:
                self.pq_vector_store = get_pq_vector_store()
                self.logger.info("✅ Post-quantum vector store initialized")
            except Exception as e:
                self.logger.warning(f"Vector store initialization failed (optional): {e}")
                self.initialization_errors.append(f"Vector store: {e}")
            
            # Initialize compliance framework
            self.pq_compliance_framework = get_pq_compliance_framework()
            self.logger.info("✅ Post-quantum compliance framework initialized")
            
            self.initialized = True
            self.logger.info("🔐 Post-quantum cryptographic system fully initialized!")
            
            return await self.get_system_status()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize post-quantum system: {e}")
            self.initialization_errors.append(str(e))
            raise
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        try:
            status = {
                "system": {
                    "initialized": self.initialized,
                    "initialization_errors": self.initialization_errors,
                    "timestamp": datetime.utcnow().isoformat()
                },
                "components": {
                    "crypto_suite": {
                        "available": self.pq_suite is not None,
                        "status": self.pq_suite.get_system_status() if self.pq_suite else None
                    },
                    "authentication": {
                        "available": self.pq_auth_manager is not None,
                        "quantum_enabled": self.pq_auth_manager.enable_pq_crypto if self.pq_auth_manager else False
                    },
                    "database": {
                        "available": self.pq_db_manager is not None,
                        "encryption_status": await self.pq_db_manager.get_encryption_status() if self.pq_db_manager else None
                    },
                    "vector_store": {
                        "available": self.pq_vector_store is not None,
                        "status": await self.pq_vector_store.get_vector_store_status() if self.pq_vector_store else None
                    },
                    "configuration": {
                        "available": self.pq_config_manager is not None,
                        "summary": self.pq_config_manager.get_configuration_summary() if self.pq_config_manager else None
                    },
                    "compliance": {
                        "available": self.pq_compliance_framework is not None,
                        "frameworks": self.pq_compliance_framework.get_available_frameworks() if self.pq_compliance_framework else []
                    }
                }
            }
            
            return status
            
        except Exception as e:
            self.logger.error(f"Failed to get system status: {e}")
            return {
                "system": {
                    "initialized": False,
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat()
                }
            }
    
    async def conduct_quantum_readiness_assessment(self, tenant_id: str) -> Dict[str, Any]:
        """Conduct comprehensive quantum readiness assessment"""
        try:
            if not self.pq_compliance_framework:
                raise ValueError("Compliance framework not initialized")
            
            assessments = []
            frameworks = ['nist_csf', 'iso27001', 'soc2', 'nist_pqc']
            
            for framework in frameworks:
                try:
                    assessment = await self.pq_compliance_framework.conduct_quantum_readiness_assessment(
                        tenant_id=tenant_id,
                        framework=framework,
                        assessor="system_automated"
                    )
                    assessments.append(assessment)
                    self.logger.info(f"Completed {framework} assessment: {assessment.quantum_ready_percentage:.1f}% ready")
                except Exception as e:
                    self.logger.error(f"Assessment failed for {framework}: {e}")
            
            if assessments:
                # Generate comprehensive scorecard
                scorecard = self.pq_compliance_framework.generate_quantum_readiness_scorecard(assessments)
                
                # Generate individual reports
                reports = {}
                for assessment in assessments:
                    reports[assessment.framework] = self.pq_compliance_framework.generate_compliance_report(assessment)
                
                return {
                    "scorecard": scorecard,
                    "assessments": [
                        {
                            "framework": a.framework,
                            "overall_status": a.overall_status.value,
                            "quantum_ready_percentage": a.quantum_ready_percentage,
                            "total_controls": a.total_controls,
                            "compliant_controls": a.compliant_controls
                        }
                        for a in assessments
                    ],
                    "detailed_reports": reports,
                    "assessment_date": datetime.utcnow().isoformat()
                }
            else:
                return {"error": "No assessments completed", "assessments": []}
                
        except Exception as e:
            self.logger.error(f"Quantum readiness assessment failed: {e}")
            raise
    
    async def encrypt_sensitive_data(self, data: Any, context: str = "general") -> Dict[str, str]:
        """Encrypt sensitive data with post-quantum algorithms"""
        try:
            if not self.pq_auth_manager:
                raise ValueError("Authentication manager not initialized")
            
            return await self.pq_auth_manager.encrypt_sensitive_data(data, context)
            
        except Exception as e:
            self.logger.error(f"Data encryption failed: {e}")
            raise
    
    async def decrypt_sensitive_data(self, encrypted_package: Dict[str, str]) -> Any:
        """Decrypt sensitive data with post-quantum algorithms"""
        try:
            if not self.pq_auth_manager:
                raise ValueError("Authentication manager not initialized")
            
            return await self.pq_auth_manager.decrypt_sensitive_data(encrypted_package)
            
        except Exception as e:
            self.logger.error(f"Data decryption failed: {e}")
            raise
    
    async def store_encrypted_scan_data(self, tenant_id: str, scan_data: Dict[str, Any]) -> str:
        """Store scan data with post-quantum encryption"""
        try:
            if not self.pq_db_manager:
                raise ValueError("Database manager not initialized")
            
            return await self.pq_db_manager.store_encrypted_scan_data(tenant_id, scan_data)
            
        except Exception as e:
            self.logger.error(f"Encrypted scan data storage failed: {e}")
            raise
    
    async def get_encrypted_scan_data(self, tenant_id: str, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve and decrypt scan data"""
        try:
            if not self.pq_db_manager:
                raise ValueError("Database manager not initialized")
            
            return await self.pq_db_manager.get_encrypted_scan_data(tenant_id, scan_id)
            
        except Exception as e:
            self.logger.error(f"Encrypted scan data retrieval failed: {e}")
            raise
    
    async def store_secure_document(self, tenant_id: str, document_id: str, 
                                  content: str, metadata: Dict[str, Any], 
                                  category: str = "general") -> bool:
        """Store document with quantum-resistant encryption in vector store"""
        try:
            if not self.pq_vector_store:
                raise ValueError("Vector store not initialized")
            
            return await self.pq_vector_store.store_secure_document(
                tenant_id, document_id, content, metadata, category
            )
            
        except Exception as e:
            self.logger.error(f"Secure document storage failed: {e}")
            raise
    
    async def search_secure_documents(self, tenant_id: str, query: str, 
                                    category: Optional[str] = None, 
                                    limit: int = 10) -> List[Dict[str, Any]]:
        """Search documents with quantum-resistant security"""
        try:
            if not self.pq_vector_store:
                raise ValueError("Vector store not initialized")
            
            return await self.pq_vector_store.search_secure_documents(
                tenant_id, query, category, limit
            )
            
        except Exception as e:
            self.logger.error(f"Secure document search failed: {e}")
            raise
    
    async def log_quantum_security_event(self, event_type: str, tenant_id: str, 
                                       event_data: Dict[str, Any]) -> str:
        """Log security event with post-quantum encryption"""
        try:
            if not self.pq_db_manager:
                raise ValueError("Database manager not initialized")
            
            return await self.pq_db_manager.log_quantum_event(event_type, event_data, tenant_id)
            
        except Exception as e:
            self.logger.error(f"Quantum security event logging failed: {e}")
            raise
    
    async def get_quantum_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive data for quantum dashboard"""
        try:
            dashboard_data = {
                "system_status": await self.get_system_status(),
                "algorithm_status": self.pq_suite.get_system_status() if self.pq_suite else None,
                "database_encryption": await self.pq_db_manager.get_encryption_status() if self.pq_db_manager else None,
                "vector_store_status": await self.pq_vector_store.get_vector_store_status() if self.pq_vector_store else None,
                "configuration_summary": self.pq_config_manager.get_configuration_summary() if self.pq_config_manager else None,
                "compliance_frameworks": self.pq_compliance_framework.get_available_frameworks() if self.pq_compliance_framework else [],
                "timestamp": datetime.utcnow().isoformat()
            }
            
            return dashboard_data
            
        except Exception as e:
            self.logger.error(f"Failed to get dashboard data: {e}")
            return {"error": str(e), "timestamp": datetime.utcnow().isoformat()}
    
    async def cleanup_expired_data(self) -> Dict[str, int]:
        """Clean up expired quantum sessions and data"""
        try:
            cleanup_results = {}
            
            # Clean up authentication sessions
            if self.pq_auth_manager:
                await self.pq_auth_manager.cleanup_expired_sessions()
                cleanup_results["auth_sessions"] = await self.pq_auth_manager.get_active_session_count()
            
            # Clean up database sessions
            if self.pq_db_manager:
                expired_count = await self.pq_db_manager.cleanup_expired_quantum_sessions()
                cleanup_results["db_sessions"] = expired_count
            
            # Clean up vector store data (if needed)
            if self.pq_vector_store:
                cleaned_vectors = await self.pq_vector_store.cleanup_expired_vectors()
                cleanup_results["vector_data"] = cleaned_vectors
            
            self.logger.info(f"Cleanup completed: {cleanup_results}")
            return cleanup_results
            
        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")
            return {"error": str(e)}
    
    def get_integration_summary(self) -> Dict[str, Any]:
        """Get summary of post-quantum integration status"""
        return {
            "integration_name": "AuditHound Post-Quantum Cryptography",
            "version": "1.0.0",
            "description": "Enterprise quantum-resistant security implementation",
            "initialized": self.initialized,
            "components": {
                "crypto_suite": self.pq_suite is not None,
                "authentication": self.pq_auth_manager is not None,
                "database": self.pq_db_manager is not None,
                "vector_store": self.pq_vector_store is not None,
                "configuration": self.pq_config_manager is not None,
                "compliance": self.pq_compliance_framework is not None
            },
            "algorithms": {
                "CRYSTALS-Kyber": "Implemented",
                "CRYSTALS-Dilithium": "Implemented",
                "FALCON": "Implemented",
                "SPHINCS+": "Implemented",
                "ChaCha20-Poly1305": "Implemented"
            },
            "security_level": 5,
            "nist_standardized": True,
            "quantum_resistant": True,
            "initialization_errors": self.initialization_errors,
            "last_updated": datetime.utcnow().isoformat()
        }


# Global instance
_pq_integration_manager = None

def get_pq_integration_manager(database_url: str, secret_key: str) -> PostQuantumIntegrationManager:
    """Get or create global post-quantum integration manager"""
    global _pq_integration_manager
    if _pq_integration_manager is None:
        _pq_integration_manager = PostQuantumIntegrationManager(database_url, secret_key)
    return _pq_integration_manager


async def initialize_post_quantum_system(database_url: str, secret_key: str) -> Dict[str, Any]:
    """Initialize the complete post-quantum cryptographic system"""
    manager = get_pq_integration_manager(database_url, secret_key)
    return await manager.initialize_all_components()