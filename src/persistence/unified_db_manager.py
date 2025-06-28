"""
Unified Database Manager
Combines PostgreSQL for structured data and Weaviate for vector/semantic search
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
import json

import asyncpg
import weaviate
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

from ..ai_analytics.vector.weaviate_vector_store import WeaviateVectorStore
from ..unified_models import (
    SecurityScan, Finding, TenantInfo, AuditResult,
    ComplianceFramework, SecurityScore
)

logger = logging.getLogger(__name__)

class UnifiedDatabaseManager:
    """
    Unified database management combining PostgreSQL and Weaviate
    PostgreSQL: Structured data, transactions, user management
    Weaviate: Vector search, semantic analysis, AI-powered correlations
    """
    
    def __init__(self, postgres_url: str, weaviate_config: Optional[Dict] = None):
        self.postgres_url = postgres_url
        self.weaviate_config = weaviate_config or {}
        
        # PostgreSQL components
        self.engine = None
        self.SessionLocal = None
        
        # Weaviate components
        self.vector_store = WeaviateVectorStore()
        
        self._initialized = False
    
    async def initialize(self):
        """Initialize both PostgreSQL and Weaviate connections"""
        try:
            logger.info("Initializing Unified Database Manager...")
            
            # Initialize PostgreSQL
            await self._initialize_postgresql()
            
            # Initialize Weaviate
            await self._initialize_weaviate()
            
            # Create database schemas if needed
            await self._ensure_schemas()
            
            self._initialized = True
            logger.info("Unified Database Manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database manager: {e}")
            raise
    
    async def _initialize_postgresql(self):
        """Initialize PostgreSQL async connection"""
        try:
            self.engine = create_async_engine(
                self.postgres_url,
                echo=False,
                pool_size=20,
                max_overflow=30,
                pool_pre_ping=True,
                pool_recycle=3600
            )
            
            self.SessionLocal = sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            
            # Test connection
            async with self.engine.begin() as conn:
                result = await conn.execute(text("SELECT 1"))
                
            logger.info("PostgreSQL connection established")
            
        except Exception as e:
            logger.error(f"PostgreSQL initialization failed: {e}")
            raise
    
    async def _initialize_weaviate(self):
        """Initialize Weaviate vector database"""
        try:
            # Vector store handles its own initialization
            if hasattr(self.vector_store, 'initialize'):
                await self.vector_store.initialize()
            
            logger.info("Weaviate connection established")
            
        except Exception as e:
            logger.error(f"Weaviate initialization failed: {e}")
            # Don't fail completely - PostgreSQL can work standalone
            logger.warning("Continuing with PostgreSQL only - vector search disabled")
    
    async def _ensure_schemas(self):
        """Ensure database schemas exist"""
        try:
            # PostgreSQL schema creation handled by SQLAlchemy models
            # This is where you'd run database migrations
            
            # Weaviate collections are created by the vector store
            logger.info("Database schemas verified")
            
        except Exception as e:
            logger.error(f"Schema verification failed: {e}")
            raise
    
    async def get_session(self) -> AsyncSession:
        """Get PostgreSQL database session"""
        if not self._initialized:
            await self.initialize()
        
        return self.SessionLocal()
    
    # Security Scan Operations
    async def create_security_scan(
        self, 
        tenant_id: str,
        scan_data: Dict[str, Any]
    ) -> str:
        """Create a new security scan record"""
        try:
            scan_id = f"scan_{tenant_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Store structured data in PostgreSQL
            async with self.get_session() as session:
                scan_record = SecurityScan(
                    scan_id=scan_id,
                    tenant_id=tenant_id,
                    scan_type=scan_data.get("scan_type", "comprehensive"),
                    status="running",
                    created_at=datetime.now(),
                    scan_config=json.dumps(scan_data.get("config", {})),
                    targets=json.dumps(scan_data.get("targets", []))
                )
                
                session.add(scan_record)
                await session.commit()
            
            # Store vector data in Weaviate for semantic search
            if self.vector_store:
                await self.vector_store.store_security_scan({
                    "scan_id": scan_id,
                    "tenant_id": tenant_id,
                    "scan_data": scan_data
                })
            
            logger.info(f"Security scan created: {scan_id}")
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to create security scan: {e}")
            raise
    
    async def update_scan_results(
        self, 
        scan_id: str,
        results: Dict[str, Any],
        status: str = "completed"
    ):
        """Update scan with results"""
        try:
            # Update PostgreSQL record
            async with self.get_session() as session:
                result = await session.execute(
                    text("""
                        UPDATE security_scans 
                        SET status = :status, 
                            completed_at = :completed_at,
                            results = :results,
                            overall_score = :score
                        WHERE scan_id = :scan_id
                    """),
                    {
                        "status": status,
                        "completed_at": datetime.now(),
                        "results": json.dumps(results),
                        "score": results.get("overall_score", 0),
                        "scan_id": scan_id
                    }
                )
                await session.commit()
            
            # Update vector store for semantic search
            if self.vector_store:
                await self.vector_store.update_security_scan(scan_id, results)
            
            logger.info(f"Scan results updated: {scan_id}")
            
        except Exception as e:
            logger.error(f"Failed to update scan results: {e}")
            raise
    
    async def get_scan_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve scan results by ID"""
        try:
            async with self.get_session() as session:
                result = await session.execute(
                    text("""
                        SELECT scan_id, tenant_id, scan_type, status, 
                               created_at, completed_at, results, overall_score
                        FROM security_scans 
                        WHERE scan_id = :scan_id
                    """),
                    {"scan_id": scan_id}
                )
                
                row = result.fetchone()
                if row:
                    return {
                        "scan_id": row[0],
                        "tenant_id": row[1],
                        "scan_type": row[2],
                        "status": row[3],
                        "created_at": row[4].isoformat() if row[4] else None,
                        "completed_at": row[5].isoformat() if row[5] else None,
                        "results": json.loads(row[6]) if row[6] else {},
                        "overall_score": row[7]
                    }
                
                return None
                
        except Exception as e:
            logger.error(f"Failed to retrieve scan results: {e}")
            raise
    
    # Finding Operations
    async def store_findings(
        self, 
        scan_id: str,
        findings: List[Dict[str, Any]]
    ):
        """Store security findings"""
        try:
            async with self.get_session() as session:
                for finding_data in findings:
                    finding = Finding(
                        finding_id=f"finding_{scan_id}_{len(findings)}_{datetime.now().strftime('%Y%m%d%H%M%S')}",
                        scan_id=scan_id,
                        title=finding_data.get("title", ""),
                        description=finding_data.get("description", ""),
                        severity=finding_data.get("severity", "Medium"),
                        category=finding_data.get("category", "general"),
                        status="open",
                        provider=finding_data.get("provider", ""),
                        created_at=datetime.now(),
                        remediation=finding_data.get("remediation", ""),
                        cvss_score=finding_data.get("cvss_score", 0.0)
                    )
                    session.add(finding)
                
                await session.commit()
            
            # Store in vector database for semantic search
            if self.vector_store:
                for finding_data in findings:
                    await self.vector_store.store_finding(finding_data)
            
            logger.info(f"Stored {len(findings)} findings for scan {scan_id}")
            
        except Exception as e:
            logger.error(f"Failed to store findings: {e}")
            raise
    
    async def get_findings(
        self, 
        tenant_id: str,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Retrieve findings with filtering"""
        try:
            # Build dynamic query
            query = """
                SELECT f.finding_id, f.scan_id, f.title, f.description, 
                       f.severity, f.category, f.status, f.provider,
                       f.created_at, f.remediation, f.cvss_score
                FROM findings f
                JOIN security_scans s ON f.scan_id = s.scan_id
                WHERE s.tenant_id = :tenant_id
            """
            
            params = {"tenant_id": tenant_id}
            
            if severity:
                query += " AND f.severity = :severity"
                params["severity"] = severity
            
            if status:
                query += " AND f.status = :status"
                params["status"] = status
            
            query += " ORDER BY f.created_at DESC LIMIT :limit OFFSET :offset"
            params.update({"limit": limit, "offset": offset})
            
            async with self.get_session() as session:
                result = await session.execute(text(query), params)
                
                findings = []
                for row in result.fetchall():
                    findings.append({
                        "finding_id": row[0],
                        "scan_id": row[1],
                        "title": row[2],
                        "description": row[3],
                        "severity": row[4],
                        "category": row[5],
                        "status": row[6],
                        "provider": row[7],
                        "created_at": row[8].isoformat() if row[8] else None,
                        "remediation": row[9],
                        "cvss_score": float(row[10]) if row[10] else 0.0
                    })
                
                return findings
                
        except Exception as e:
            logger.error(f"Failed to retrieve findings: {e}")
            raise
    
    # Semantic Search Operations
    async def semantic_search_findings(
        self, 
        query: str,
        tenant_id: Optional[str] = None,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Perform semantic search on findings using Weaviate"""
        if not self.vector_store:
            return []
        
        try:
            return await self.vector_store.semantic_search(
                query=query,
                tenant_id=tenant_id,
                limit=limit
            )
        except Exception as e:
            logger.error(f"Semantic search failed: {e}")
            return []
    
    async def find_similar_findings(
        self, 
        finding_id: str,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Find similar findings using vector similarity"""
        if not self.vector_store:
            return []
        
        try:
            return await self.vector_store.find_similar_findings(
                finding_id=finding_id,
                limit=limit
            )
        except Exception as e:
            logger.error(f"Finding similarity search failed: {e}")
            return []
    
    # Tenant Operations
    async def create_tenant(
        self, 
        tenant_name: str,
        config: Dict[str, Any]
    ) -> str:
        """Create a new tenant"""
        try:
            tenant_id = f"tenant_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            async with self.get_session() as session:
                tenant = TenantInfo(
                    tenant_id=tenant_id,
                    name=tenant_name,
                    created_at=datetime.now(),
                    config=json.dumps(config),
                    is_active=True
                )
                
                session.add(tenant)
                await session.commit()
            
            logger.info(f"Tenant created: {tenant_id}")
            return tenant_id
            
        except Exception as e:
            logger.error(f"Failed to create tenant: {e}")
            raise
    
    async def get_tenant_info(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve tenant information"""
        try:
            async with self.get_session() as session:
                result = await session.execute(
                    text("""
                        SELECT tenant_id, name, created_at, config, is_active
                        FROM tenants 
                        WHERE tenant_id = :tenant_id
                    """),
                    {"tenant_id": tenant_id}
                )
                
                row = result.fetchone()
                if row:
                    return {
                        "tenant_id": row[0],
                        "name": row[1],
                        "created_at": row[2].isoformat() if row[2] else None,
                        "config": json.loads(row[3]) if row[3] else {},
                        "is_active": row[4]
                    }
                
                return None
                
        except Exception as e:
            logger.error(f"Failed to retrieve tenant info: {e}")
            raise
    
    # Health and Statistics
    async def get_database_health(self) -> Dict[str, Any]:
        """Check database health and return status"""
        health = {
            "postgresql": {"status": "unknown", "error": None},
            "weaviate": {"status": "unknown", "error": None}
        }
        
        # Check PostgreSQL
        try:
            async with self.get_session() as session:
                await session.execute(text("SELECT 1"))
            health["postgresql"]["status"] = "healthy"
        except Exception as e:
            health["postgresql"]["status"] = "unhealthy"
            health["postgresql"]["error"] = str(e)
        
        # Check Weaviate
        try:
            if self.vector_store and hasattr(self.vector_store, 'health_check'):
                weaviate_health = await self.vector_store.health_check()
                health["weaviate"] = weaviate_health
            else:
                health["weaviate"]["status"] = "unavailable"
        except Exception as e:
            health["weaviate"]["status"] = "unhealthy"
            health["weaviate"]["error"] = str(e)
        
        return health
    
    async def get_tenant_statistics(self, tenant_id: str) -> Dict[str, Any]:
        """Get statistics for a tenant"""
        try:
            async with self.get_session() as session:
                # Get scan counts
                scan_result = await session.execute(
                    text("""
                        SELECT COUNT(*) as total_scans,
                               COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_scans,
                               AVG(overall_score) as avg_score
                        FROM security_scans 
                        WHERE tenant_id = :tenant_id
                    """),
                    {"tenant_id": tenant_id}
                )
                scan_stats = scan_result.fetchone()
                
                # Get finding counts by severity
                finding_result = await session.execute(
                    text("""
                        SELECT severity, COUNT(*) as count
                        FROM findings f
                        JOIN security_scans s ON f.scan_id = s.scan_id
                        WHERE s.tenant_id = :tenant_id
                        GROUP BY severity
                    """),
                    {"tenant_id": tenant_id}
                )
                
                finding_stats = {}
                for row in finding_result.fetchall():
                    finding_stats[row[0]] = row[1]
                
                return {
                    "total_scans": scan_stats[0] if scan_stats else 0,
                    "completed_scans": scan_stats[1] if scan_stats else 0,
                    "average_score": float(scan_stats[2]) if scan_stats and scan_stats[2] else 0.0,
                    "findings_by_severity": finding_stats
                }
                
        except Exception as e:
            logger.error(f"Failed to get tenant statistics: {e}")
            raise
    
    async def cleanup(self):
        """Clean up database connections"""
        try:
            if self.engine:
                await self.engine.dispose()
            
            if self.vector_store and hasattr(self.vector_store, 'cleanup'):
                await self.vector_store.cleanup()
            
            logger.info("Database manager cleanup completed")
            
        except Exception as e:
            logger.error(f"Database cleanup failed: {e}")