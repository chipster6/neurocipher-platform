#!/usr/bin/env python3
"""
AuditHound Worker Service
Background task processing with Celery and Redis
"""

import argparse
import asyncio
import signal
import sys
import os
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.observability.logger import get_logger, setup_logging
from src.observability.metrics import MetricsCollector
from src.unified_audit_engine import UnifiedAuditEngine
from src.multi_tenant_manager import MultiTenantManager

# Initialize logging
setup_logging()
logger = get_logger(__name__)

class AuditWorker:
    """AuditHound background worker"""
    
    def __init__(self, concurrency: int = 4):
        self.concurrency = concurrency
        self.executor = ThreadPoolExecutor(max_workers=concurrency)
        self.metrics = MetricsCollector()
        self.audit_engine = UnifiedAuditEngine()
        self.tenant_manager = MultiTenantManager()
        self.running = False
        
    async def initialize(self):
        """Initialize worker"""
        logger.info("Initializing AuditHound Worker...")
        
        await self.audit_engine.initialize()
        await self.tenant_manager.initialize()
        self.metrics.start_background_collection()
        
        logger.info("Worker initialized successfully")
    
    async def start(self):
        """Start worker processes"""
        self.running = True
        logger.info(f"Starting {self.concurrency} worker processes...")
        
        # Start worker tasks
        tasks = []
        for i in range(self.concurrency):
            task = asyncio.create_task(self._worker_loop(f"worker-{i}"))
            tasks.append(task)
        
        # Wait for all tasks
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Worker processes cancelled")
    
    async def stop(self):
        """Stop worker processes"""
        logger.info("Stopping worker processes...")
        self.running = False
        
        # Cleanup
        await self.audit_engine.cleanup()
        await self.tenant_manager.cleanup()
        self.executor.shutdown(wait=True)
    
    async def _worker_loop(self, worker_id: str):
        """Main worker loop"""
        logger.info(f"Starting worker loop: {worker_id}")
        
        while self.running:
            try:
                # Poll for tasks (in production, use Redis/RabbitMQ)
                task = await self._get_next_task()
                
                if task:
                    await self._process_task(worker_id, task)
                else:
                    # No tasks available, sleep briefly
                    await asyncio.sleep(1)
                    
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")
                self.metrics.record_worker_error(worker_id, str(e))
                await asyncio.sleep(5)  # Error backoff
        
        logger.info(f"Worker loop stopped: {worker_id}")
    
    async def _get_next_task(self) -> Dict[str, Any]:
        """Get next task from queue"""
        # Mock task polling - replace with Redis/RabbitMQ implementation
        
        # Simulate task availability
        import random
        if random.random() < 0.1:  # 10% chance of task
            return {
                "id": f"task-{int(time.time())}",
                "type": "audit",
                "tenant_id": "default",
                "data": {
                    "audit_type": "security_scan",
                    "targets": ["127.0.0.1"]
                }
            }
        
        return None
    
    async def _process_task(self, worker_id: str, task: Dict[str, Any]):
        """Process a task"""
        task_id = task["id"]
        task_type = task["type"]
        tenant_id = task["tenant_id"]
        
        logger.info(f"Worker {worker_id} processing task {task_id} (type: {task_type})")
        
        start_time = time.time()
        
        try:
            # Process different task types
            if task_type == "audit":
                await self._process_audit_task(tenant_id, task["data"])
            elif task_type == "compliance_check":
                await self._process_compliance_task(tenant_id, task["data"])
            elif task_type == "report_generation":
                await self._process_report_task(tenant_id, task["data"])
            elif task_type == "threat_analysis":
                await self._process_threat_task(tenant_id, task["data"])
            else:
                logger.warning(f"Unknown task type: {task_type}")
                return
            
            # Record success metrics
            duration = time.time() - start_time
            self.metrics.record_task_completed(worker_id, task_type, duration, True)
            logger.info(f"Task {task_id} completed in {duration:.2f}s")
            
        except Exception as e:
            duration = time.time() - start_time
            self.metrics.record_task_completed(worker_id, task_type, duration, False)
            logger.error(f"Task {task_id} failed after {duration:.2f}s: {e}")
            raise
    
    async def _process_audit_task(self, tenant_id: str, data: Dict[str, Any]):
        """Process security audit task"""
        audit_type = data.get("audit_type", "comprehensive")
        targets = data.get("targets", [])
        
        logger.info(f"Processing audit task: {audit_type} for tenant {tenant_id}")
        
        # Run audit in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            self.executor,
            self._run_audit_sync,
            tenant_id,
            audit_type,
            targets
        )
        
        logger.info(f"Audit completed for tenant {tenant_id}: {len(result.get('findings', []))} findings")
    
    def _run_audit_sync(self, tenant_id: str, audit_type: str, targets: list) -> Dict[str, Any]:
        """Synchronous audit execution"""
        # Mock audit implementation
        import random
        
        findings = []
        for target in targets:
            # Generate mock findings
            num_findings = random.randint(0, 5)
            for i in range(num_findings):
                findings.append({
                    "id": f"finding-{target}-{i}",
                    "target": target,
                    "severity": random.choice(["low", "medium", "high", "critical"]),
                    "title": f"Security issue {i+1}",
                    "description": f"Mock security finding for {target}"
                })
        
        return {
            "tenant_id": tenant_id,
            "audit_type": audit_type,
            "targets": targets,
            "findings": findings,
            "completed_at": time.time()
        }
    
    async def _process_compliance_task(self, tenant_id: str, data: Dict[str, Any]):
        """Process compliance check task"""
        framework = data.get("framework", "soc2")
        controls = data.get("controls", [])
        
        logger.info(f"Processing compliance task: {framework} for tenant {tenant_id}")
        
        # Mock compliance processing
        await asyncio.sleep(2)  # Simulate work
        
        logger.info(f"Compliance check completed for tenant {tenant_id}")
    
    async def _process_report_task(self, tenant_id: str, data: Dict[str, Any]):
        """Process report generation task"""
        report_type = data.get("type", "compliance")
        format_type = data.get("format", "pdf")
        
        logger.info(f"Processing report task: {report_type} ({format_type}) for tenant {tenant_id}")
        
        # Mock report generation
        await asyncio.sleep(5)  # Simulate work
        
        logger.info(f"Report generated for tenant {tenant_id}")
    
    async def _process_threat_task(self, tenant_id: str, data: Dict[str, Any]):
        """Process threat analysis task"""
        indicators = data.get("indicators", [])
        
        logger.info(f"Processing threat analysis for tenant {tenant_id}")
        
        # Mock threat analysis
        await asyncio.sleep(3)  # Simulate work
        
        logger.info(f"Threat analysis completed for tenant {tenant_id}")

def setup_signal_handlers(worker: AuditWorker):
    """Setup signal handlers for graceful shutdown"""
    
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, initiating shutdown...")
        asyncio.create_task(worker.stop())
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

async def main():
    """Main worker entry point"""
    parser = argparse.ArgumentParser(description="AuditHound Worker Service")
    parser.add_argument("--concurrency", type=int, default=4, help="Number of concurrent workers")
    parser.add_argument("--queue", default="audithound-tasks", help="Task queue name")
    
    args = parser.parse_args()
    
    # Create and initialize worker
    worker = AuditWorker(concurrency=args.concurrency)
    setup_signal_handlers(worker)
    
    try:
        await worker.initialize()
        await worker.start()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Worker error: {e}")
    finally:
        await worker.stop()

if __name__ == "__main__":
    asyncio.run(main())