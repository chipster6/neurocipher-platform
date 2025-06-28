#!/usr/bin/env python3
"""
AuditHound Scheduler Service
Cron-like scheduler for periodic tasks
"""

import argparse
import asyncio
import signal
import sys
import os
from typing import Dict, List
from datetime import datetime, timedelta
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.observability.logger import get_logger, setup_logging
from src.observability.metrics import MetricsCollector

# Initialize logging
setup_logging()
logger = get_logger(__name__)

class ScheduledTask:
    """Represents a scheduled task"""
    
    def __init__(self, name: str, cron_expr: str, task_func, **kwargs):
        self.name = name
        self.cron_expr = cron_expr
        self.task_func = task_func
        self.kwargs = kwargs
        self.last_run = None
        self.next_run = None
        self.enabled = True
        
    def should_run(self) -> bool:
        """Check if task should run now"""
        if not self.enabled:
            return False
            
        now = datetime.now()
        
        # Simple interval-based scheduling (replace with proper cron parser)
        if self.cron_expr.startswith("@every"):
            interval_str = self.cron_expr.replace("@every ", "")
            
            if self.last_run is None:
                return True
                
            if "m" in interval_str:
                minutes = int(interval_str.replace("m", ""))
                return now >= self.last_run + timedelta(minutes=minutes)
            elif "h" in interval_str:
                hours = int(interval_str.replace("h", ""))
                return now >= self.last_run + timedelta(hours=hours)
            elif "d" in interval_str:
                days = int(interval_str.replace("d", ""))
                return now >= self.last_run + timedelta(days=days)
        
        return False
    
    async def run(self):
        """Execute the task"""
        logger.info(f"Running scheduled task: {self.name}")
        
        try:
            if asyncio.iscoroutinefunction(self.task_func):
                await self.task_func(**self.kwargs)
            else:
                self.task_func(**self.kwargs)
                
            self.last_run = datetime.now()
            logger.info(f"Task completed: {self.name}")
            
        except Exception as e:
            logger.error(f"Task failed: {self.name} - {e}")
            raise

class AuditScheduler:
    """AuditHound task scheduler"""
    
    def __init__(self, timezone: str = "UTC"):
        self.timezone = timezone
        self.tasks: List[ScheduledTask] = []
        self.metrics = MetricsCollector()
        self.running = False
    
    def add_task(self, name: str, cron_expr: str, task_func, **kwargs):
        """Add a scheduled task"""
        task = ScheduledTask(name, cron_expr, task_func, **kwargs)
        self.tasks.append(task)
        logger.info(f"Added scheduled task: {name} ({cron_expr})")
    
    def remove_task(self, name: str):
        """Remove a scheduled task"""
        self.tasks = [t for t in self.tasks if t.name != name]
        logger.info(f"Removed scheduled task: {name}")
    
    def enable_task(self, name: str):
        """Enable a scheduled task"""
        for task in self.tasks:
            if task.name == name:
                task.enabled = True
                logger.info(f"Enabled task: {name}")
                break
    
    def disable_task(self, name: str):
        """Disable a scheduled task"""
        for task in self.tasks:
            if task.name == name:
                task.enabled = False
                logger.info(f"Disabled task: {name}")
                break
    
    async def start(self):
        """Start the scheduler"""
        self.running = True
        logger.info("Starting AuditHound Scheduler...")
        
        # Register default tasks
        self._register_default_tasks()
        
        # Main scheduler loop
        while self.running:
            try:
                await self._check_and_run_tasks()
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                await asyncio.sleep(60)
        
        logger.info("Scheduler stopped")
    
    async def stop(self):
        """Stop the scheduler"""
        logger.info("Stopping scheduler...")
        self.running = False
    
    async def _check_and_run_tasks(self):
        """Check and run scheduled tasks"""
        for task in self.tasks:
            if task.should_run():
                try:
                    start_time = time.time()
                    await task.run()
                    
                    duration = time.time() - start_time
                    self.metrics.record_scheduled_task(task.name, duration, True)
                    
                except Exception as e:
                    duration = time.time() - start_time
                    self.metrics.record_scheduled_task(task.name, duration, False)
                    logger.error(f"Scheduled task failed: {task.name} - {e}")
    
    def _register_default_tasks(self):
        """Register default scheduled tasks"""
        
        # System health check every 5 minutes
        self.add_task(
            "system_health_check",
            "@every 5m",
            self._system_health_check
        )
        
        # Compliance check daily at 2 AM
        self.add_task(
            "daily_compliance_check",
            "@every 24h",
            self._daily_compliance_check
        )
        
        # Threat intelligence update every hour
        self.add_task(
            "threat_intel_update",
            "@every 1h",
            self._threat_intel_update
        )
        
        # Database maintenance weekly
        self.add_task(
            "database_maintenance",
            "@every 7d",
            self._database_maintenance
        )
        
        # Report generation monthly
        self.add_task(
            "monthly_reports",
            "@every 30d",
            self._generate_monthly_reports
        )
    
    async def _system_health_check(self):
        """Perform system health check"""
        logger.info("Performing system health check...")
        
        # Check system resources
        # Check database connections
        # Check external service connectivity
        
        # Mock implementation
        await asyncio.sleep(2)
        
        logger.info("System health check completed")
    
    async def _daily_compliance_check(self):
        """Perform daily compliance checks"""
        logger.info("Performing daily compliance check...")
        
        # Run compliance scans for all tenants
        # Generate compliance reports
        # Send notifications for critical issues
        
        # Mock implementation
        await asyncio.sleep(10)
        
        logger.info("Daily compliance check completed")
    
    async def _threat_intel_update(self):
        """Update threat intelligence feeds"""
        logger.info("Updating threat intelligence...")
        
        # Update MISP feeds
        # Refresh IOC databases
        # Update threat signatures
        
        # Mock implementation
        await asyncio.sleep(5)
        
        logger.info("Threat intelligence updated")
    
    async def _database_maintenance(self):
        """Perform database maintenance"""
        logger.info("Performing database maintenance...")
        
        # Clean up old data
        # Optimize indexes
        # Backup critical data
        
        # Mock implementation
        await asyncio.sleep(30)
        
        logger.info("Database maintenance completed")
    
    async def _generate_monthly_reports(self):
        """Generate monthly reports"""
        logger.info("Generating monthly reports...")
        
        # Generate compliance reports
        # Create executive summaries
        # Send to stakeholders
        
        # Mock implementation
        await asyncio.sleep(60)
        
        logger.info("Monthly reports generated")

def setup_signal_handlers(scheduler: AuditScheduler):
    """Setup signal handlers for graceful shutdown"""
    
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, initiating shutdown...")
        asyncio.create_task(scheduler.stop())
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

async def main():
    """Main scheduler entry point"""
    parser = argparse.ArgumentParser(description="AuditHound Scheduler Service")
    parser.add_argument("--timezone", default="UTC", help="Timezone for scheduling")
    
    args = parser.parse_args()
    
    # Create and start scheduler
    scheduler = AuditScheduler(timezone=args.timezone)
    setup_signal_handlers(scheduler)
    
    try:
        await scheduler.start()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Scheduler error: {e}")
    finally:
        await scheduler.stop()

if __name__ == "__main__":
    asyncio.run(main())