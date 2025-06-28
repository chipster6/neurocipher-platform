#!/usr/bin/env python3
"""
Chat Notifications for SOC Integration
Supports Slack, Mattermost, and Microsoft Teams for real-time security alerts
"""

import json
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Union
import requests
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class NotificationPriority(Enum):
    """Notification priority levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class NotificationChannel(Enum):
    """Supported notification channels"""
    SLACK = "slack"
    MATTERMOST = "mattermost"
    TEAMS = "teams"
    DISCORD = "discord"

@dataclass
class NotificationConfig:
    """Configuration for notification channels"""
    channel_type: NotificationChannel
    webhook_url: str
    channel_name: str
    enabled: bool = True
    priority_filter: List[NotificationPriority] = None
    mention_users: List[str] = None
    
    def __post_init__(self):
        if self.priority_filter is None:
            self.priority_filter = [NotificationPriority.CRITICAL, NotificationPriority.HIGH]

class ChatNotificationManager:
    """
    Manages chat notifications across multiple platforms
    """
    
    def __init__(self, configs: List[NotificationConfig]):
        """
        Initialize notification manager
        
        Args:
            configs: List of notification channel configurations
        """
        self.configs = {config.channel_type: config for config in configs}
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'AuditHound-SOC-Notifications/1.0'
        })
        
        logger.info(f"Initialized chat notifications for {len(self.configs)} channels")
    
    async def send_finding_alert(self, finding: Dict, priority: NotificationPriority = NotificationPriority.HIGH):
        """
        Send finding alert to configured channels
        
        Args:
            finding: Finding dictionary with details
            priority: Notification priority level
        """
        try:
            # Prepare notification content
            content = self._prepare_finding_content(finding, priority)
            
            # Send to all configured channels that match priority filter
            tasks = []
            for channel_type, config in self.configs.items():
                if (config.enabled and 
                    priority in config.priority_filter):
                    
                    task = self._send_to_channel(config, content, priority)
                    tasks.append(task)
            
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                success_count = sum(1 for r in results if not isinstance(r, Exception))
                logger.info(f"Sent finding alert to {success_count}/{len(tasks)} channels")
            
        except Exception as e:
            logger.error(f"Error sending finding alert: {str(e)}")
    
    async def send_scan_summary(self, scan_result: Dict):
        """
        Send scan completion summary
        
        Args:
            scan_result: Scan result dictionary
        """
        try:
            content = self._prepare_scan_summary_content(scan_result)
            priority = self._determine_scan_priority(scan_result)
            
            tasks = []
            for channel_type, config in self.configs.items():
                if (config.enabled and 
                    priority in config.priority_filter):
                    
                    task = self._send_to_channel(config, content, priority)
                    tasks.append(task)
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
                logger.info(f"Sent scan summary to {len(tasks)} channels")
            
        except Exception as e:
            logger.error(f"Error sending scan summary: {str(e)}")
    
    async def send_threat_intelligence_alert(self, ioc_data: Dict, correlation_results: Dict):
        """
        Send threat intelligence correlation alert
        
        Args:
            ioc_data: IOC information
            correlation_results: Threat intelligence correlation results
        """
        try:
            content = self._prepare_threat_intel_content(ioc_data, correlation_results)
            priority = self._determine_threat_intel_priority(correlation_results)
            
            tasks = []
            for channel_type, config in self.configs.items():
                if (config.enabled and 
                    priority in config.priority_filter):
                    
                    task = self._send_to_channel(config, content, priority)
                    tasks.append(task)
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
                logger.info(f"Sent threat intelligence alert to {len(tasks)} channels")
            
        except Exception as e:
            logger.error(f"Error sending threat intelligence alert: {str(e)}")
    
    async def send_soc_workflow_update(self, workflow_type: str, details: Dict):
        """
        Send SOC workflow status updates
        
        Args:
            workflow_type: Type of workflow (misp_submission, thehive_case, etc.)
            details: Workflow details
        """
        try:
            content = self._prepare_workflow_content(workflow_type, details)
            priority = NotificationPriority.INFO
            
            tasks = []
            for channel_type, config in self.configs.items():
                if (config.enabled and 
                    priority in config.priority_filter):
                    
                    task = self._send_to_channel(config, content, priority)
                    tasks.append(task)
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
                logger.info(f"Sent workflow update to {len(tasks)} channels")
            
        except Exception as e:
            logger.error(f"Error sending workflow update: {str(e)}")
    
    async def _send_to_channel(self, config: NotificationConfig, content: Dict, priority: NotificationPriority):
        """Send notification to specific channel"""
        try:
            if config.channel_type == NotificationChannel.SLACK:
                await self._send_slack_message(config, content, priority)
            elif config.channel_type == NotificationChannel.MATTERMOST:
                await self._send_mattermost_message(config, content, priority)
            elif config.channel_type == NotificationChannel.TEAMS:
                await self._send_teams_message(config, content, priority)
            elif config.channel_type == NotificationChannel.DISCORD:
                await self._send_discord_message(config, content, priority)
            else:
                logger.warning(f"Unsupported channel type: {config.channel_type}")
                
        except Exception as e:
            logger.error(f"Failed to send to {config.channel_type}: {str(e)}")
            raise
    
    async def _send_slack_message(self, config: NotificationConfig, content: Dict, priority: NotificationPriority):
        """Send message to Slack"""
        # Build Slack message format
        color_map = {
            NotificationPriority.CRITICAL: "#FF0000",
            NotificationPriority.HIGH: "#FF8C00",
            NotificationPriority.MEDIUM: "#FFD700",
            NotificationPriority.LOW: "#32CD32",
            NotificationPriority.INFO: "#1E90FF"
        }
        
        mentions = ""
        if config.mention_users and priority in [NotificationPriority.CRITICAL, NotificationPriority.HIGH]:
            mentions = " " + " ".join(f"<@{user}>" for user in config.mention_users)
        
        slack_payload = {
            "channel": config.channel_name,
            "username": "AuditHound",
            "icon_emoji": ":shield:",
            "text": f"🚨 *AuditHound Security Alert*{mentions}",
            "attachments": [
                {
                    "color": color_map.get(priority, "#1E90FF"),
                    "title": content["title"],
                    "text": content["description"],
                    "fields": content.get("fields", []),
                    "footer": "AuditHound Security Platform",
                    "ts": int(datetime.now().timestamp())
                }
            ]
        }
        
        response = self.session.post(config.webhook_url, json=slack_payload, timeout=10)
        response.raise_for_status()
        
        logger.debug(f"Successfully sent Slack notification to {config.channel_name}")
    
    async def _send_mattermost_message(self, config: NotificationConfig, content: Dict, priority: NotificationPriority):
        """Send message to Mattermost"""
        icon_map = {
            NotificationPriority.CRITICAL: ":exclamation:",
            NotificationPriority.HIGH: ":warning:",
            NotificationPriority.MEDIUM: ":information_source:",
            NotificationPriority.LOW: ":white_check_mark:",
            NotificationPriority.INFO: ":information_source:"
        }
        
        mentions = ""
        if config.mention_users and priority in [NotificationPriority.CRITICAL, NotificationPriority.HIGH]:
            mentions = " " + " ".join(f"@{user}" for user in config.mention_users)
        
        # Format as Markdown for Mattermost
        fields_text = ""
        if content.get("fields"):
            fields_text = "\n".join([
                f"**{field['title']}:** {field['value']}"
                for field in content["fields"]
            ])
        
        mattermost_text = f"""
{icon_map.get(priority, ':information_source:')} **AuditHound Security Alert**{mentions}

### {content['title']}

{content['description']}

{fields_text}

---
*AuditHound Security Platform* | {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
        """.strip()
        
        mattermost_payload = {
            "channel": config.channel_name,
            "username": "AuditHound",
            "icon_url": "https://audithound.com/icon.png",
            "text": mattermost_text
        }
        
        response = self.session.post(config.webhook_url, json=mattermost_payload, timeout=10)
        response.raise_for_status()
        
        logger.debug(f"Successfully sent Mattermost notification to {config.channel_name}")
    
    async def _send_teams_message(self, config: NotificationConfig, content: Dict, priority: NotificationPriority):
        """Send message to Microsoft Teams"""
        color_map = {
            NotificationPriority.CRITICAL: "FF0000",
            NotificationPriority.HIGH: "FF8C00",
            NotificationPriority.MEDIUM: "FFD700",
            NotificationPriority.LOW: "32CD32",
            NotificationPriority.INFO: "1E90FF"
        }
        
        # Build Teams adaptive card
        facts = []
        if content.get("fields"):
            facts = [
                {"name": field["title"], "value": field["value"]}
                for field in content["fields"]
            ]
        
        teams_payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color_map.get(priority, "1E90FF"),
            "summary": content["title"],
            "sections": [
                {
                    "activityTitle": "🛡️ AuditHound Security Alert",
                    "activitySubtitle": datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "activityImage": "https://audithound.com/icon.png",
                    "facts": facts,
                    "markdown": True
                },
                {
                    "text": content["description"]
                }
            ]
        }
        
        response = self.session.post(config.webhook_url, json=teams_payload, timeout=10)
        response.raise_for_status()
        
        logger.debug(f"Successfully sent Teams notification")
    
    async def _send_discord_message(self, config: NotificationConfig, content: Dict, priority: NotificationPriority):
        """Send message to Discord"""
        color_map = {
            NotificationPriority.CRITICAL: 0xFF0000,
            NotificationPriority.HIGH: 0xFF8C00,
            NotificationPriority.MEDIUM: 0xFFD700,
            NotificationPriority.LOW: 0x32CD32,
            NotificationPriority.INFO: 0x1E90FF
        }
        
        embed_fields = []
        if content.get("fields"):
            embed_fields = [
                {"name": field["title"], "value": field["value"], "inline": True}
                for field in content["fields"]
            ]
        
        discord_payload = {
            "username": "AuditHound",
            "avatar_url": "https://audithound.com/icon.png",
            "embeds": [
                {
                    "title": content["title"],
                    "description": content["description"],
                    "color": color_map.get(priority, 0x1E90FF),
                    "fields": embed_fields,
                    "footer": {
                        "text": "AuditHound Security Platform"
                    },
                    "timestamp": datetime.now().isoformat()
                }
            ]
        }
        
        response = self.session.post(config.webhook_url, json=discord_payload, timeout=10)
        response.raise_for_status()
        
        logger.debug(f"Successfully sent Discord notification")
    
    def _prepare_finding_content(self, finding: Dict, priority: NotificationPriority) -> Dict:
        """Prepare content for finding alerts"""
        fields = [
            {"title": "Finding Type", "value": finding.get("finding_type", "Unknown"), "short": True},
            {"title": "Severity", "value": finding.get("severity", "Unknown"), "short": True},
            {"title": "Risk Score", "value": f"{finding.get('risk_score', 0):.1f}/100", "short": True},
            {"title": "Status", "value": finding.get("status", "Unknown"), "short": True}
        ]
        
        # Add compliance specific fields
        if finding.get("control_id"):
            fields.append({
                "title": "Control", 
                "value": f"{finding['control_id']} ({finding.get('compliance_framework', 'Unknown')})",
                "short": True
            })
        
        # Add threat specific fields
        if finding.get("mitre_techniques"):
            fields.append({
                "title": "MITRE Techniques",
                "value": ", ".join(finding["mitre_techniques"][:3]),
                "short": True
            })
        
        # Add affected assets
        if finding.get("affected_assets"):
            asset_count = len(finding["affected_assets"])
            fields.append({
                "title": "Affected Assets",
                "value": f"{asset_count} asset(s)",
                "short": True
            })
        
        return {
            "title": finding.get("title", "Security Finding"),
            "description": finding.get("description", "No description available"),
            "fields": fields
        }
    
    def _prepare_scan_summary_content(self, scan_result: Dict) -> Dict:
        """Prepare content for scan summary"""
        fields = [
            {"title": "Scan ID", "value": scan_result.get("scan_id", "Unknown"), "short": True},
            {"title": "Scan Type", "value": scan_result.get("scan_type", "Unknown"), "short": True},
            {"title": "Duration", "value": f"{scan_result.get('duration_minutes', 0):.1f} minutes", "short": True},
            {"title": "Assets Scanned", "value": str(scan_result.get("assets_scanned", 0)), "short": True},
            {"title": "Total Findings", "value": str(scan_result.get("total_findings", 0)), "short": True},
            {"title": "Critical Findings", "value": str(scan_result.get("critical_findings", 0)), "short": True},
            {"title": "Overall Compliance", "value": f"{scan_result.get('overall_compliance_score', 0):.1f}%", "short": True},
            {"title": "Overall Threat Score", "value": f"{scan_result.get('overall_threat_score', 0):.1f}%", "short": True}
        ]
        
        return {
            "title": f"Scan Completed: {scan_result.get('scan_id', 'Unknown')}",
            "description": f"Unified security scan has completed with {scan_result.get('total_findings', 0)} findings identified.",
            "fields": fields
        }
    
    def _prepare_threat_intel_content(self, ioc_data: Dict, correlation_results: Dict) -> Dict:
        """Prepare content for threat intelligence alerts"""
        fields = [
            {"title": "IOC Type", "value": ioc_data.get("ioc_type", "Unknown"), "short": True},
            {"title": "IOC Value", "value": ioc_data.get("ioc_value", "Unknown"), "short": False},
            {"title": "Threat Score", "value": f"{correlation_results.get('threat_score', 0):.1f}/100", "short": True},
            {"title": "Sources", "value": str(len(correlation_results.get("sources", []))), "short": True}
        ]
        
        if correlation_results.get("recommendations"):
            rec_text = "\n".join([f"• {rec}" for rec in correlation_results["recommendations"][:3]])
            fields.append({
                "title": "Recommendations",
                "value": rec_text,
                "short": False
            })
        
        return {
            "title": "Threat Intelligence Match",
            "description": f"IOC correlation found threat intelligence for {ioc_data.get('ioc_value', 'unknown IOC')}",
            "fields": fields
        }
    
    def _prepare_workflow_content(self, workflow_type: str, details: Dict) -> Dict:
        """Prepare content for workflow updates"""
        workflow_names = {
            "misp_submission": "MISP Event Created",
            "thehive_case": "TheHive Case Created",
            "scan_started": "Security Scan Started",
            "scan_completed": "Security Scan Completed"
        }
        
        fields = []
        for key, value in details.items():
            if key not in ["title", "description"]:
                fields.append({
                    "title": key.replace("_", " ").title(),
                    "value": str(value),
                    "short": True
                })
        
        return {
            "title": workflow_names.get(workflow_type, f"Workflow: {workflow_type}"),
            "description": details.get("description", f"SOC workflow {workflow_type} has been executed"),
            "fields": fields
        }
    
    def _determine_scan_priority(self, scan_result: Dict) -> NotificationPriority:
        """Determine priority based on scan results"""
        critical_findings = scan_result.get("critical_findings", 0)
        total_findings = scan_result.get("total_findings", 0)
        compliance_score = scan_result.get("overall_compliance_score", 100)
        
        if critical_findings > 0 or compliance_score < 50:
            return NotificationPriority.CRITICAL
        elif total_findings > 10 or compliance_score < 70:
            return NotificationPriority.HIGH
        elif total_findings > 5:
            return NotificationPriority.MEDIUM
        else:
            return NotificationPriority.INFO
    
    def _determine_threat_intel_priority(self, correlation_results: Dict) -> NotificationPriority:
        """Determine priority based on threat intelligence correlation"""
        threat_score = correlation_results.get("threat_score", 0)
        
        if threat_score >= 80:
            return NotificationPriority.CRITICAL
        elif threat_score >= 60:
            return NotificationPriority.HIGH
        elif threat_score >= 40:
            return NotificationPriority.MEDIUM
        else:
            return NotificationPriority.INFO

# Factory function for creating notification manager
def create_notification_manager(config: Dict) -> Optional[ChatNotificationManager]:
    """
    Create notification manager from configuration
    
    Args:
        config: Configuration dictionary
        
    Returns:
        ChatNotificationManager instance or None if no valid configs
    """
    configs = []
    
    # Load Slack configuration
    slack_config = config.get("notifications", {}).get("slack", {})
    if slack_config.get("enabled", False):
        configs.append(NotificationConfig(
            channel_type=NotificationChannel.SLACK,
            webhook_url=slack_config["webhook_url"],
            channel_name=slack_config.get("channel", "#security"),
            enabled=True,
            mention_users=slack_config.get("mention_users", [])
        ))
    
    # Load Mattermost configuration
    mattermost_config = config.get("notifications", {}).get("mattermost", {})
    if mattermost_config.get("enabled", False):
        configs.append(NotificationConfig(
            channel_type=NotificationChannel.MATTERMOST,
            webhook_url=mattermost_config["webhook_url"],
            channel_name=mattermost_config.get("channel", "security"),
            enabled=True,
            mention_users=mattermost_config.get("mention_users", [])
        ))
    
    # Load Teams configuration
    teams_config = config.get("notifications", {}).get("teams", {})
    if teams_config.get("enabled", False):
        configs.append(NotificationConfig(
            channel_type=NotificationChannel.TEAMS,
            webhook_url=teams_config["webhook_url"],
            channel_name="Security Team",
            enabled=True
        ))
    
    if configs:
        return ChatNotificationManager(configs)
    else:
        logger.warning("No notification channels configured")
        return None

# Example usage and testing
if __name__ == "__main__":
    import asyncio
    import os
    
    # Test notification system
    sample_configs = [
        NotificationConfig(
            channel_type=NotificationChannel.SLACK,
            webhook_url=os.getenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"),
            channel_name="#security",
            mention_users=["security-team"]
        )
    ]
    
    async def test_notifications():
        manager = ChatNotificationManager(sample_configs)
        
        # Test finding alert
        sample_finding = {
            "finding_id": "test-123",
            "title": "Critical Security Violation",
            "description": "Multiple failed login attempts detected",
            "finding_type": "threat",
            "severity": "critical",
            "risk_score": 85.5,
            "status": "active",
            "affected_assets": ["server-01", "server-02"],
            "mitre_techniques": ["T1110", "T1078"]
        }
        
        await manager.send_finding_alert(sample_finding, NotificationPriority.CRITICAL)
        print("✅ Test notification sent successfully")
    
    if os.getenv("SLACK_WEBHOOK_URL"):
        asyncio.run(test_notifications())
    else:
        print("Set SLACK_WEBHOOK_URL environment variable to test notifications")