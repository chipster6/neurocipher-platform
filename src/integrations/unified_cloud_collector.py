#!/usr/bin/env python3
"""
Unified Multi-Cloud Security Data Collector
Orchestrates evidence collection across AWS, GCP, and Azure with parallel processing
"""

import asyncio
import sys
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from .aws_integration_enhanced import AWSSecurityCollector, AWSConfig, create_aws_collector
from .gcp_integration_enhanced import GCPSecurityCollector, GCPConfig, create_gcp_collector
from .azure_integration_enhanced import AzureSecurityCollector, AzureConfig, create_azure_collector
from ..compliance.mapping_enhanced import EnhancedComplianceMappingMatrix, CloudProvider, ComplianceFramework

@dataclass
class UnifiedCloudConfig:
    """Configuration for unified multi-cloud collection"""
    aws_config: Optional[AWSConfig] = None
    gcp_config: Optional[GCPConfig] = None
    azure_config: Optional[AzureConfig] = None
    enabled_providers: List[str] = field(default_factory=lambda: ["aws", "gcp", "azure"])
    parallel_execution: bool = True
    timeout_seconds: int = 300
    include_recommendations: bool = True

class UnifiedCloudCollector:
    """Orchestrates security data collection across multiple cloud providers"""
    
    def __init__(self, config: UnifiedCloudConfig):
        self.config = config
        self.collectors = {}
        self.mapping_matrix = EnhancedComplianceMappingMatrix()
        
        # Initialize collectors for enabled providers
        self._initialize_collectors()
    
    def _initialize_collectors(self):
        """Initialize collectors for enabled cloud providers"""
        if "aws" in self.config.enabled_providers and self.config.aws_config:
            try:
                self.collectors["aws"] = AWSSecurityCollector(self.config.aws_config)
                print("✅ AWS collector initialized")
            except Exception as e:
                print(f"⚠️ AWS collector initialization failed: {e}")
        
        if "gcp" in self.config.enabled_providers and self.config.gcp_config:
            try:
                self.collectors["gcp"] = GCPSecurityCollector(self.config.gcp_config)
                print("✅ GCP collector initialized")
            except Exception as e:
                print(f"⚠️ GCP collector initialization failed: {e}")
        
        if "azure" in self.config.enabled_providers and self.config.azure_config:
            try:
                self.collectors["azure"] = AzureSecurityCollector(self.config.azure_config)
                print("✅ Azure collector initialized")
            except Exception as e:
                print(f"⚠️ Azure collector initialization failed: {e}")
    
    def authenticate_all_providers(self) -> Dict[str, bool]:
        """Test authentication with all configured providers"""
        results = {}
        
        for provider, collector in self.collectors.items():
            try:
                results[provider] = collector.authenticate()
            except Exception as e:
                print(f"❌ {provider.upper()} authentication failed: {e}")
                results[provider] = False
        
        return results
    
    def collect_soc2_evidence(self, controls: List[str] = None) -> Dict[str, Any]:
        """Collect SOC 2 evidence across all providers"""
        if controls is None:
            controls = ["CC6.1", "CC6.2", "CC6.3", "CC7.1", "CC8.1"]
        
        print(f"🔍 Collecting SOC 2 evidence for controls: {controls}")
        
        evidence_results = {}
        collection_start = datetime.now()
        
        for control_id in controls:
            print(f"\n📋 Collecting evidence for {control_id}...")
            control_evidence = self._collect_control_evidence(control_id)
            
            # Normalize evidence across providers
            normalized_evidence = self.mapping_matrix.normalize_evidence_across_providers(
                control_id, control_evidence
            )
            
            evidence_results[control_id] = normalized_evidence
        
        collection_end = datetime.now()
        collection_time = (collection_end - collection_start).total_seconds()
        
        # Create unified report
        unified_report = {
            "collection_metadata": {
                "timestamp": collection_end.isoformat(),
                "collection_time_seconds": collection_time,
                "providers_included": list(self.collectors.keys()),
                "controls_assessed": controls,
                "framework": "SOC2"
            },
            "controls": evidence_results,
            "summary": self._generate_summary(evidence_results),
            "recommendations": self._generate_unified_recommendations(evidence_results) if self.config.include_recommendations else []
        }
        
        return unified_report
    
    def _collect_control_evidence(self, control_id: str) -> Dict[str, Any]:
        """Collect evidence for a specific control across all providers"""
        control_evidence = {}
        
        if self.config.parallel_execution:
            # Parallel execution across providers
            with ThreadPoolExecutor(max_workers=len(self.collectors)) as executor:
                future_to_provider = {}
                
                for provider, collector in self.collectors.items():
                    future = executor.submit(self._collect_provider_evidence, provider, collector, control_id)
                    future_to_provider[future] = provider
                
                for future in as_completed(future_to_provider, timeout=self.config.timeout_seconds):
                    provider = future_to_provider[future]
                    try:
                        evidence = future.result()
                        control_evidence[provider] = evidence
                        print(f"  ✅ {provider.upper()} evidence collected")
                    except Exception as e:
                        print(f"  ❌ {provider.upper()} evidence collection failed: {e}")
                        control_evidence[provider] = {"error": str(e)}
        else:
            # Sequential execution
            for provider, collector in self.collectors.items():
                try:
                    evidence = self._collect_provider_evidence(provider, collector, control_id)
                    control_evidence[provider] = evidence
                    print(f"  ✅ {provider.upper()} evidence collected")
                except Exception as e:
                    print(f"  ❌ {provider.upper()} evidence collection failed: {e}")
                    control_evidence[provider] = {"error": str(e)}
        
        return control_evidence
    
    def _collect_provider_evidence(self, provider: str, collector: Any, control_id: str) -> Dict[str, Any]:
        """Collect evidence from a specific provider for a control"""
        collection_method = self.mapping_matrix.get_collection_method(
            control_id, CloudProvider(provider)
        )
        
        if not collection_method:
            return {"error": f"No collection method defined for {control_id} on {provider}"}
        
        if hasattr(collector, collection_method):
            method = getattr(collector, collection_method)
            return method()
        else:
            return {"error": f"Collection method {collection_method} not found on {provider} collector"}
    
    def _generate_summary(self, evidence_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a summary of compliance results"""
        total_controls = len(evidence_results)
        compliant_controls = sum(1 for result in evidence_results.values() 
                               if result.get("compliance_status") == "compliant")
        partial_controls = sum(1 for result in evidence_results.values() 
                             if result.get("compliance_status") == "partial")
        non_compliant_controls = sum(1 for result in evidence_results.values() 
                                   if result.get("compliance_status") == "non_compliant")
        
        overall_score = sum(result.get("unified_score", 0) for result in evidence_results.values()) / total_controls if total_controls > 0 else 0
        
        provider_scores = {}
        for provider in self.collectors.keys():
            provider_total = 0
            provider_count = 0
            for result in evidence_results.values():
                provider_data = result.get("providers", {}).get(provider, {})
                if "score" in provider_data:
                    provider_total += provider_data["score"]
                    provider_count += 1
            
            if provider_count > 0:
                provider_scores[provider] = provider_total / provider_count
        
        return {
            "overall_compliance_score": overall_score,
            "compliance_status_distribution": {
                "compliant": compliant_controls,
                "partial": partial_controls,
                "non_compliant": non_compliant_controls,
                "total": total_controls
            },
            "compliance_percentage": (compliant_controls / total_controls * 100) if total_controls > 0 else 0,
            "provider_scores": provider_scores,
            "risk_level": self._calculate_risk_level(overall_score),
            "areas_needing_attention": self._identify_problem_areas(evidence_results)
        }
    
    def _calculate_risk_level(self, score: float) -> str:
        """Calculate overall risk level based on compliance score"""
        if score >= 90:
            return "Low"
        elif score >= 70:
            return "Medium"
        elif score >= 50:
            return "High"
        else:
            return "Critical"
    
    def _identify_problem_areas(self, evidence_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify controls and providers with compliance issues"""
        problem_areas = []
        
        for control_id, result in evidence_results.items():
            if result.get("compliance_status") in ["partial", "non_compliant"]:
                control = self.mapping_matrix.get_control_mapping(control_id)
                
                problem_area = {
                    "control_id": control_id,
                    "title": control.title if control else "Unknown",
                    "score": result.get("unified_score", 0),
                    "status": result.get("compliance_status", "unknown"),
                    "risk_level": control.risk_level if control else "Unknown",
                    "affected_providers": []
                }
                
                # Identify which providers have issues
                for provider, provider_data in result.get("providers", {}).items():
                    if provider_data.get("status") in ["partial", "non_compliant"]:
                        problem_area["affected_providers"].append({
                            "provider": provider,
                            "score": provider_data.get("score", 0),
                            "status": provider_data.get("status", "unknown")
                        })
                
                problem_areas.append(problem_area)
        
        # Sort by score (lowest first)
        problem_areas.sort(key=lambda x: x["score"])
        
        return problem_areas
    
    def _generate_unified_recommendations(self, evidence_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate unified recommendations across all controls and providers"""
        all_recommendations = []
        
        for control_id, result in evidence_results.items():
            control = self.mapping_matrix.get_control_mapping(control_id)
            
            for provider, provider_data in result.get("providers", {}).items():
                if "recommendations" in provider_data.get("evidence", {}):
                    provider_recommendations = provider_data["evidence"]["recommendations"]
                    
                    for rec in provider_recommendations:
                        all_recommendations.append({
                            "control_id": control_id,
                            "control_title": control.title if control else "Unknown",
                            "provider": provider,
                            "recommendation": rec,
                            "priority": self._calculate_recommendation_priority(control_id, provider_data.get("score", 0)),
                            "category": control.category if control else "Unknown"
                        })
        
        # Sort by priority and deduplicate similar recommendations
        all_recommendations.sort(key=lambda x: (x["priority"], x["control_id"]))
        
        return self._deduplicate_recommendations(all_recommendations)
    
    def _calculate_recommendation_priority(self, control_id: str, score: float) -> int:
        """Calculate priority for recommendations (1=highest, 3=lowest)"""
        control = self.mapping_matrix.get_control_mapping(control_id)
        
        # High priority for critical controls with low scores
        if control and control.risk_level == "High" and score < 50:
            return 1
        elif score < 70:
            return 2
        else:
            return 3
    
    def _deduplicate_recommendations(self, recommendations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate recommendations and consolidate similar ones"""
        seen_recommendations = set()
        deduplicated = []
        
        for rec in recommendations:
            # Create a key based on recommendation text (simplified)
            key = rec["recommendation"].lower().replace(" ", "")[:50]
            
            if key not in seen_recommendations:
                seen_recommendations.add(key)
                deduplicated.append(rec)
        
        return deduplicated[:20]  # Limit to top 20 recommendations
    
    def collect_comprehensive_inventory(self) -> Dict[str, Any]:
        """Collect comprehensive asset inventory across all providers"""
        inventory = {
            "collection_timestamp": datetime.now().isoformat(),
            "providers": {}
        }
        
        print("📦 Collecting comprehensive asset inventory...")
        
        for provider, collector in self.collectors.items():
            print(f"  📋 Collecting {provider.upper()} inventory...")
            
            provider_inventory = {}
            
            try:
                if provider == "aws":
                    provider_inventory.update({
                        "account_summary": collector.collect_account_summary(),
                        "s3_security": collector.collect_s3_security(),
                        "cloudtrail_config": collector.collect_cloudtrail_config(),
                        "config_rules": collector.collect_config_rules(),
                        "security_hub_findings": collector.collect_security_hub_findings()
                    })
                elif provider == "gcp":
                    provider_inventory.update({
                        "organization_policies": collector.collect_organization_policies(),
                        "storage_security": collector.collect_storage_security(),
                        "compute_security": collector.collect_compute_security(),
                        "cloud_logging": collector.collect_cloud_logging_config()
                    })
                elif provider == "azure":
                    provider_inventory.update({
                        "storage_security": collector.collect_storage_security(),
                        "network_security": collector.collect_network_security(),
                        "key_vault_security": collector.collect_key_vault_security(),
                        "activity_logs": collector.collect_activity_logs()
                    })
                
                inventory["providers"][provider] = provider_inventory
                print(f"    ✅ {provider.upper()} inventory collected")
                
            except Exception as e:
                print(f"    ❌ {provider.upper()} inventory collection failed: {e}")
                inventory["providers"][provider] = {"error": str(e)}
        
        return inventory
    
    async def collect_evidence_async(self, controls: List[str] = None) -> Dict[str, Any]:
        """Asynchronous evidence collection for better performance"""
        return await asyncio.get_event_loop().run_in_executor(
            None, self.collect_soc2_evidence, controls
        )
    
    def export_evidence_report(self, evidence_data: Dict[str, Any], format_type: str = "json") -> str:
        """Export evidence report in various formats"""
        if format_type == "json":
            import json
            return json.dumps(evidence_data, indent=2, default=str)
        
        elif format_type == "markdown":
            return self._generate_markdown_report(evidence_data)
        
        elif format_type == "csv":
            return self._generate_csv_report(evidence_data)
        
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
    
    def _generate_markdown_report(self, evidence_data: Dict[str, Any]) -> str:
        """Generate a markdown compliance report"""
        metadata = evidence_data.get("collection_metadata", {})
        summary = evidence_data.get("summary", {})
        controls = evidence_data.get("controls", {})
        
        report = f"""# SOC 2 Compliance Report

## Executive Summary

**Generated:** {metadata.get('timestamp', 'Unknown')}  
**Collection Time:** {metadata.get('collection_time_seconds', 0):.1f} seconds  
**Providers:** {', '.join(metadata.get('providers_included', []))}  
**Overall Score:** {summary.get('overall_compliance_score', 0):.1f}%  
**Risk Level:** {summary.get('risk_level', 'Unknown')}  

### Compliance Status Distribution
- ✅ **Compliant:** {summary.get('compliance_status_distribution', {}).get('compliant', 0)} controls
- ⚠️ **Partial:** {summary.get('compliance_status_distribution', {}).get('partial', 0)} controls  
- ❌ **Non-Compliant:** {summary.get('compliance_status_distribution', {}).get('non_compliant', 0)} controls

## Control Assessment Results

"""
        
        for control_id, control_data in controls.items():
            score = control_data.get('unified_score', 0)
            status = control_data.get('compliance_status', 'unknown')
            title = control_data.get('title', 'Unknown')
            
            status_icon = {"compliant": "✅", "partial": "⚠️", "non_compliant": "❌"}.get(status, "❓")
            
            report += f"""### {status_icon} {control_id}: {title}

**Score:** {score:.1f}%  
**Status:** {status.replace('_', ' ').title()}  

"""
            
            # Add provider-specific details
            for provider, provider_data in control_data.get("providers", {}).items():
                provider_score = provider_data.get("score", 0)
                provider_status = provider_data.get("status", "unknown")
                
                report += f"- **{provider.upper()}:** {provider_score:.1f}% ({provider_status})\n"
            
            report += "\n"
        
        # Add recommendations
        recommendations = evidence_data.get("recommendations", [])
        if recommendations:
            report += "## Recommendations\n\n"
            
            for i, rec in enumerate(recommendations[:10], 1):  # Top 10 recommendations
                priority = "🔴 High" if rec.get("priority") == 1 else "🟡 Medium" if rec.get("priority") == 2 else "🟢 Low"
                report += f"{i}. **[{rec.get('control_id')}]** {rec.get('recommendation')} ({priority})\n"
        
        return report
    
    def _generate_csv_report(self, evidence_data: Dict[str, Any]) -> str:
        """Generate a CSV compliance report"""
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            "Control ID", "Title", "Unified Score", "Status", "Category", "Risk Level",
            "AWS Score", "AWS Status", "GCP Score", "GCP Status", "Azure Score", "Azure Status"
        ])
        
        # Write control data
        for control_id, control_data in evidence_data.get("controls", {}).items():
            row = [
                control_id,
                control_data.get("title", ""),
                f"{control_data.get('unified_score', 0):.1f}",
                control_data.get("compliance_status", ""),
                control_data.get("category", ""),
                control_data.get("risk_level", "")
            ]
            
            # Add provider scores
            for provider in ["aws", "gcp", "azure"]:
                provider_data = control_data.get("providers", {}).get(provider, {})
                row.extend([
                    f"{provider_data.get('score', 0):.1f}",
                    provider_data.get("status", "not_assessed")
                ])
            
            writer.writerow(row)
        
        return output.getvalue()

# Factory functions for easy initialization
def create_unified_collector(
    aws_region: str = "us-west-2",
    aws_profile: str = None,
    gcp_project_id: str = None,
    gcp_credentials_path: str = None,
    azure_tenant_id: str = None,
    azure_subscription_id: str = None,
    enabled_providers: List[str] = None
) -> UnifiedCloudCollector:
    """Create a unified cloud collector with simplified configuration"""
    
    if enabled_providers is None:
        enabled_providers = []
        if aws_region:
            enabled_providers.append("aws")
        if gcp_project_id:
            enabled_providers.append("gcp")
        if azure_tenant_id and azure_subscription_id:
            enabled_providers.append("azure")
    
    # Create provider configs
    aws_config = AWSConfig(region=aws_region, profile_name=aws_profile) if "aws" in enabled_providers else None
    gcp_config = GCPConfig(project_id=gcp_project_id, credentials_path=gcp_credentials_path) if "gcp" in enabled_providers else None
    azure_config = AzureConfig(tenant_id=azure_tenant_id, subscription_id=azure_subscription_id) if "azure" in enabled_providers else None
    
    unified_config = UnifiedCloudConfig(
        aws_config=aws_config,
        gcp_config=gcp_config,
        azure_config=azure_config,
        enabled_providers=enabled_providers
    )
    
    return UnifiedCloudCollector(unified_config)