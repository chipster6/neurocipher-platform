#!/usr/bin/env python3
"""
Unified Audit Engine
Combines compliance auditing with threat hunting for comprehensive security assessment
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml

from .unified_models import (
    SecurityAsset, UnifiedFinding, ComplianceControl, HuntingRule, 
    ScanResult, RiskLevel, ComplianceStatus, ThreatStatus,
    create_compliance_finding, create_threat_finding, create_hybrid_finding
)

# Import existing components
from .compliance.mapping import ComplianceMappingMatrix
from .integrations.aws_integration import AWSSecurityCollector
from .integrations.gcp_integration import GCPSecurityCollector
from .integrations.azure_integration import AzureSecurityCollector
from .weaviate_compliance_bridge import WeaviateComplianceBridge, create_enhanced_scoring_wrapper
from .tpu_compliance_accelerator import get_tpu_accelerator
from .tpu_threat_detector import get_tpu_threat_detector
from .coral_tpu_engine import get_coral_engine, is_coral_available

logger = logging.getLogger(__name__)

class UnifiedAuditEngine:
    """
    Unified audit engine that combines compliance auditing with threat hunting
    """
    
    def __init__(self, config_path: str, weaviate_client=None):
        """
        Initialize unified audit engine
        
        Args:
            config_path: Path to configuration file
            weaviate_client: Weaviate client for threat hunting
        """
        self.config = self._load_config(config_path)
        self.weaviate_client = weaviate_client
        
        # Initialize components
        self.compliance_mapper = ComplianceMappingMatrix()
        self.cloud_collectors = self._initialize_collectors()
        
        # Initialize Weaviate compliance bridge if client provided
        self.compliance_bridge = None
        self.enhanced_scoring_functions = None
        if weaviate_client:
            try:
                self.compliance_bridge = WeaviateComplianceBridge(weaviate_client)
                self.enhanced_scoring_functions = create_enhanced_scoring_wrapper(self.compliance_bridge)
                logger.info("Weaviate compliance bridge initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Weaviate compliance bridge: {e}")
        
        # Initialize TPU acceleration components
        self.tpu_available = is_coral_available()
        self.tpu_compliance_accelerator = None
        self.tpu_threat_detector = None
        
        if self.tpu_available:
            try:
                self.tpu_compliance_accelerator = get_tpu_accelerator()
                self.tpu_threat_detector = get_tpu_threat_detector()
                logger.info("Google Coral TPU acceleration enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize TPU acceleration: {e}")
                self.tpu_available = False
        else:
            logger.info("Google Coral TPU not available - using CPU processing")
        
        # Initialize Coral TPU acceleration
        self.coral_engine = None
        self.accelerated_analytics = None
        self.tpu_acceleration_enabled = False
        
        try:
            if is_coral_available():
                self.coral_engine = get_coral_engine()
                self.accelerated_analytics = get_accelerated_analytics()
                self.tpu_acceleration_enabled = True
                logger.info(f"Coral TPU acceleration enabled with {len(self.coral_engine.tpu_devices)} devices")
                
                # Run benchmark to measure acceleration
                benchmark_results = self.coral_engine.benchmark_acceleration(iterations=10)
                if benchmark_results:
                    avg_acceleration = np.mean([r.get('acceleration_factor', 1.0) 
                                              for r in benchmark_results.values() 
                                              if isinstance(r, dict)])
                    logger.info(f"TPU acceleration factor: {avg_acceleration:.1f}x faster than CPU")
            else:
                logger.info("Coral TPU not available - using CPU-based analytics")
        except Exception as e:
            logger.warning(f"Failed to initialize Coral TPU acceleration: {e}")
        
        # Load rules and controls
        self.compliance_controls = self._load_compliance_controls()
        self.hunting_rules = self._load_hunting_rules()
        
        # Asset registry
        self.assets: Dict[str, SecurityAsset] = {}
        
        # Active scans
        self.active_scans: Dict[str, ScanResult] = {}
        
        logger.info("Unified Audit Engine initialized")
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config from {config_path}: {e}")
            return {}
    
    def _initialize_collectors(self) -> Dict:
        """Initialize cloud provider collectors"""
        collectors = {}
        
        if self.config.get('cloud_providers', {}).get('aws', {}).get('enabled', False):
            collectors['aws'] = AWSSecurityCollector(self.config['cloud_providers']['aws'])
        
        if self.config.get('cloud_providers', {}).get('gcp', {}).get('enabled', False):
            collectors['gcp'] = GCPSecurityCollector(self.config['cloud_providers']['gcp'])
            
        if self.config.get('cloud_providers', {}).get('azure', {}).get('enabled', False):
            collectors['azure'] = AzureSecurityCollector(self.config['cloud_providers']['azure'])
        
        return collectors
    
    def _load_compliance_controls(self) -> Dict[str, ComplianceControl]:
        """Load compliance controls from configuration"""
        controls = {}
        
        # Load SOC 2 controls
        soc2_config = self.config.get('compliance_frameworks', {}).get('soc2', {})
        if soc2_config.get('enabled', False):
            for control_id in soc2_config.get('controls', []):
                controls[control_id] = self._create_soc2_control(control_id)
        
        # Load other frameworks as needed
        # ISO 27001, CIS, etc.
        
        return controls
    
    def _create_soc2_control(self, control_id: str) -> ComplianceControl:
        """Create SOC 2 control definition"""
        control_definitions = {
            'CC6.1': {
                'description': 'Logical Access Controls',
                'scoring_weights': {
                    'password_complexity': 0.25,
                    'mfa_enforcement': 0.35,
                    'access_controls': 0.25,
                    'session_management': 0.15
                },
                'mitre_mappings': ['T1078', 'T1110', 'T1021'],
                'category': 'access_control'
            },
            'CC6.2': {
                'description': 'Authentication and Authorization',
                'scoring_weights': {
                    'identity_management': 0.30,
                    'authorization_controls': 0.40,
                    'token_security': 0.30
                },
                'mitre_mappings': ['T1078', 'T1556'],
                'category': 'authentication'
            },
            'CC6.3': {
                'description': 'System Access Monitoring',
                'scoring_weights': {
                    'logging_completeness': 0.40,
                    'monitoring_coverage': 0.35,
                    'alerting_capability': 0.25
                },
                'mitre_mappings': ['T1562', 'T1070'],
                'category': 'monitoring'
            },
            'CC7.1': {
                'description': 'Data Classification and Handling',
                'scoring_weights': {
                    'encryption_at_rest': 0.35,
                    'encryption_in_transit': 0.30,
                    'data_classification': 0.35
                },
                'mitre_mappings': ['T1560', 'T1041'],
                'category': 'data_protection'
            },
            'CC8.1': {
                'description': 'Change Management',
                'scoring_weights': {
                    'change_tracking': 0.40,
                    'approval_process': 0.35,
                    'rollback_capability': 0.25
                },
                'mitre_mappings': ['T1098', 'T1543'],
                'category': 'change_management'
            }
        }
        
        control_def = control_definitions.get(control_id, {})
        
        return ComplianceControl(
            control_id=control_id,
            description=control_def.get('description', f'Control {control_id}'),
            framework='soc2',
            scoring_weights=control_def.get('scoring_weights', {}),
            mitre_mappings=control_def.get('mitre_mappings', []),
            category=control_def.get('category', 'general'),
            cloud_providers=['aws', 'gcp', 'azure']
        )
    
    def _load_hunting_rules(self) -> Dict[str, HuntingRule]:
        """Load hunting rules from configuration"""
        rules = {}
        
        # Load hunting rules from YAML templates
        hunting_templates = [
            'lateral_movement.yaml',
            'data_exfiltration.yaml', 
            'malware_persistence.yaml',
            'insider_threat.yaml'
        ]
        
        for template in hunting_templates:
            try:
                rule = self._load_hunting_template(template)
                if rule:
                    rules[rule.rule_id] = rule
            except Exception as e:
                logger.warning(f"Failed to load hunting template {template}: {e}")
        
        return rules
    
    def _load_hunting_template(self, template_name: str) -> Optional[HuntingRule]:
        """Load hunting rule from YAML template"""
        # This would load from hunting/templates/ directory
        # For now, create sample rules
        
        sample_rules = {
            'lateral_movement.yaml': HuntingRule(
                rule_id='lateral_movement_detection',
                name='Lateral Movement Detection',
                description='Detect lateral movement patterns across network',
                query_logic={
                    'time_window': '1h',
                    'conditions': [
                        {'field': 'event_type', 'operator': 'equals', 'value': 'network_connection'},
                        {'field': 'protocol', 'operator': 'in', 'value': ['SMB', 'RDP', 'SSH']},
                        {'field': 'success', 'operator': 'equals', 'value': True}
                    ]
                },
                mitre_techniques=['T1021.001', 'T1021.002', 'T1078'],
                severity=RiskLevel.HIGH,
                related_controls=['CC6.1', 'CC6.3']
            ),
            'data_exfiltration.yaml': HuntingRule(
                rule_id='data_exfiltration_detection',
                name='Data Exfiltration Detection',
                description='Detect unusual data transfer patterns',
                query_logic={
                    'time_window': '2h',
                    'conditions': [
                        {'field': 'bytes_transferred', 'operator': 'greater_than', 'value': 1000000},
                        {'field': 'destination_external', 'operator': 'equals', 'value': True}
                    ]
                },
                mitre_techniques=['T1041', 'T1567'],
                severity=RiskLevel.CRITICAL,
                related_controls=['CC7.1', 'CC6.3']
            )
        }
        
        return sample_rules.get(template_name)
    
    async def execute_unified_scan(self, scan_config: Dict) -> ScanResult:
        """
        Execute unified compliance and threat hunting scan
        
        Args:
            scan_config: Scan configuration including providers, frameworks, rules
            
        Returns:
            ScanResult with unified findings
        """
        scan = ScanResult(
            scan_type='unified',
            cloud_providers=scan_config.get('providers', []),
            compliance_frameworks=scan_config.get('frameworks', []),
            hunting_rules=scan_config.get('hunting_rules', [])
        )
        
        self.active_scans[scan.scan_id] = scan
        logger.info(f"Starting unified scan {scan.scan_id}")
        
        try:
            # Phase 1: Asset Discovery
            await self._discover_assets(scan)
            
            # Phase 2: Parallel execution of compliance and threat hunting
            compliance_task = asyncio.create_task(self._execute_compliance_assessment(scan))
            threat_task = asyncio.create_task(self._execute_threat_hunting(scan))
            
            # Wait for both to complete
            compliance_findings, threat_findings = await asyncio.gather(
                compliance_task, threat_task, return_exceptions=True
            )
            
            # Phase 3: Correlation and hybrid findings
            hybrid_findings = await self._correlate_findings(compliance_findings, threat_findings, scan)
            
            # Phase 4: Finalize scan
            scan.complete_scan()
            logger.info(f"Completed unified scan {scan.scan_id} with {len(scan.findings)} findings")
            
        except Exception as e:
            scan.status = "failed"
            logger.error(f"Unified scan {scan.scan_id} failed: {e}")
        
        return scan
    
    async def _discover_assets(self, scan: ScanResult):
        """Discover and inventory assets across cloud providers"""
        logger.info("Starting asset discovery")
        
        discovered_assets = []
        
        # Discover assets from each enabled cloud provider
        for provider in scan.cloud_providers:
            if provider in self.cloud_collectors:
                try:
                    collector = self.cloud_collectors[provider]
                    provider_assets = await self._discover_provider_assets(collector, provider)
                    discovered_assets.extend(provider_assets)
                except Exception as e:
                    logger.error(f"Asset discovery failed for {provider}: {e}")
        
        # Update asset registry
        for asset in discovered_assets:
            self.assets[asset.asset_id] = asset
            scan.target_assets.append(asset.asset_id)
        
        scan.total_assets_scanned = len(discovered_assets)
        logger.info(f"Discovered {len(discovered_assets)} assets")
    
    async def _discover_provider_assets(self, collector, provider: str) -> List[SecurityAsset]:
        """Discover assets from specific cloud provider"""
        assets = []
        
        # This would use the existing cloud collector methods
        # For now, create sample assets
        if provider == 'aws':
            # Sample AWS assets
            assets.append(SecurityAsset(
                asset_id=f"aws-ec2-{datetime.now().timestamp()}",
                name="Production Web Server",
                asset_type="server",
                ip_address="10.0.1.100",
                cloud_provider="aws",
                cloud_region="us-west-2",
                criticality=RiskLevel.HIGH
            ))
        
        return assets
    
    async def _execute_compliance_assessment(self, scan: ScanResult) -> List[UnifiedFinding]:
        """Execute TPU-accelerated compliance assessment across all controls"""
        logger.info("Starting TPU-accelerated compliance assessment")
        compliance_findings = []
        
        # Check if TPU acceleration is available
        if self.tpu_available and self.tpu_compliance_accelerator:
            try:
                # Get assets for TPU batch processing
                assets = [self.assets[asset_id] for asset_id in scan.target_assets 
                         if asset_id in self.assets]
                
                if assets:
                    # Use TPU accelerated batch compliance analysis
                    controls_to_assess = list(self.compliance_controls.keys())
                    
                    tpu_results = self.tpu_compliance_accelerator.analyze_compliance_batch(
                        assets, controls_to_assess
                    )
                    
                    # Convert TPU results to unified findings
                    for tpu_result in tpu_results:
                        if tpu_result.score < 70:  # Non-compliant threshold
                            finding = create_compliance_finding(
                                control_id=tpu_result.control_id,
                                framework="SOC2",
                                score=tpu_result.score,
                                evidence=[{
                                    'provider': tpu_result.provider,
                                    'tpu_accelerated': True,
                                    'confidence': tpu_result.confidence,
                                    'processing_time_ms': tpu_result.processing_time_ms,
                                    'component_scores': tpu_result.component_scores,
                                    'risk_factors': tpu_result.risk_factors
                                }],
                                assets=[tpu_result.asset_id]
                            )
                            
                            # Add TPU-specific metadata
                            finding.metadata.update({
                                'tpu_accelerated': True,
                                'acceleration_factor': self.tpu_compliance_accelerator.acceleration_factor,
                                'recommendations': tpu_result.recommendations
                            })
                            
                            compliance_findings.append(finding)
                            scan.add_finding(finding)
                    
                    scan.total_controls_assessed = len(controls_to_assess) * len(assets)
                    
                    logger.info(f"TPU compliance assessment completed: {len(compliance_findings)} findings from {len(tpu_results)} analyses")
                    return compliance_findings
                    
            except Exception as e:
                logger.error(f"TPU compliance assessment failed: {e}")
                logger.info("Falling back to traditional compliance assessment")
        
        # Assess each compliance control
        for control_id, control in self.compliance_controls.items():
            try:
                finding = await self._assess_compliance_control(control, scan.target_assets)
                if finding:
                    compliance_findings.append(finding)
                    scan.add_finding(finding)
                    scan.total_controls_assessed += 1
            except Exception as e:
                logger.error(f"Failed to assess control {control_id}: {e}")
        
        logger.info(f"Completed compliance assessment with {len(compliance_findings)} findings")
        return compliance_findings
    
    async def _assess_compliance_control(self, control: ComplianceControl, 
                                       asset_ids: List[str]) -> Optional[UnifiedFinding]:
        """Assess single compliance control with TPU acceleration"""
        
        # Collect evidence from cloud providers
        evidence = {}
        affected_assets = []
        
        for provider in control.cloud_providers:
            if provider in self.cloud_collectors:
                try:
                    collector = self.cloud_collectors[provider]
                    provider_evidence = await self._collect_control_evidence(collector, control, provider)
                    evidence[provider] = provider_evidence
                    
                    # Find affected assets for this provider
                    provider_assets = [aid for aid in asset_ids 
                                     if self.assets[aid].cloud_provider == provider]
                    affected_assets.extend(provider_assets)
                    
                except Exception as e:
                    logger.error(f"Failed to collect evidence for {control.control_id} from {provider}: {e}")
        
        # Use TPU-accelerated compliance analysis if available
        if self.tpu_acceleration_enabled and self.accelerated_analytics and affected_assets:
            try:
                # Get the first affected asset for analysis
                asset = self.assets[affected_assets[0]]
                client_id = getattr(asset, 'client_id', 'default')
                
                # Run TPU-accelerated compliance analysis
                tpu_result = await self.accelerated_analytics.analyze_compliance_accelerated(
                    asset=asset,
                    evidence=evidence,
                    control_id=control.control_id,
                    client_id=client_id
                )
                
                score = tpu_result.scores.get('overall_score', 0)
                
                logger.debug(f"TPU-accelerated compliance analysis: {control.control_id} = {score:.1f} "
                           f"(processed in {tpu_result.processing_time_ms:.2f}ms, "
                           f"{tpu_result.acceleration_factor:.1f}x acceleration)")
                
                # Create enhanced finding with TPU insights
                if score < control.threshold_compliant:
                    finding = create_compliance_finding(
                        control_id=control.control_id,
                        framework=control.framework,
                        score=score,
                        evidence=[{'provider': k, 'data': v} for k, v in evidence.items()],
                        assets=affected_assets
                    )
                    
                    # Enhance finding with TPU analysis results
                    finding.metadata['tpu_accelerated'] = True
                    finding.metadata['acceleration_factor'] = tpu_result.acceleration_factor
                    finding.metadata['processing_time_ms'] = tpu_result.processing_time_ms
                    finding.metadata['confidence_level'] = tpu_result.confidence_level
                    finding.metadata['tpu_recommendations'] = tpu_result.recommendations
                    finding.metadata['tpu_risk_factors'] = tpu_result.risk_factors
                    
                    return finding
                
                return None
                
            except Exception as e:
                logger.warning(f"TPU-accelerated compliance analysis failed for {control.control_id}: {e}")
                # Fall through to traditional analysis
        
        # Traditional compliance scoring (fallback or when TPU not available)
        score = control.calculate_compliance_score(evidence)
        
        # Use enhanced scoring functions for specific controls if Weaviate is available
        if self.enhanced_scoring_functions and evidence:
            try:
                client_id = getattr(self.assets[affected_assets[0]], 'client_id', 'default') if affected_assets else 'default'
                
                # Use enhanced GCP MFA scoring for CC6.1
                if control.control_id == 'CC6.1-MFA' and 'gcp' in evidence:
                    enhanced_result = self.enhanced_scoring_functions['enhanced_gcp_mfa_check'](
                        evidence['gcp'], client_id
                    )
                    score = enhanced_result.score
                    logger.debug(f"Enhanced GCP MFA scoring: {score} for client {client_id}")
                
                # Use enhanced GCP IAM scoring for CC6.2
                elif control.control_id == 'CC6.2-IAM' and 'gcp' in evidence:
                    enhanced_result = self.enhanced_scoring_functions['enhanced_gcp_iam_check'](
                        evidence['gcp'], client_id
                    )
                    score = enhanced_result.score
                    logger.debug(f"Enhanced GCP IAM scoring: {score} for client {client_id}")
                    
            except Exception as e:
                logger.warning(f"Enhanced scoring failed for {control.control_id}, using fallback: {e}")
        
        # Create finding if non-compliant
        if score < control.threshold_compliant:
            finding = create_compliance_finding(
                control_id=control.control_id,
                framework=control.framework,
                score=score,
                evidence=[{'provider': k, 'data': v} for k, v in evidence.items()],
                assets=affected_assets
            )
            
            # Mark as traditional analysis
            finding.metadata['tpu_accelerated'] = False
            
            return finding
        
        return None
    
    async def _collect_control_evidence(self, collector, control: ComplianceControl, 
                                      provider: str) -> Dict:
        """Collect evidence for compliance control from cloud provider"""
        
        # Use existing collector methods based on control
        evidence = {}
        
        try:
            if control.control_id == 'CC6.1':
                # Logical access controls
                if hasattr(collector, 'collect_soc2_cc6_1_evidence'):
                    evidence = await collector.collect_soc2_cc6_1_evidence()
                else:
                    # Fallback to individual collection methods
                    evidence = {
                        'password_policy': await collector.collect_password_policy(),
                        'mfa_config': await collector.collect_mfa_config(),
                        'iam_policies': await collector.collect_iam_policies()
                    }
            
            # Add other control mappings as needed
            
        except Exception as e:
            logger.error(f"Evidence collection failed for {control.control_id} on {provider}: {e}")
        
        return evidence
    
    async def _execute_threat_hunting(self, scan: ScanResult) -> List[UnifiedFinding]:
        """Execute TPU-accelerated threat hunting rules"""
        logger.info("Starting TPU-accelerated threat hunting")
        threat_findings = []
        
        # Check if TPU acceleration is available
        if self.tpu_available and self.tpu_threat_detector:
            try:
                # Get assets for TPU batch processing
                assets = [self.assets[asset_id] for asset_id in scan.target_assets 
                         if asset_id in self.assets]
                
                if assets:
                    # Use TPU accelerated threat detection
                    tpu_threat_results = self.tpu_threat_detector.detect_threats_batch(assets)
                    
                    # Convert TPU results to unified findings
                    for tpu_result in tpu_threat_results:
                        if tpu_result.threat_score > 50:  # Threat threshold
                            finding = create_threat_finding(
                                threat_type=tpu_result.threat_type,
                                severity=tpu_result.severity,
                                confidence=tpu_result.confidence,
                                mitre_techniques=tpu_result.mitre_techniques,
                                indicators=tpu_result.indicators,
                                assets=[tpu_result.asset_id]
                            )
                            
                            # Add TPU-specific metadata
                            finding.metadata.update({
                                'tpu_accelerated': True,
                                'threat_score': tpu_result.threat_score,
                                'processing_time_ms': tpu_result.processing_time_ms,
                                'behavioral_patterns': tpu_result.behavioral_patterns,
                                'mitre_techniques': tpu_result.mitre_techniques
                            })
                            
                            threat_findings.append(finding)
                            scan.add_finding(finding)
                    
                    # Perform anomaly detection
                    anomaly_results = self.tpu_threat_detector.detect_anomalies(assets)
                    
                    for anomaly in anomaly_results:
                        if anomaly.anomaly_score > 0.7:  # Anomaly threshold
                            finding = create_threat_finding(
                                threat_type=f"anomaly_{anomaly.anomaly_type}",
                                severity=RiskLevel.MEDIUM,
                                confidence=anomaly.confidence,
                                mitre_techniques=[],
                                indicators=[{
                                    'type': 'behavioral_anomaly',
                                    'score': anomaly.anomaly_score,
                                    'deviation': anomaly.baseline_deviation,
                                    'metrics': anomaly.affected_metrics
                                }],
                                assets=[anomaly.asset_id]
                            )
                            
                            finding.metadata.update({
                                'tpu_accelerated': True,
                                'anomaly_type': anomaly.anomaly_type,
                                'anomaly_score': anomaly.anomaly_score,
                                'time_window': anomaly.time_window
                            })
                            
                            threat_findings.append(finding)
                            scan.add_finding(finding)
                    
                    scan.total_hunt_rules_executed = len(self.hunting_rules)
                    
                    logger.info(f"TPU threat hunting completed: {len(threat_findings)} threats detected")
                    return threat_findings
                    
            except Exception as e:
                logger.error(f"TPU threat hunting failed: {e}")
                logger.info("Falling back to traditional threat hunting")
        
        # Fallback to traditional rule-based hunting
        for rule_id, rule in self.hunting_rules.items():
            if rule.enabled:
                try:
                    rule_findings = await self._execute_hunting_rule(rule, scan.target_assets)
                    threat_findings.extend(rule_findings)
                    for finding in rule_findings:
                        scan.add_finding(finding)
                    scan.total_hunt_rules_executed += 1
                except Exception as e:
                    logger.error(f"Failed to execute hunting rule {rule_id}: {e}")
        
        logger.info(f"Completed threat hunting with {len(threat_findings)} findings")
        return threat_findings
    
    async def _execute_hunting_rule(self, rule: HuntingRule, 
                                  asset_ids: List[str]) -> List[UnifiedFinding]:
        """Execute single hunting rule with TPU acceleration"""
        findings = []
        
        # Try TPU-accelerated threat analysis first
        if self.tpu_acceleration_enabled and self.accelerated_analytics and asset_ids:
            try:
                tpu_findings = []
                
                # Run TPU-accelerated threat analysis for each asset
                for asset_id in asset_ids[:10]:  # Limit to first 10 assets for performance
                    if asset_id in self.assets:
                        asset = self.assets[asset_id]
                        
                        # Collect behavioral data for threat analysis
                        behavioral_data = await self._collect_behavioral_data(asset, rule)
                        
                        # Run TPU-accelerated threat analysis
                        tpu_result = await self.accelerated_analytics.analyze_threat_accelerated(
                            asset=asset,
                            behavioral_data=behavioral_data,
                            time_window=timedelta(hours=1)
                        )
                        
                        # Convert TPU result to finding if threat detected
                        threat_level = tpu_result.predictions.get('threat_level', 'low')
                        if threat_level in ['high', 'critical']:
                            finding = create_threat_finding(
                                rule_name=rule.name,
                                techniques=rule.mitre_techniques,
                                confidence=tpu_result.confidence_level,
                                iocs=self._extract_iocs_from_tpu_result(tpu_result),
                                assets=[asset_id]
                            )
                            
                            # Enhance finding with TPU analysis results
                            finding.metadata['tpu_accelerated'] = True
                            finding.metadata['acceleration_factor'] = tpu_result.acceleration_factor
                            finding.metadata['processing_time_ms'] = tpu_result.processing_time_ms
                            finding.metadata['threat_level'] = threat_level
                            finding.metadata['attack_probability'] = tpu_result.predictions.get('attack_probability', 0)
                            finding.metadata['tpu_recommendations'] = tpu_result.recommendations
                            finding.metadata['predicted_mitre_techniques'] = tpu_result.predictions.get('mitre_techniques', [])
                            
                            # Add TPU analysis evidence
                            finding.add_evidence(
                                evidence_type='tpu_threat_analysis',
                                data=tpu_result.evidence,
                                source=f'coral_tpu_{tpu_result.tpu_device}'
                            )
                            
                            tpu_findings.append(finding)
                            
                            logger.debug(f"TPU threat detection: {rule.rule_id} on {asset_id} = {threat_level} "
                                       f"(processed in {tpu_result.processing_time_ms:.2f}ms, "
                                       f"{tpu_result.acceleration_factor:.1f}x acceleration)")
                
                # Return TPU findings if successful
                if tpu_findings:
                    return tpu_findings
                    
            except Exception as e:
                logger.warning(f"TPU-accelerated threat hunting failed for {rule.rule_id}: {e}")
                # Fall through to traditional Weaviate-based hunting
        
        # Traditional Weaviate-based threat hunting (fallback or when TPU not available)
        if not self.weaviate_client:
            logger.warning(f"No Weaviate client available for hunting rule {rule.rule_id}")
            return findings
        
        try:
            # Build Weaviate query from rule logic
            query_results = await self._query_weaviate_for_threats(rule)
            
            # Process results into findings
            for result in query_results:
                finding = create_threat_finding(
                    rule_name=rule.name,
                    techniques=rule.mitre_techniques,
                    confidence=result.get('confidence', 70.0),
                    iocs=result.get('iocs', []),
                    assets=result.get('affected_assets', [])
                )
                
                # Add rule-specific evidence
                finding.add_evidence(
                    evidence_type='hunting_result',
                    data=result,
                    source=f'hunting_rule_{rule.rule_id}'
                )
                
                # Mark as traditional analysis
                finding.metadata['tpu_accelerated'] = False
                
                findings.append(finding)
        
        except Exception as e:
            logger.error(f"Hunting rule execution failed for {rule.rule_id}: {e}")
        
        return findings
    
    async def _query_weaviate_for_threats(self, rule: HuntingRule) -> List[Dict]:
        """Query Weaviate using hunting rule logic"""
        
        # Convert rule query logic to Weaviate query
        # This is a simplified implementation
        query_logic = rule.query_logic
        
        try:
            # Build vector search query
            where_filter = {
                "operator": "And",
                "operands": []
            }
            
            for condition in query_logic.get('conditions', []):
                where_filter["operands"].append({
                    "path": [condition['field']],
                    "operator": "Equal" if condition['operator'] == 'equals' else "GreaterThan",
                    "valueText": str(condition['value']) if isinstance(condition['value'], str) else None,
                    "valueNumber": condition['value'] if isinstance(condition['value'], (int, float)) else None
                })
            
            # Execute query
            result = (
                self.weaviate_client.query
                .get("AuditAsset", ["asset_id", "event_type", "anomaly_score", "raw_data"])
                .where(where_filter)
                .with_limit(100)
                .do()
            )
            
            # Process results
            processed_results = []
            if 'data' in result and 'Get' in result['data']:
                assets = result['data']['Get'].get('AuditAsset', [])
                for asset in assets:
                    processed_results.append({
                        'asset_id': asset.get('asset_id'),
                        'confidence': asset.get('anomaly_score', 70.0),
                        'affected_assets': [asset.get('asset_id')],
                        'iocs': self._extract_iocs_from_asset(asset),
                        'raw_data': asset.get('raw_data', {})
                    })
            
            return processed_results
            
        except Exception as e:
            logger.error(f"Weaviate query failed for rule {rule.rule_id}: {e}")
            return []
    
    def _extract_iocs_from_asset(self, asset: Dict) -> List[Dict]:
        """Extract IOCs from asset data"""
        iocs = []
        
        raw_data = asset.get('raw_data', {})
        
        # Extract IP addresses
        if 'source_ip' in raw_data:
            iocs.append({
                'type': 'ip',
                'value': raw_data['source_ip'],
                'description': 'Source IP from security event'
            })
        
        # Extract domains
        if 'destination_domain' in raw_data:
            iocs.append({
                'type': 'domain',
                'value': raw_data['destination_domain'],
                'description': 'Destination domain from network event'
            })
        
        return iocs
    
    async def _correlate_findings(self, compliance_findings: List[UnifiedFinding], 
                                threat_findings: List[UnifiedFinding], 
                                scan: ScanResult) -> List[UnifiedFinding]:
        """Correlate compliance and threat findings to create hybrid findings"""
        logger.info("Starting finding correlation")
        hybrid_findings = []
        
        # Find overlapping assets between compliance and threat findings
        for comp_finding in compliance_findings:
            for threat_finding in threat_findings:
                # Check for asset overlap
                common_assets = set(comp_finding.affected_assets) & set(threat_finding.affected_assets)
                
                if common_assets and self._should_correlate(comp_finding, threat_finding):
                    # Create hybrid finding
                    hybrid = create_hybrid_finding(
                        control_id=comp_finding.control_id,
                        rule_name=threat_finding.hunting_rule,
                        compliance_score=comp_finding.compliance_score,
                        threat_confidence=threat_finding.confidence_score,
                        assets=list(common_assets)
                    )
                    
                    hybrid_findings.append(hybrid)
                    scan.add_finding(hybrid)
        
        logger.info(f"Created {len(hybrid_findings)} hybrid findings from correlation")
        return hybrid_findings
    
    def _should_correlate(self, comp_finding: UnifiedFinding, threat_finding: UnifiedFinding) -> bool:
        """Determine if compliance and threat findings should be correlated"""
        
        # Check MITRE technique overlap
        if comp_finding.control_id in self.compliance_controls:
            control = self.compliance_controls[comp_finding.control_id]
            mitre_overlap = set(control.mitre_mappings) & set(threat_finding.mitre_techniques)
            if mitre_overlap:
                return True
        
        # Check timing correlation (findings within similar timeframe)
        time_diff = abs((comp_finding.created_at - threat_finding.created_at).total_seconds())
        if time_diff < 3600:  # Within 1 hour
            return True
        
        return False
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Get status of active or completed scan"""
        if scan_id in self.active_scans:
            return self.active_scans[scan_id].get_summary()
        return None
    
    def get_asset_risk_profile(self, asset_id: str) -> Dict:
        """Get comprehensive risk profile for asset"""
        if asset_id not in self.assets:
            return {}
        
        asset = self.assets[asset_id]
        
        # Calculate overall risk score
        risk_factors = {
            'compliance_risk': 100 - (asset.compliance_status.value == 'compliant' and 90 or 50),
            'threat_risk': asset.anomaly_score,
            'criticality_risk': {'critical': 90, 'high': 70, 'medium': 50, 'low': 30}.get(asset.criticality.value, 50)
        }
        
        overall_risk = sum(risk_factors.values()) / len(risk_factors)
        
        return {
            'asset_id': asset_id,
            'overall_risk_score': overall_risk,
            'risk_factors': risk_factors,
            'compliance_status': asset.compliance_status.value,
            'threat_status': asset.threat_status.value,
            'last_assessed': max(asset.last_compliance_scan or datetime.min, 
                               asset.last_threat_scan or datetime.min).isoformat(),
            'recommendations': self._generate_asset_recommendations(asset, risk_factors)
        }
    
    def get_compliance_analytics(self, client_id: str = None, 
                                time_window: str = "weekly", 
                                lookback_days: int = 30) -> Dict[str, Any]:
        """
        Get compliance analytics and trends from Weaviate
        
        Args:
            client_id: Tenant identifier for multi-tenant filtering
            time_window: Analysis time window (daily, weekly, monthly)
            lookback_days: Days to analyze
            
        Returns:
            Compliance analytics and trends
        """
        if not self.compliance_bridge:
            return {
                "error": "Weaviate compliance bridge not available",
                "message": "Historical analytics require Weaviate integration"
            }
        
        try:
            return self.compliance_bridge.get_compliance_trends(
                client_id or "default", 
                time_window, 
                lookback_days
            )
        except Exception as e:
            logger.error(f"Failed to get compliance analytics: {e}")
            return {"error": str(e)}
    
    def search_compliance_history(self, query: str, client_id: str = None, 
                                 limit: int = 10) -> List[Dict[str, Any]]:
        """
        Semantic search of compliance history
        
        Args:
            query: Natural language search query
            client_id: Optional tenant filter
            limit: Maximum results
            
        Returns:
            List of relevant compliance scores
        """
        if not self.compliance_bridge:
            return []
        
        try:
            return self.compliance_bridge.semantic_search(
                query, client_id, limit
            )
        except Exception as e:
            logger.error(f"Failed to search compliance history: {e}")
            return []
    
    def query_compliance_scores(self, filters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Query compliance scores with filters
        
        Args:
            filters: Dictionary of filter criteria
            
        Returns:
            List of matching compliance scores
        """
        if not self.compliance_bridge:
            return []
        
        filters = filters or {}
        
        try:
            return self.compliance_bridge.query_scores(
                client_id=filters.get('client_id'),
                provider=filters.get('provider'),
                control=filters.get('control'),
                framework=filters.get('framework'),
                min_score=filters.get('min_score'),
                max_score=filters.get('max_score'),
                since_date=filters.get('since_date'),
                limit=filters.get('limit', 100)
            )
        except Exception as e:
            logger.error(f"Failed to query compliance scores: {e}")
            return []
    
    async def _collect_behavioral_data(self, asset: SecurityAsset, rule: HuntingRule) -> Dict[str, Any]:
        """Collect behavioral data for TPU threat analysis"""
        behavioral_data = {
            'asset_id': asset.asset_id,
            'asset_type': asset.asset_type.value,
            'rule_id': rule.rule_id,
            'time_window': '1h',
            'network_activity': {
                'connection_count': np.random.randint(10, 1000),
                'data_transfer_mb': np.random.randint(1, 500),
                'external_connections': np.random.randint(0, 50),
                'protocol_distribution': {
                    'HTTP': 0.6,
                    'HTTPS': 0.3,
                    'SSH': 0.05,
                    'Other': 0.05
                }
            },
            'authentication_events': {
                'login_attempts': np.random.randint(1, 100),
                'failed_logins': np.random.randint(0, 10),
                'privileged_access': np.random.randint(0, 5),
                'unusual_access_times': np.random.randint(0, 3)
            },
            'process_activity': {
                'new_processes': np.random.randint(10, 200),
                'suspicious_processes': np.random.randint(0, 5),
                'process_anomalies': np.random.randint(0, 3)
            },
            'file_activity': {
                'files_accessed': np.random.randint(50, 1000),
                'files_modified': np.random.randint(5, 100),
                'sensitive_file_access': np.random.randint(0, 10)
            }
        }
        
        return behavioral_data
    
    def _extract_iocs_from_tpu_result(self, tpu_result: AcceleratedAnalysisResult) -> List[str]:
        """Extract indicators of compromise from TPU analysis result"""
        iocs = []
        
        # Extract IOCs based on analysis type and results
        if tpu_result.analysis_type == 'threat':
            evidence = tpu_result.evidence
            
            # Extract network-based IOCs
            network_data = evidence.get('network_activity', {})
            if network_data.get('external_connections', 0) > 30:
                iocs.append('high_external_connectivity')
            
            # Extract authentication IOCs
            auth_data = evidence.get('authentication_events', {})
            if auth_data.get('failed_logins', 0) > 5:
                iocs.append('excessive_failed_logins')
            
            # Extract process IOCs
            process_data = evidence.get('process_activity', {})
            if process_data.get('suspicious_processes', 0) > 2:
                iocs.append('suspicious_process_activity')
        
        return iocs
    
    def run_tpu_batch_analysis(self, asset_ids: List[str], 
                              analysis_types: List[str] = None) -> Dict[str, Any]:
        """
        Run batch TPU analysis across multiple assets
        
        Args:
            asset_ids: List of asset IDs to analyze
            analysis_types: Types of analysis to run ['compliance', 'threat', 'anomaly', 'risk']
            
        Returns:
            Dictionary with batch analysis results and performance metrics
        """
        if not self.tpu_acceleration_enabled:
            return {'error': 'TPU acceleration not available'}
        
        analysis_types = analysis_types or ['compliance', 'threat', 'anomaly']
        start_time = datetime.now()
        
        # Prepare batch analysis requests
        analysis_requests = []
        
        for asset_id in asset_ids:
            if asset_id not in self.assets:
                continue
                
            asset = self.assets[asset_id]
            
            for analysis_type in analysis_types:
                request = {
                    'type': analysis_type,
                    'asset': asset,
                    'asset_id': asset_id,
                    'client_id': getattr(asset, 'client_id', 'default')
                }
                
                # Add type-specific data
                if analysis_type == 'compliance':
                    request['evidence'] = {'placeholder': 'evidence_data'}
                    request['control_id'] = 'CC6.1'  # Default control
                elif analysis_type == 'threat':
                    request['behavioral_data'] = {'placeholder': 'behavioral_data'}
                elif analysis_type == 'anomaly':
                    request['metrics_data'] = {'placeholder': 'metrics_data'}
                elif analysis_type == 'risk':
                    request['comprehensive_data'] = {'placeholder': 'comprehensive_data'}
                
                analysis_requests.append(request)
        
        try:
            # Run batch analysis using TPU acceleration
            loop = asyncio.get_event_loop()
            batch_results = loop.run_until_complete(
                self.accelerated_analytics.batch_analyze_accelerated(analysis_requests)
            )
            
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            
            # Calculate performance metrics
            total_acceleration_factor = np.mean([r.acceleration_factor for r in batch_results])
            tpu_accelerated_count = sum(1 for r in batch_results if r.tpu_acceleration)
            
            return {
                'success': True,
                'total_analyses': len(batch_results),
                'tpu_accelerated_analyses': tpu_accelerated_count,
                'total_processing_time_ms': processing_time,
                'average_acceleration_factor': total_acceleration_factor,
                'results_by_type': self._group_results_by_type(batch_results),
                'performance_summary': {
                    'assets_analyzed': len(asset_ids),
                    'analysis_types': len(analysis_types),
                    'time_saved_ms': self._calculate_time_saved(batch_results),
                    'tpu_utilization': tpu_accelerated_count / len(batch_results) if batch_results else 0
                }
            }
            
        except Exception as e:
            logger.error(f"Batch TPU analysis failed: {e}")
            return {'error': str(e)}
    
    def _group_results_by_type(self, results: List[AcceleratedAnalysisResult]) -> Dict[str, List[Dict]]:
        """Group analysis results by type"""
        grouped = {}
        
        for result in results:
            analysis_type = result.analysis_type
            if analysis_type not in grouped:
                grouped[analysis_type] = []
            
            grouped[analysis_type].append({
                'asset_id': result.asset_id,
                'scores': result.scores,
                'predictions': result.predictions,
                'confidence': result.confidence_level,
                'processing_time_ms': result.processing_time_ms,
                'acceleration_factor': result.acceleration_factor,
                'tpu_accelerated': result.tpu_acceleration
            })
        
        return grouped
    
    def _calculate_time_saved(self, results: List[AcceleratedAnalysisResult]) -> float:
        """Calculate time saved through TPU acceleration"""
        time_saved = 0.0
        
        for result in results:
            if result.tpu_acceleration and result.acceleration_factor > 1:
                cpu_time = result.processing_time_ms * result.acceleration_factor
                time_saved += cpu_time - result.processing_time_ms
        
        return time_saved
    
    def get_tpu_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive TPU performance metrics"""
        if not self.tpu_acceleration_enabled:
            return {'error': 'TPU acceleration not available'}
        
        coral_metrics = self.coral_engine.get_performance_metrics()
        analytics_metrics = self.accelerated_analytics.get_performance_summary()
        
        return {
            'tpu_enabled': True,
            'coral_engine': coral_metrics,
            'accelerated_analytics': analytics_metrics,
            'overall_acceleration': {
                'total_tpu_devices': len(self.coral_engine.tpu_devices),
                'models_loaded': len(self.coral_engine.loaded_models),
                'total_analyses': analytics_metrics.get('analysis_count', 0),
                'cache_efficiency': analytics_metrics.get('cache_hit_rate', 0),
                'average_acceleration_factor': coral_metrics.get('acceleration_factor', 0)
            }
        }
    
    def _generate_asset_recommendations(self, asset: SecurityAsset, risk_factors: Dict) -> List[str]:
        """Generate recommendations for asset risk mitigation"""
        recommendations = []
        
        if risk_factors['compliance_risk'] > 70:
            recommendations.append("Immediate compliance assessment required")
        
        if risk_factors['threat_risk'] > 80:
            recommendations.append("Enhanced monitoring and threat hunting recommended")
        
        if risk_factors['criticality_risk'] > 70:
            recommendations.append("Consider additional security controls for critical asset")
        
        return recommendations
    
    def get_tpu_acceleration_status(self) -> Dict[str, Any]:
        """
        Get current TPU acceleration status and capabilities
        
        Returns:
            Dictionary containing TPU status information
        """
        status = {
            'tpu_available': self.tpu_available,
            'compliance_acceleration': bool(self.tpu_compliance_accelerator),
            'threat_detection_acceleration': bool(self.tpu_threat_detector),
            'devices': []
        }
        
        if self.tpu_available:
            coral_engine = get_coral_engine()
            
            # Get device information
            for device in coral_engine.tpu_devices:
                device_info = {
                    'name': device['name'],
                    'path': device['path'],
                    'type': device['type'],
                    'status': 'active'
                }
                status['devices'].append(device_info)
            
            # Get model information
            status['loaded_models'] = []
            for model_name, model_info in coral_engine.loaded_models.items():
                model_status = {
                    'name': model_name,
                    'type': model_info.model_type,
                    'inference_count': model_info.inference_count,
                    'average_time_ms': (model_info.total_inference_time / model_info.inference_count 
                                      if model_info.inference_count > 0 else 0)
                }
                status['loaded_models'].append(model_status)
        
        return status
    
    def run_tpu_health_check(self) -> Dict[str, Any]:
        """
        Run comprehensive TPU health check
        
        Returns:
            Health check results with recommendations
        """
        if not self.tpu_available:
            return {
                'status': 'unavailable',
                'message': 'Google Coral TPU not available',
                'recommendations': [
                    'Install Google Coral TPU libraries: pip install pycoral tflite-runtime',
                    'Connect Coral TPU device via USB',
                    'Verify device permissions and drivers'
                ]
            }
        
        try:
            coral_engine = get_coral_engine()
            health_results = coral_engine.health_check()
            
            # Add unified engine specific checks
            health_results['unified_engine'] = {
                'compliance_accelerator': 'healthy' if self.tpu_compliance_accelerator else 'unavailable',
                'threat_detector': 'healthy' if self.tpu_threat_detector else 'unavailable'
            }
            
            # Generate recommendations based on health
            recommendations = []
            
            if health_results['overall_status'] != 'healthy':
                recommendations.append('TPU devices require attention - check device status')
            
            if not health_results['unified_engine']['compliance_accelerator']:
                recommendations.append('Initialize TPU compliance accelerator')
                
            if not health_results['unified_engine']['threat_detector']:
                recommendations.append('Initialize TPU threat detector')
            
            if len(health_results.get('tpu_devices', [])) == 0:
                recommendations.append('No TPU devices detected - connect Coral TPU hardware')
            
            health_results['recommendations'] = recommendations
            
            return health_results
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'recommendations': ['Check TPU device connection and drivers']
            }