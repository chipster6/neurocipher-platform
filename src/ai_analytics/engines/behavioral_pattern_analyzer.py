"""
Advanced Behavioral Pattern Analysis Engine
AI-powered pattern detection for security anomalies and behavioral analysis
"""

import asyncio
import json
import logging
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel

logger = logging.getLogger(__name__)

@dataclass
class BehavioralPattern:
    """Represents a detected behavioral pattern"""
    pattern_id: str
    pattern_type: str
    confidence: float
    anomaly_score: float
    affected_entities: List[str]
    time_window: Dict[str, str]
    indicators: List[str]
    risk_level: str
    description: str
    recommended_actions: List[str]

@dataclass
class SecurityEvent:
    """Represents a security event for pattern analysis"""
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    user_id: Optional[str]
    resource: str
    action: str
    result: str
    metadata: Dict[str, Any]

class BehavioralPatternAnalyzer:
    """
    Advanced AI-powered behavioral pattern analysis engine
    Uses multiple ML models and neural networks for anomaly detection
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.isolation_forest = None
        self.dbscan = None
        self.scaler = StandardScaler()
        self.neural_detector = None
        self.tokenizer = None
        self.bert_model = None
        self.patterns_detected = []
        self.baseline_behavior = {}
        self.learning_enabled = True
        
    async def initialize(self):
        """Initialize the behavioral pattern analyzer"""
        try:
            logger.info("Initializing Behavioral Pattern Analyzer...")
            
            # Initialize ML models
            self.isolation_forest = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            
            self.dbscan = DBSCAN(
                eps=0.5,
                min_samples=5,
                metric='euclidean'
            )
            
            # Initialize neural network for complex pattern detection
            self.neural_detector = BehavioralNeuralNetwork()
            
            # Initialize BERT for text-based analysis
            self.tokenizer = AutoTokenizer.from_pretrained('bert-base-uncased')
            self.bert_model = AutoModel.from_pretrained('bert-base-uncased')
            
            # Load baseline behavioral patterns
            await self._load_baseline_behavior()
            
            logger.info("Behavioral Pattern Analyzer initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Behavioral Pattern Analyzer: {e}")
            raise
    
    async def analyze_behavioral_patterns(
        self,
        events: List[SecurityEvent],
        time_window_hours: int = 24
    ) -> List[BehavioralPattern]:
        """
        Analyze events for behavioral patterns and anomalies
        
        Args:
            events: List of security events to analyze
            time_window_hours: Analysis time window in hours
            
        Returns:
            List of detected behavioral patterns
        """
        try:
            logger.info(f"Analyzing behavioral patterns for {len(events)} events")
            
            if not events:
                return []
            
            # Prepare event data for analysis
            event_features = await self._extract_event_features(events)
            
            # Detect anomalies using multiple approaches
            anomaly_patterns = await self._detect_anomalies(events, event_features)
            
            # Detect user behavior patterns
            user_patterns = await self._analyze_user_behavior(events)
            
            # Detect temporal patterns
            temporal_patterns = await self._analyze_temporal_patterns(events)
            
            # Detect access patterns
            access_patterns = await self._analyze_access_patterns(events)
            
            # Detect lateral movement patterns
            lateral_movement = await self._detect_lateral_movement(events)
            
            # Detect privilege escalation patterns
            privilege_escalation = await self._detect_privilege_escalation(events)
            
            # Combine all detected patterns
            all_patterns = (
                anomaly_patterns + user_patterns + temporal_patterns +
                access_patterns + lateral_movement + privilege_escalation
            )
            
            # Score and rank patterns
            ranked_patterns = await self._rank_patterns(all_patterns)
            
            # Update baseline behavior if learning is enabled
            if self.learning_enabled:
                await self._update_baseline_behavior(events)
            
            logger.info(f"Detected {len(ranked_patterns)} behavioral patterns")
            return ranked_patterns
            
        except Exception as e:
            logger.error(f"Behavioral pattern analysis failed: {e}")
            return []
    
    async def _extract_event_features(self, events: List[SecurityEvent]) -> np.ndarray:
        """Extract numerical features from security events"""
        features = []
        
        for event in events:
            feature_vector = [
                # Temporal features
                event.timestamp.hour,
                event.timestamp.weekday(),
                (event.timestamp - datetime.min).total_seconds(),
                
                # Categorical features (encoded as numbers)
                hash(event.event_type) % 1000,
                hash(event.source) % 1000,
                hash(event.action) % 1000,
                hash(event.result) % 1000,
                
                # Metadata features
                len(event.metadata),
                1 if event.user_id else 0,
                len(event.resource),
                
                # Success/failure indicator
                1 if event.result.lower() in ['success', 'allowed'] else 0
            ]
            features.append(feature_vector)
        
        return np.array(features)
    
    async def _detect_anomalies(
        self,
        events: List[SecurityEvent],
        features: np.ndarray
    ) -> List[BehavioralPattern]:
        """Detect anomalies using machine learning models"""
        patterns = []
        
        try:
            if len(features) < 10:
                return patterns
            
            # Normalize features
            features_scaled = self.scaler.fit_transform(features)
            
            # Isolation Forest anomaly detection
            anomaly_scores = self.isolation_forest.fit_predict(features_scaled)
            anomaly_indices = np.where(anomaly_scores == -1)[0]
            
            if len(anomaly_indices) > 0:
                anomalous_events = [events[i] for i in anomaly_indices]
                
                pattern = BehavioralPattern(
                    pattern_id=f"anomaly_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                    pattern_type="statistical_anomaly",
                    confidence=0.85,
                    anomaly_score=float(np.mean([abs(s) for s in anomaly_scores if s == -1])),
                    affected_entities=[e.user_id or e.source for e in anomalous_events],
                    time_window={
                        "start": min(e.timestamp for e in anomalous_events).isoformat(),
                        "end": max(e.timestamp for e in anomalous_events).isoformat()
                    },
                    indicators=[
                        f"Anomalous {e.event_type} from {e.source}" for e in anomalous_events[:5]
                    ],
                    risk_level="medium",
                    description=f"Detected {len(anomalous_events)} statistically anomalous events",
                    recommended_actions=[
                        "Investigate anomalous events for potential threats",
                        "Review affected user accounts and resources",
                        "Check for unauthorized access patterns"
                    ]
                )
                patterns.append(pattern)
            
            # DBSCAN clustering for pattern detection
            clusters = self.dbscan.fit_predict(features_scaled)
            unique_clusters = set(clusters)
            
            for cluster_id in unique_clusters:
                if cluster_id == -1:  # Noise points
                    continue
                    
                cluster_indices = np.where(clusters == cluster_id)[0]
                if len(cluster_indices) > 5:  # Significant cluster
                    cluster_events = [events[i] for i in cluster_indices]
                    
                    pattern = BehavioralPattern(
                        pattern_id=f"cluster_{cluster_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                        pattern_type="behavioral_cluster",
                        confidence=0.75,
                        anomaly_score=0.5,
                        affected_entities=list(set(e.user_id or e.source for e in cluster_events)),
                        time_window={
                            "start": min(e.timestamp for e in cluster_events).isoformat(),
                            "end": max(e.timestamp for e in cluster_events).isoformat()
                        },
                        indicators=[
                            f"Clustered {e.event_type} activities" for e in cluster_events[:3]
                        ],
                        risk_level="low",
                        description=f"Detected behavioral cluster with {len(cluster_events)} similar events",
                        recommended_actions=[
                            "Monitor cluster for evolution",
                            "Validate if behavior is legitimate"
                        ]
                    )
                    patterns.append(pattern)
            
            return patterns
            
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            return []
    
    async def _analyze_user_behavior(self, events: List[SecurityEvent]) -> List[BehavioralPattern]:
        """Analyze user behavioral patterns"""
        patterns = []
        user_activities = defaultdict(list)
        
        # Group events by user
        for event in events:
            if event.user_id:
                user_activities[event.user_id].append(event)
        
        for user_id, user_events in user_activities.items():
            if len(user_events) < 5:
                continue
            
            # Analyze login patterns
            login_pattern = await self._analyze_login_patterns(user_id, user_events)
            if login_pattern:
                patterns.append(login_pattern)
            
            # Analyze resource access patterns
            access_pattern = await self._analyze_resource_access(user_id, user_events)
            if access_pattern:
                patterns.append(access_pattern)
            
            # Analyze time-based patterns
            temporal_pattern = await self._analyze_user_temporal_patterns(user_id, user_events)
            if temporal_pattern:
                patterns.append(temporal_pattern)
        
        return patterns
    
    async def _analyze_login_patterns(
        self,
        user_id: str,
        events: List[SecurityEvent]
    ) -> Optional[BehavioralPattern]:
        """Analyze login patterns for a specific user"""
        login_events = [e for e in events if 'login' in e.event_type.lower() or 'auth' in e.event_type.lower()]
        
        if len(login_events) < 3:
            return None
        
        # Check for unusual login times
        login_hours = [e.timestamp.hour for e in login_events]
        unusual_hours = [h for h in login_hours if h < 6 or h > 22]
        
        # Check for multiple failed logins
        failed_logins = [e for e in login_events if e.result.lower() in ['failed', 'denied']]
        
        # Check for logins from multiple locations/sources
        sources = set(e.source for e in login_events)
        
        risk_indicators = []
        risk_level = "low"
        
        if len(unusual_hours) > len(login_hours) * 0.3:
            risk_indicators.append(f"Unusual login times: {unusual_hours}")
            risk_level = "medium"
        
        if len(failed_logins) > 3:
            risk_indicators.append(f"{len(failed_logins)} failed login attempts")
            risk_level = "high"
        
        if len(sources) > 3:
            risk_indicators.append(f"Logins from {len(sources)} different sources")
            risk_level = "medium"
        
        if not risk_indicators:
            return None
        
        return BehavioralPattern(
            pattern_id=f"login_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            pattern_type="login_behavior",
            confidence=0.8,
            anomaly_score=len(risk_indicators) * 0.3,
            affected_entities=[user_id],
            time_window={
                "start": min(e.timestamp for e in login_events).isoformat(),
                "end": max(e.timestamp for e in login_events).isoformat()
            },
            indicators=risk_indicators,
            risk_level=risk_level,
            description=f"Suspicious login patterns detected for user {user_id}",
            recommended_actions=[
                "Review user authentication logs",
                "Verify user identity and recent activities",
                "Consider additional authentication requirements"
            ]
        )
    
    async def _analyze_temporal_patterns(self, events: List[SecurityEvent]) -> List[BehavioralPattern]:
        """Analyze temporal patterns in events"""
        patterns = []
        
        # Analyze events by hour
        hourly_counts = defaultdict(int)
        for event in events:
            hourly_counts[event.timestamp.hour] += 1
        
        # Detect unusual activity hours
        avg_hourly = np.mean(list(hourly_counts.values()))
        std_hourly = np.std(list(hourly_counts.values()))
        
        unusual_hours = []
        for hour, count in hourly_counts.items():
            if count > avg_hourly + 2 * std_hourly:
                unusual_hours.append((hour, count))
        
        if unusual_hours:
            pattern = BehavioralPattern(
                pattern_id=f"temporal_spike_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                pattern_type="temporal_anomaly",
                confidence=0.75,
                anomaly_score=len(unusual_hours) * 0.2,
                affected_entities=list(set(e.source for e in events)),
                time_window={
                    "start": min(e.timestamp for e in events).isoformat(),
                    "end": max(e.timestamp for e in events).isoformat()
                },
                indicators=[f"High activity at hour {h}: {c} events" for h, c in unusual_hours],
                risk_level="medium",
                description=f"Detected unusual temporal activity spikes",
                recommended_actions=[
                    "Investigate cause of activity spikes",
                    "Check for automated or scripted activities",
                    "Verify legitimacy of high-volume periods"
                ]
            )
            patterns.append(pattern)
        
        return patterns
    
    async def _detect_lateral_movement(self, events: List[SecurityEvent]) -> List[BehavioralPattern]:
        """Detect lateral movement patterns"""
        patterns = []
        
        # Group events by user and track resource access
        user_resources = defaultdict(set)
        user_timelines = defaultdict(list)
        
        for event in events:
            if event.user_id:
                user_resources[event.user_id].add(event.resource)
                user_timelines[event.user_id].append((event.timestamp, event.resource))
        
        for user_id, resources in user_resources.items():
            if len(resources) > 5:  # User accessed many resources
                timeline = sorted(user_timelines[user_id])
                
                # Check for rapid resource enumeration
                rapid_access = []
                for i in range(len(timeline) - 1):
                    time_diff = (timeline[i+1][0] - timeline[i][0]).total_seconds()
                    if time_diff < 60:  # Less than 1 minute between accesses
                        rapid_access.append((timeline[i][1], timeline[i+1][1]))
                
                if len(rapid_access) > 3:
                    pattern = BehavioralPattern(
                        pattern_id=f"lateral_movement_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                        pattern_type="lateral_movement",
                        confidence=0.85,
                        anomaly_score=len(rapid_access) * 0.2,
                        affected_entities=[user_id],
                        time_window={
                            "start": timeline[0][0].isoformat(),
                            "end": timeline[-1][0].isoformat()
                        },
                        indicators=[
                            f"Rapid access to {len(resources)} different resources",
                            f"{len(rapid_access)} rapid sequential accesses"
                        ],
                        risk_level="high",
                        description=f"Potential lateral movement detected for user {user_id}",
                        recommended_actions=[
                            "Immediately investigate user activities",
                            "Check for unauthorized access patterns",
                            "Review resource access logs",
                            "Consider temporary access restrictions"
                        ]
                    )
                    patterns.append(pattern)
        
        return patterns
    
    async def _detect_privilege_escalation(self, events: List[SecurityEvent]) -> List[BehavioralPattern]:
        """Detect privilege escalation patterns"""
        patterns = []
        
        # Look for escalation-related events
        escalation_keywords = ['privilege', 'admin', 'root', 'sudo', 'elevation', 'escalation']
        privilege_events = []
        
        for event in events:
            if any(keyword in event.action.lower() or keyword in event.event_type.lower() 
                   for keyword in escalation_keywords):
                privilege_events.append(event)
        
        if len(privilege_events) > 2:
            users_with_escalation = defaultdict(list)
            for event in privilege_events:
                if event.user_id:
                    users_with_escalation[event.user_id].append(event)
            
            for user_id, user_events in users_with_escalation.items():
                if len(user_events) > 1:
                    pattern = BehavioralPattern(
                        pattern_id=f"privilege_escalation_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                        pattern_type="privilege_escalation",
                        confidence=0.90,
                        anomaly_score=len(user_events) * 0.3,
                        affected_entities=[user_id],
                        time_window={
                            "start": min(e.timestamp for e in user_events).isoformat(),
                            "end": max(e.timestamp for e in user_events).isoformat()
                        },
                        indicators=[
                            f"Multiple privilege-related actions: {[e.action for e in user_events]}"
                        ],
                        risk_level="high",
                        description=f"Potential privilege escalation detected for user {user_id}",
                        recommended_actions=[
                            "URGENT: Investigate privilege escalation immediately",
                            "Review user permissions and recent changes",
                            "Check for unauthorized administrative activities",
                            "Consider immediate account restriction"
                        ]
                    )
                    patterns.append(pattern)
        
        return patterns
    
    async def _analyze_access_patterns(self, events: List[SecurityEvent]) -> List[BehavioralPattern]:
        """Analyze resource access patterns"""
        patterns = []
        
        # Analyze failed access attempts
        failed_events = [e for e in events if e.result.lower() in ['failed', 'denied', 'blocked']]
        
        if len(failed_events) > 10:
            # Group by source to detect potential brute force
            source_failures = defaultdict(list)
            for event in failed_events:
                source_failures[event.source].append(event)
            
            for source, failures in source_failures.items():
                if len(failures) > 5:
                    pattern = BehavioralPattern(
                        pattern_id=f"access_pattern_{source}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                        pattern_type="failed_access_pattern",
                        confidence=0.80,
                        anomaly_score=len(failures) * 0.1,
                        affected_entities=[source],
                        time_window={
                            "start": min(e.timestamp for e in failures).isoformat(),
                            "end": max(e.timestamp for e in failures).isoformat()
                        },
                        indicators=[
                            f"{len(failures)} failed access attempts from {source}"
                        ],
                        risk_level="medium" if len(failures) < 20 else "high",
                        description=f"High number of failed access attempts from {source}",
                        recommended_actions=[
                            "Investigate source of failed attempts",
                            "Consider blocking or rate-limiting source",
                            "Review access control policies"
                        ]
                    )
                    patterns.append(pattern)
        
        return patterns
    
    async def _rank_patterns(self, patterns: List[BehavioralPattern]) -> List[BehavioralPattern]:
        """Rank patterns by risk and confidence"""
        risk_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        
        def pattern_score(pattern):
            risk_weight = risk_weights.get(pattern.risk_level, 1)
            return pattern.confidence * risk_weight * (1 + pattern.anomaly_score)
        
        return sorted(patterns, key=pattern_score, reverse=True)
    
    async def _load_baseline_behavior(self):
        """Load baseline behavioral patterns"""
        # In a real implementation, this would load from a database
        self.baseline_behavior = {
            "normal_login_hours": list(range(8, 18)),  # 8 AM to 6 PM
            "max_failed_logins": 3,
            "max_resources_per_hour": 20,
            "normal_activity_sources": set()
        }
    
    async def _update_baseline_behavior(self, events: List[SecurityEvent]):
        """Update baseline behavior based on new events"""
        if not self.learning_enabled:
            return
        
        # Update normal activity sources
        sources = set(e.source for e in events if e.result.lower() in ['success', 'allowed'])
        self.baseline_behavior["normal_activity_sources"].update(sources)
        
        # Keep only the most recent 1000 sources to prevent memory bloat
        if len(self.baseline_behavior["normal_activity_sources"]) > 1000:
            source_list = list(self.baseline_behavior["normal_activity_sources"])
            self.baseline_behavior["normal_activity_sources"] = set(source_list[-1000:])
    
    async def _analyze_resource_access(self, user_id: str, events: List[SecurityEvent]) -> Optional[BehavioralPattern]:
        """Analyze resource access patterns for a user"""
        resources = [e.resource for e in events]
        unique_resources = set(resources)
        
        if len(unique_resources) > 10:  # User accessed many different resources
            return BehavioralPattern(
                pattern_id=f"resource_access_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                pattern_type="resource_enumeration",
                confidence=0.70,
                anomaly_score=len(unique_resources) * 0.05,
                affected_entities=[user_id],
                time_window={
                    "start": min(e.timestamp for e in events).isoformat(),
                    "end": max(e.timestamp for e in events).isoformat()
                },
                indicators=[f"Accessed {len(unique_resources)} different resources"],
                risk_level="medium",
                description=f"User {user_id} accessed unusually high number of resources",
                recommended_actions=[
                    "Review user's job requirements",
                    "Validate legitimate need for resource access",
                    "Monitor for potential data exfiltration"
                ]
            )
        return None
    
    async def _analyze_user_temporal_patterns(self, user_id: str, events: List[SecurityEvent]) -> Optional[BehavioralPattern]:
        """Analyze temporal patterns for a specific user"""
        hours = [e.timestamp.hour for e in events]
        off_hours = [h for h in hours if h < 6 or h > 22]
        
        if len(off_hours) > len(hours) * 0.5:  # More than 50% activity outside business hours
            return BehavioralPattern(
                pattern_id=f"off_hours_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                pattern_type="off_hours_activity",
                confidence=0.75,
                anomaly_score=len(off_hours) / len(hours),
                affected_entities=[user_id],
                time_window={
                    "start": min(e.timestamp for e in events).isoformat(),
                    "end": max(e.timestamp for e in events).isoformat()
                },
                indicators=[f"Significant off-hours activity: {len(off_hours)}/{len(hours)} events"],
                risk_level="medium",
                description=f"User {user_id} shows unusual off-hours activity pattern",
                recommended_actions=[
                    "Verify user's work schedule and time zone",
                    "Check for automated processes running under user account",
                    "Investigate necessity of off-hours access"
                ]
            )
        return None


class BehavioralNeuralNetwork(nn.Module):
    """Neural network for complex behavioral pattern detection"""
    
    def __init__(self, input_size=50, hidden_size=128, output_size=1):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_size // 2, output_size),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        return self.network(x)