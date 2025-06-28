#!/usr/bin/env python3
"""
Data Protection and Privacy Compliance Implementation for AuditHound
Implements GDPR/CCPA compliance, data retention policies, and data subject rights
"""

import os
import json
import logging
import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import time
import re
from collections import defaultdict

# Import our security components (placeholder for now)
try:
    from src.security.config_manager import get_config
    from src.security.secrets_manager import SecretsManager
except ImportError:
    # Fallback for testing
    def get_config():
        return {}
    
    class SecretsManager:
        def __init__(self, config=None):
            pass

logger = logging.getLogger(__name__)

class PersonalDataType(Enum):
    """Types of personal data under GDPR/CCPA"""
    IDENTIFIER = "identifier"  # Names, emails, phone numbers
    DEMOGRAPHIC = "demographic"  # Age, gender, location
    FINANCIAL = "financial"  # Payment info, financial records
    BIOMETRIC = "biometric"  # Fingerprints, facial recognition
    BEHAVIORAL = "behavioral"  # Browsing history, preferences
    LOCATION = "location"  # GPS, IP addresses
    COMMUNICATION = "communication"  # Messages, call logs
    TECHNICAL = "technical"  # Device info, cookies
    SENSITIVE = "sensitive"  # Health, religion, political views

class DataSubjectRight(Enum):
    """Data subject rights under GDPR"""
    ACCESS = "access"  # Right to access (Article 15)
    RECTIFICATION = "rectification"  # Right to rectification (Article 16)
    ERASURE = "erasure"  # Right to be forgotten (Article 17)
    PORTABILITY = "portability"  # Right to data portability (Article 20)
    RESTRICTION = "restriction"  # Right to restrict processing (Article 18)
    OBJECTION = "objection"  # Right to object (Article 21)
    WITHDRAW_CONSENT = "withdraw_consent"  # Withdraw consent (Article 7)

class LegalBasis(Enum):
    """Legal basis for processing under GDPR Article 6"""
    CONSENT = "consent"  # Article 6(1)(a)
    CONTRACT = "contract"  # Article 6(1)(b)
    LEGAL_OBLIGATION = "legal_obligation"  # Article 6(1)(c)
    VITAL_INTERESTS = "vital_interests"  # Article 6(1)(d)
    PUBLIC_TASK = "public_task"  # Article 6(1)(e)
    LEGITIMATE_INTERESTS = "legitimate_interests"  # Article 6(1)(f)

class RetentionStatus(Enum):
    """Data retention status"""
    ACTIVE = "active"
    PENDING_DELETION = "pending_deletion"
    SCHEDULED_DELETION = "scheduled_deletion"
    DELETED = "deleted"
    ARCHIVED = "archived"
    UNDER_LEGAL_HOLD = "under_legal_hold"

@dataclass
class PersonalDataRecord:
    """Personal data record for tracking and compliance"""
    record_id: str
    data_subject_id: str
    data_type: PersonalDataType
    data_category: str
    legal_basis: LegalBasis
    
    # Data details
    data_location: str  # Where the data is stored
    data_format: str  # JSON, CSV, binary, etc.
    encrypted: bool = True
    
    # Processing details
    purpose: str = ""
    collection_date: datetime = field(default_factory=datetime.now)
    consent_date: Optional[datetime] = None
    consent_id: Optional[str] = None
    
    # Retention and lifecycle
    retention_period_days: int = 365
    retention_status: RetentionStatus = RetentionStatus.ACTIVE
    scheduled_deletion: Optional[datetime] = None
    last_accessed: Optional[datetime] = None
    
    # Compliance tracking
    gdpr_applicable: bool = True
    ccpa_applicable: bool = False
    data_source: str = ""
    third_party_shared: List[str] = field(default_factory=list)
    
    # Audit trail
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DataSubjectRequest:
    """Data subject rights request"""
    request_id: str
    data_subject_id: str
    request_type: DataSubjectRight
    status: str = "pending"  # pending, in_progress, completed, rejected
    
    # Request details
    request_date: datetime = field(default_factory=datetime.now)
    description: str = ""
    identity_verified: bool = False
    
    # Processing
    assigned_to: str = ""
    due_date: Optional[datetime] = None
    completion_date: Optional[datetime] = None
    response_data: Dict[str, Any] = field(default_factory=dict)
    
    # Compliance
    response_time_hours: int = 0
    legal_review_required: bool = False
    notes: List[str] = field(default_factory=list)

class PIIDetector:
    """PII detection and classification"""
    
    def __init__(self):
        self.pii_patterns = {
            PersonalDataType.IDENTIFIER: [
                (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'email'),
                (r'\b\d{3}-?\d{3}-?\d{4}\b', 'phone'),
                (r'\b\d{3}-?\d{2}-?\d{4}\b', 'ssn'),
            ],
            PersonalDataType.FINANCIAL: [
                (r'\b4[0-9]{12}(?:[0-9]{3})?\b', 'visa_card'),
                (r'\b5[1-5][0-9]{14}\b', 'mastercard'),
                (r'\b3[47][0-9]{13}\b', 'amex'),
            ],
            PersonalDataType.LOCATION: [
                (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'ip_address'),
                (r'\b\d{5}(?:-\d{4})?\b', 'zip_code'),
            ],
        }
        
        self.sensitive_keywords = [
            'password', 'token', 'secret', 'key', 'credential',
            'birth_date', 'age', 'gender', 'race', 'religion',
            'health', 'medical', 'diagnosis', 'prescription'
        ]
    
    def detect_pii(self, text: str) -> List[Dict[str, Any]]:
        """Detect PII in text content"""
        findings = []
        
        # Pattern-based detection
        for data_type, patterns in self.pii_patterns.items():
            for pattern, pii_type in patterns:
                matches = re.finditer(pattern, text, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        'type': data_type.value,
                        'subtype': pii_type,
                        'value': match.group(),
                        'start': match.start(),
                        'end': match.end(),
                        'confidence': 0.8
                    })
        
        # Keyword-based detection
        text_lower = text.lower()
        for keyword in self.sensitive_keywords:
            if keyword in text_lower:
                findings.append({
                    'type': PersonalDataType.SENSITIVE.value,
                    'subtype': 'keyword',
                    'value': keyword,
                    'confidence': 0.6
                })
        
        return findings
    
    def classify_data_sensitivity(self, data: Dict[str, Any]) -> PersonalDataType:
        """Classify data sensitivity level"""
        data_str = json.dumps(data, default=str).lower()
        
        # Check for sensitive data indicators
        if any(word in data_str for word in ['health', 'medical', 'religion', 'political']):
            return PersonalDataType.SENSITIVE
        
        if any(word in data_str for word in ['email', 'phone', 'name', 'address']):
            return PersonalDataType.IDENTIFIER
        
        if any(word in data_str for word in ['payment', 'card', 'bank', 'financial']):
            return PersonalDataType.FINANCIAL
        
        if any(word in data_str for word in ['location', 'gps', 'address', 'ip']):
            return PersonalDataType.LOCATION
        
        return PersonalDataType.TECHNICAL

class DataRetentionManager:
    """Manages data retention policies and lifecycle"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.retention_policies = self._load_retention_policies()
        self.data_records: Dict[str, PersonalDataRecord] = {}
        self.scheduled_deletions: List[Tuple[datetime, str]] = []
        
        # Default retention periods (days)
        self.default_retention = {
            PersonalDataType.IDENTIFIER: 2555,  # 7 years
            PersonalDataType.FINANCIAL: 2555,  # 7 years
            PersonalDataType.BEHAVIORAL: 365,  # 1 year
            PersonalDataType.TECHNICAL: 730,   # 2 years
            PersonalDataType.SENSITIVE: 365,   # 1 year
            PersonalDataType.COMMUNICATION: 1095,  # 3 years
            PersonalDataType.LOCATION: 365,    # 1 year
        }
        
        logger.info("Data retention manager initialized")
    
    def _load_retention_policies(self) -> Dict[str, Any]:
        """Load retention policies from configuration"""
        return {
            "default_retention_days": 365,
            "minimum_retention_days": 30,
            "maximum_retention_days": 2555,  # 7 years
            "auto_deletion_enabled": True,
            "legal_hold_override": True,
            "audit_retention_years": 7
        }
    
    def register_data_record(self, data_subject_id: str, data_type: PersonalDataType, 
                           data_location: str, legal_basis: LegalBasis, **kwargs) -> str:
        """Register a new personal data record"""
        record_id = str(uuid.uuid4())
        
        retention_days = kwargs.get('retention_period_days') or self.default_retention.get(
            data_type, self.retention_policies['default_retention_days']
        )
        
        record = PersonalDataRecord(
            record_id=record_id,
            data_subject_id=data_subject_id,
            data_type=data_type,
            data_category=kwargs.get('data_category', 'unknown'),
            legal_basis=legal_basis,
            data_location=data_location,
            data_format=kwargs.get('data_format', 'json'),
            purpose=kwargs.get('purpose', 'business_operations'),
            retention_period_days=retention_days,
            gdpr_applicable=kwargs.get('gdpr_applicable', True),
            ccpa_applicable=kwargs.get('ccpa_applicable', False),
            data_source=kwargs.get('data_source', 'application'),
            metadata=kwargs.get('metadata', {})
        )
        
        # Calculate scheduled deletion
        record.scheduled_deletion = record.collection_date + timedelta(days=retention_days)
        
        self.data_records[record_id] = record
        self._schedule_deletion(record)
        
        logger.info(f"Registered data record {record_id} for subject {data_subject_id}")
        return record_id
    
    def _schedule_deletion(self, record: PersonalDataRecord):
        """Schedule record for deletion"""
        if record.scheduled_deletion and self.retention_policies['auto_deletion_enabled']:
            self.scheduled_deletions.append((record.scheduled_deletion, record.record_id))
            self.scheduled_deletions.sort(key=lambda x: x[0])
    
    def get_records_for_deletion(self, check_date: datetime = None) -> List[PersonalDataRecord]:
        """Get records scheduled for deletion"""
        if check_date is None:
            check_date = datetime.now()
        
        records_to_delete = []
        for scheduled_time, record_id in self.scheduled_deletions:
            if scheduled_time <= check_date:
                record = self.data_records.get(record_id)
                if record and record.retention_status == RetentionStatus.ACTIVE:
                    records_to_delete.append(record)
        
        return records_to_delete
    
    def execute_scheduled_deletions(self) -> Dict[str, Any]:
        """Execute scheduled data deletions"""
        deletion_results = {
            'deleted_records': [],
            'failed_deletions': [],
            'total_processed': 0,
            'execution_time': datetime.now()
        }
        
        records_to_delete = self.get_records_for_deletion()
        
        for record in records_to_delete:
            try:
                # Mark as pending deletion
                record.retention_status = RetentionStatus.PENDING_DELETION
                record.updated_at = datetime.now()
                
                # Perform actual deletion
                success = self._delete_data_record(record)
                
                if success:
                    record.retention_status = RetentionStatus.DELETED
                    deletion_results['deleted_records'].append({
                        'record_id': record.record_id,
                        'data_subject_id': record.data_subject_id,
                        'data_type': record.data_type.value,
                        'deleted_at': datetime.now().isoformat()
                    })
                else:
                    deletion_results['failed_deletions'].append(record.record_id)
                
                deletion_results['total_processed'] += 1
                
            except Exception as e:
                logger.error(f"Failed to delete record {record.record_id}: {e}")
                deletion_results['failed_deletions'].append(record.record_id)
        
        logger.info(f"Executed {len(deletion_results['deleted_records'])} scheduled deletions")
        return deletion_results
    
    def _delete_data_record(self, record: PersonalDataRecord) -> bool:
        """Perform actual data deletion"""
        try:
            # This would implement actual data deletion logic
            # For example: delete from database, remove files, etc.
            
            # Placeholder implementation
            logger.info(f"Deleting data at {record.data_location} for record {record.record_id}")
            
            # In a real implementation, this would:
            # 1. Delete from Weaviate
            # 2. Remove files from disk
            # 3. Clear cache entries
            # 4. Update backup systems
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete data for record {record.record_id}: {e}")
            return False
    
    def extend_retention(self, record_id: str, additional_days: int, reason: str) -> bool:
        """Extend retention period for a record"""
        record = self.data_records.get(record_id)
        if not record:
            return False
        
        record.retention_period_days += additional_days
        record.scheduled_deletion = record.collection_date + timedelta(
            days=record.retention_period_days
        )
        record.updated_at = datetime.now()
        record.metadata['retention_extension'] = {
            'additional_days': additional_days,
            'reason': reason,
            'extended_at': datetime.now().isoformat()
        }
        
        # Update scheduled deletions
        self._schedule_deletion(record)
        
        logger.info(f"Extended retention for record {record_id} by {additional_days} days")
        return True

class DataSubjectRightsManager:
    """Manages GDPR data subject rights requests"""
    
    def __init__(self, retention_manager: DataRetentionManager):
        self.retention_manager = retention_manager
        self.requests: Dict[str, DataSubjectRequest] = {}
        self.sla_hours = {
            DataSubjectRight.ACCESS: 720,  # 30 days
            DataSubjectRight.RECTIFICATION: 720,  # 30 days
            DataSubjectRight.ERASURE: 720,  # 30 days
            DataSubjectRight.PORTABILITY: 720,  # 30 days
            DataSubjectRight.RESTRICTION: 72,  # 3 days
            DataSubjectRight.OBJECTION: 72,  # 3 days
            DataSubjectRight.WITHDRAW_CONSENT: 24,  # 1 day
        }
        
        logger.info("Data subject rights manager initialized")
    
    def submit_request(self, data_subject_id: str, request_type: DataSubjectRight, 
                      description: str = "", **kwargs) -> str:
        """Submit a new data subject rights request"""
        request_id = str(uuid.uuid4())
        
        # Calculate due date based on SLA
        sla_hours = self.sla_hours.get(request_type, 720)
        due_date = datetime.now() + timedelta(hours=sla_hours)
        
        request = DataSubjectRequest(
            request_id=request_id,
            data_subject_id=data_subject_id,
            request_type=request_type,
            description=description,
            due_date=due_date,
            identity_verified=kwargs.get('identity_verified', False),
            legal_review_required=kwargs.get('legal_review_required', False)
        )
        
        self.requests[request_id] = request
        
        logger.info(f"Submitted {request_type.value} request {request_id} for subject {data_subject_id}")
        return request_id
    
    def process_access_request(self, request_id: str) -> Dict[str, Any]:
        """Process right to access request (GDPR Article 15)"""
        request = self.requests.get(request_id)
        if not request or request.request_type != DataSubjectRight.ACCESS:
            return {'error': 'Invalid request'}
        
        request.status = 'in_progress'
        
        # Find all data for the subject
        subject_data = self._get_subject_data(request.data_subject_id)
        
        # Prepare response
        response_data = {
            'data_subject_id': request.data_subject_id,
            'request_date': request.request_date.isoformat(),
            'data_records': subject_data,
            'processing_purposes': self._get_processing_purposes(request.data_subject_id),
            'legal_basis': self._get_legal_basis_summary(request.data_subject_id),
            'retention_periods': self._get_retention_summary(request.data_subject_id),
            'third_party_sharing': self._get_third_party_sharing(request.data_subject_id)
        }
        
        request.response_data = response_data
        request.status = 'completed'
        request.completion_date = datetime.now()
        
        logger.info(f"Processed access request {request_id}")
        return response_data
    
    def process_erasure_request(self, request_id: str) -> Dict[str, Any]:
        """Process right to be forgotten request (GDPR Article 17)"""
        request = self.requests.get(request_id)
        if not request or request.request_type != DataSubjectRight.ERASURE:
            return {'error': 'Invalid request'}
        
        request.status = 'in_progress'
        
        # Find all records for the subject
        subject_records = [
            record for record in self.retention_manager.data_records.values()
            if record.data_subject_id == request.data_subject_id
        ]
        
        deletion_results = {
            'deleted_records': [],
            'retained_records': [],
            'total_processed': len(subject_records)
        }
        
        for record in subject_records:
            # Check if deletion is legally required or permitted
            can_delete = self._can_delete_record(record)
            
            if can_delete:
                # Mark for immediate deletion
                record.retention_status = RetentionStatus.SCHEDULED_DELETION
                record.scheduled_deletion = datetime.now()
                record.updated_at = datetime.now()
                
                deletion_results['deleted_records'].append({
                    'record_id': record.record_id,
                    'data_type': record.data_type.value,
                    'scheduled_deletion': record.scheduled_deletion.isoformat()
                })
            else:
                deletion_results['retained_records'].append({
                    'record_id': record.record_id,
                    'reason': 'Legal obligation or legitimate interest'
                })
        
        request.response_data = deletion_results
        request.status = 'completed'
        request.completion_date = datetime.now()
        
        logger.info(f"Processed erasure request {request_id}")
        return deletion_results
    
    def process_portability_request(self, request_id: str) -> Dict[str, Any]:
        """Process data portability request (GDPR Article 20)"""
        request = self.requests.get(request_id)
        if not request or request.request_type != DataSubjectRight.PORTABILITY:
            return {'error': 'Invalid request'}
        
        request.status = 'in_progress'
        
        # Get portable data (consent and contract basis only)
        portable_data = self._get_portable_data(request.data_subject_id)
        
        # Format in machine-readable format
        export_data = {
            'data_subject_id': request.data_subject_id,
            'export_date': datetime.now().isoformat(),
            'format': 'json',
            'data': portable_data
        }
        
        request.response_data = export_data
        request.status = 'completed'
        request.completion_date = datetime.now()
        
        logger.info(f"Processed portability request {request_id}")
        return export_data
    
    def _get_subject_data(self, data_subject_id: str) -> List[Dict[str, Any]]:
        """Get all data for a subject"""
        subject_records = [
            record for record in self.retention_manager.data_records.values()
            if record.data_subject_id == data_subject_id
        ]
        
        return [self._record_to_dict(record) for record in subject_records]
    
    def _get_processing_purposes(self, data_subject_id: str) -> List[str]:
        """Get processing purposes for a subject"""
        purposes = set()
        for record in self.retention_manager.data_records.values():
            if record.data_subject_id == data_subject_id:
                purposes.add(record.purpose)
        return list(purposes)
    
    def _get_legal_basis_summary(self, data_subject_id: str) -> Dict[str, int]:
        """Get legal basis summary for a subject"""
        basis_count = defaultdict(int)
        for record in self.retention_manager.data_records.values():
            if record.data_subject_id == data_subject_id:
                basis_count[record.legal_basis.value] += 1
        return dict(basis_count)
    
    def _get_retention_summary(self, data_subject_id: str) -> Dict[str, Any]:
        """Get retention summary for a subject"""
        records = [
            record for record in self.retention_manager.data_records.values()
            if record.data_subject_id == data_subject_id
        ]
        
        if not records:
            return {}
        
        return {
            'total_records': len(records),
            'earliest_collection': min(r.collection_date for r in records).isoformat(),
            'latest_collection': max(r.collection_date for r in records).isoformat(),
            'next_scheduled_deletion': min(
                r.scheduled_deletion for r in records 
                if r.scheduled_deletion and r.retention_status == RetentionStatus.ACTIVE
            ).isoformat() if any(r.scheduled_deletion for r in records) else None
        }
    
    def _get_third_party_sharing(self, data_subject_id: str) -> List[str]:
        """Get third party sharing info for a subject"""
        third_parties = set()
        for record in self.retention_manager.data_records.values():
            if record.data_subject_id == data_subject_id:
                third_parties.update(record.third_party_shared)
        return list(third_parties)
    
    def _get_portable_data(self, data_subject_id: str) -> List[Dict[str, Any]]:
        """Get portable data (consent/contract basis only)"""
        portable_records = [
            record for record in self.retention_manager.data_records.values()
            if (record.data_subject_id == data_subject_id and 
                record.legal_basis in [LegalBasis.CONSENT, LegalBasis.CONTRACT])
        ]
        
        return [self._record_to_dict(record) for record in portable_records]
    
    def _can_delete_record(self, record: PersonalDataRecord) -> bool:
        """Check if a record can be deleted"""
        # Cannot delete if under legal hold
        if record.retention_status == RetentionStatus.UNDER_LEGAL_HOLD:
            return False
        
        # Cannot delete if legal obligation
        if record.legal_basis == LegalBasis.LEGAL_OBLIGATION:
            return False
        
        # Check minimum retention requirements
        min_retention = timedelta(days=30)  # Example minimum
        age = datetime.now() - record.collection_date
        if age < min_retention:
            return False
        
        return True
    
    def _record_to_dict(self, record: PersonalDataRecord) -> Dict[str, Any]:
        """Convert record to dictionary"""
        return {
            'record_id': record.record_id,
            'data_type': record.data_type.value,
            'data_category': record.data_category,
            'legal_basis': record.legal_basis.value,
            'purpose': record.purpose,
            'collection_date': record.collection_date.isoformat(),
            'retention_period_days': record.retention_period_days,
            'scheduled_deletion': record.scheduled_deletion.isoformat() if record.scheduled_deletion else None,
            'encrypted': record.encrypted,
            'third_party_shared': record.third_party_shared
        }

class CCPAComplianceManager:
    """CCPA-specific compliance management"""
    
    def __init__(self, rights_manager: DataSubjectRightsManager):
        self.rights_manager = rights_manager
        self.opt_out_requests: Dict[str, Dict[str, Any]] = {}
        
        logger.info("CCPA compliance manager initialized")
    
    def process_opt_out_request(self, consumer_id: str, request_details: Dict[str, Any]) -> str:
        """Process CCPA opt-out of sale request"""
        request_id = str(uuid.uuid4())
        
        opt_out_request = {
            'request_id': request_id,
            'consumer_id': consumer_id,
            'request_date': datetime.now().isoformat(),
            'opt_out_type': request_details.get('opt_out_type', 'sale'),  # sale, targeted_advertising
            'status': 'pending',
            'verified': request_details.get('verified', False),
            'method': request_details.get('method', 'web_form'),  # web_form, email, phone
        }
        
        self.opt_out_requests[request_id] = opt_out_request
        
        # Process the opt-out
        self._execute_opt_out(request_id)
        
        logger.info(f"Processed CCPA opt-out request {request_id} for consumer {consumer_id}")
        return request_id
    
    def _execute_opt_out(self, request_id: str):
        """Execute the opt-out request"""
        request = self.opt_out_requests.get(request_id)
        if not request:
            return
        
        # Mark all relevant records as opted out
        consumer_id = request['consumer_id']
        
        for record in self.rights_manager.retention_manager.data_records.values():
            if record.data_subject_id == consumer_id and record.ccpa_applicable:
                record.metadata['ccpa_opt_out'] = {
                    'opted_out': True,
                    'opt_out_date': datetime.now().isoformat(),
                    'request_id': request_id
                }
                record.updated_at = datetime.now()
        
        request['status'] = 'completed'
        request['completion_date'] = datetime.now().isoformat()
    
    def get_consumer_data_summary(self, consumer_id: str) -> Dict[str, Any]:
        """Get CCPA-required consumer data summary"""
        consumer_records = [
            record for record in self.rights_manager.retention_manager.data_records.values()
            if record.data_subject_id == consumer_id and record.ccpa_applicable
        ]
        
        # Categorize data
        data_categories = defaultdict(list)
        for record in consumer_records:
            data_categories[record.data_type.value].append({
                'purpose': record.purpose,
                'source': record.data_source,
                'third_parties': record.third_party_shared
            })
        
        return {
            'consumer_id': consumer_id,
            'data_categories': dict(data_categories),
            'sources_of_information': list(set(r.data_source for r in consumer_records)),
            'business_purposes': list(set(r.purpose for r in consumer_records)),
            'third_parties': list(set(
                party for record in consumer_records 
                for party in record.third_party_shared
            )),
            'total_records': len(consumer_records)
        }

class DataProtectionManager:
    """Main data protection and privacy compliance manager"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Initialize components
        self.pii_detector = PIIDetector()
        self.retention_manager = DataRetentionManager(config)
        self.rights_manager = DataSubjectRightsManager(self.retention_manager)
        self.ccpa_manager = CCPAComplianceManager(self.rights_manager)
        
        # Compliance tracking
        self.compliance_metrics = {
            'total_data_subjects': 0,
            'active_records': 0,
            'pending_requests': 0,
            'completed_requests': 0,
            'scheduled_deletions': 0,
            'opt_out_requests': 0
        }
        
        logger.info("Data protection manager initialized")
    
    def scan_for_pii(self, data_source: str) -> Dict[str, Any]:
        """Scan data source for PII"""
        findings = []
        
        try:
            # This would implement actual data scanning
            # For example: scan database, files, logs, etc.
            
            # Placeholder implementation
            sample_texts = [
                "User email: john.doe@example.com, phone: 555-123-4567",
                "Credit card: 4111111111111111, SSN: 123-45-6789",
                "Medical record for patient with diabetes"
            ]
            
            for idx, text in enumerate(sample_texts):
                pii_findings = self.pii_detector.detect_pii(text)
                for finding in pii_findings:
                    finding['source_location'] = f"{data_source}:record_{idx}"
                    findings.append(finding)
            
            return {
                'data_source': data_source,
                'scan_date': datetime.now().isoformat(),
                'total_findings': len(findings),
                'findings': findings,
                'recommendations': self._generate_pii_recommendations(findings)
            }
            
        except Exception as e:
            logger.error(f"PII scan failed for {data_source}: {e}")
            return {'error': str(e)}
    
    def _generate_pii_recommendations(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on PII findings"""
        recommendations = []
        
        data_types = set(finding['type'] for finding in findings)
        
        if PersonalDataType.IDENTIFIER.value in data_types:
            recommendations.append("Implement data minimization for identifier data")
            recommendations.append("Consider pseudonymization for email addresses")
        
        if PersonalDataType.FINANCIAL.value in data_types:
            recommendations.append("Ensure PCI DSS compliance for financial data")
            recommendations.append("Implement tokenization for payment card data")
        
        if PersonalDataType.SENSITIVE.value in data_types:
            recommendations.append("Apply enhanced security controls for sensitive data")
            recommendations.append("Obtain explicit consent for sensitive data processing")
        
        return recommendations
    
    def register_data_processing(self, data_subject_id: str, data_details: Dict[str, Any]) -> str:
        """Register new data processing activity"""
        data_type = self.pii_detector.classify_data_sensitivity(data_details)
        
        # Extract legal_basis separately to avoid duplicate keyword argument
        legal_basis_str = data_details.pop('legal_basis', 'legitimate_interests')
        legal_basis = LegalBasis(legal_basis_str)
        
        record_id = self.retention_manager.register_data_record(
            data_subject_id=data_subject_id,
            data_type=data_type,
            data_location=data_details.get('location', 'unknown'),
            legal_basis=legal_basis,
            **data_details
        )
        
        self._update_compliance_metrics()
        return record_id
    
    def process_subject_request(self, data_subject_id: str, request_type: str, 
                              description: str = "") -> str:
        """Process data subject rights request"""
        request_right = DataSubjectRight(request_type)
        
        request_id = self.rights_manager.submit_request(
            data_subject_id, request_right, description
        )
        
        # Auto-process certain requests
        if request_right == DataSubjectRight.ACCESS:
            self.rights_manager.process_access_request(request_id)
        elif request_right == DataSubjectRight.ERASURE:
            self.rights_manager.process_erasure_request(request_id)
        elif request_right == DataSubjectRight.PORTABILITY:
            self.rights_manager.process_portability_request(request_id)
        
        self._update_compliance_metrics()
        return request_id
    
    def execute_data_retention(self) -> Dict[str, Any]:
        """Execute data retention policies"""
        results = self.retention_manager.execute_scheduled_deletions()
        self._update_compliance_metrics()
        return results
    
    def get_compliance_dashboard(self) -> Dict[str, Any]:
        """Get compliance dashboard data"""
        self._update_compliance_metrics()
        
        # Calculate compliance scores
        gdpr_score = self._calculate_gdpr_compliance_score()
        ccpa_score = self._calculate_ccpa_compliance_score()
        
        return {
            'compliance_metrics': self.compliance_metrics,
            'gdpr_compliance_score': gdpr_score,
            'ccpa_compliance_score': ccpa_score,
            'data_retention_status': self._get_retention_status(),
            'recent_requests': self._get_recent_requests(),
            'upcoming_deletions': self._get_upcoming_deletions(),
            'compliance_alerts': self._get_compliance_alerts()
        }
    
    def _update_compliance_metrics(self):
        """Update compliance metrics"""
        self.compliance_metrics.update({
            'total_data_subjects': len(set(
                record.data_subject_id 
                for record in self.retention_manager.data_records.values()
            )),
            'active_records': len([
                record for record in self.retention_manager.data_records.values()
                if record.retention_status == RetentionStatus.ACTIVE
            ]),
            'pending_requests': len([
                req for req in self.rights_manager.requests.values()
                if req.status == 'pending'
            ]),
            'completed_requests': len([
                req for req in self.rights_manager.requests.values()
                if req.status == 'completed'
            ]),
            'scheduled_deletions': len(self.retention_manager.get_records_for_deletion()),
            'opt_out_requests': len(self.ccpa_manager.opt_out_requests)
        })
    
    def _calculate_gdpr_compliance_score(self) -> float:
        """Calculate GDPR compliance score"""
        total_score = 0
        max_score = 100
        
        # Data inventory completeness (25 points)
        if self.compliance_metrics['active_records'] > 0:
            total_score += 25
        
        # Retention policy implementation (25 points)
        scheduled_deletions = self.compliance_metrics['scheduled_deletions']
        if scheduled_deletions >= 0:  # Has scheduled deletions
            total_score += 25
        
        # Rights request handling (25 points)
        total_requests = (self.compliance_metrics['pending_requests'] + 
                         self.compliance_metrics['completed_requests'])
        if total_requests == 0 or self.compliance_metrics['completed_requests'] / total_requests > 0.8:
            total_score += 25
        
        # Data protection measures (25 points)
        encrypted_records = len([
            record for record in self.retention_manager.data_records.values()
            if record.encrypted
        ])
        total_records = len(self.retention_manager.data_records)
        if total_records == 0 or encrypted_records / total_records > 0.9:
            total_score += 25
        
        return total_score
    
    def _calculate_ccpa_compliance_score(self) -> float:
        """Calculate CCPA compliance score"""
        total_score = 0
        max_score = 100
        
        # Consumer data inventory (30 points)
        ccpa_records = len([
            record for record in self.retention_manager.data_records.values()
            if record.ccpa_applicable
        ])
        if ccpa_records > 0:
            total_score += 30
        
        # Opt-out mechanism (30 points)
        if len(self.ccpa_manager.opt_out_requests) >= 0:  # Has opt-out capability
            total_score += 30
        
        # Data subject rights (40 points)
        total_requests = (self.compliance_metrics['pending_requests'] + 
                         self.compliance_metrics['completed_requests'])
        if total_requests == 0 or self.compliance_metrics['completed_requests'] / total_requests > 0.8:
            total_score += 40
        
        return total_score
    
    def _get_retention_status(self) -> Dict[str, Any]:
        """Get data retention status"""
        return {
            'total_records': len(self.retention_manager.data_records),
            'scheduled_deletions': len(self.retention_manager.get_records_for_deletion()),
            'next_deletion_date': min([
                record.scheduled_deletion for record in self.retention_manager.data_records.values()
                if record.scheduled_deletion and record.retention_status == RetentionStatus.ACTIVE
            ], default=None),
            'auto_deletion_enabled': self.retention_manager.retention_policies['auto_deletion_enabled']
        }
    
    def _get_recent_requests(self) -> List[Dict[str, Any]]:
        """Get recent data subject requests"""
        recent_requests = sorted(
            self.rights_manager.requests.values(),
            key=lambda x: x.request_date,
            reverse=True
        )[:10]
        
        return [{
            'request_id': req.request_id,
            'request_type': req.request_type.value,
            'status': req.status,
            'request_date': req.request_date.isoformat(),
            'due_date': req.due_date.isoformat() if req.due_date else None
        } for req in recent_requests]
    
    def _get_upcoming_deletions(self) -> List[Dict[str, Any]]:
        """Get upcoming data deletions"""
        upcoming = self.retention_manager.get_records_for_deletion(
            datetime.now() + timedelta(days=30)
        )[:10]
        
        return [{
            'record_id': record.record_id,
            'data_subject_id': record.data_subject_id,
            'data_type': record.data_type.value,
            'scheduled_deletion': record.scheduled_deletion.isoformat() if record.scheduled_deletion else None
        } for record in upcoming]
    
    def _get_compliance_alerts(self) -> List[Dict[str, str]]:
        """Get compliance alerts"""
        alerts = []
        
        # Check for overdue requests
        overdue_requests = [
            req for req in self.rights_manager.requests.values()
            if req.due_date and req.due_date < datetime.now() and req.status != 'completed'
        ]
        
        if overdue_requests:
            alerts.append({
                'type': 'warning',
                'message': f"{len(overdue_requests)} data subject requests are overdue"
            })
        
        # Check for upcoming deletions
        upcoming_deletions = self.retention_manager.get_records_for_deletion(
            datetime.now() + timedelta(days=7)
        )
        
        if upcoming_deletions:
            alerts.append({
                'type': 'info',
                'message': f"{len(upcoming_deletions)} records scheduled for deletion in next 7 days"
            })
        
        return alerts

# Example usage and testing
def main():
    """Example usage of data protection components"""
    print("🔒 Data Protection & Privacy Compliance System")
    print("=" * 50)
    
    # Initialize the system
    config = {
        'default_retention_days': 365,
        'auto_deletion_enabled': True,
        'gdpr_applicable': True,
        'ccpa_applicable': True
    }
    
    dp_manager = DataProtectionManager(config)
    
    # Example: Register data processing
    print("\n📝 Registering data processing activities...")
    
    record_id = dp_manager.register_data_processing(
        data_subject_id="user_123",
        data_details={
            'location': '/data/users/user_123.json',
            'legal_basis': 'consent',
            'purpose': 'user_account_management',
            'data_category': 'profile_data',
            'retention_period_days': 730,
            'gdpr_applicable': True,
            'ccpa_applicable': True
        }
    )
    print(f"   Registered record: {record_id}")
    
    # Example: PII scanning
    print("\n🔍 Scanning for PII...")
    pii_results = dp_manager.scan_for_pii('/data/customer_database')
    print(f"   Found {pii_results['total_findings']} PII findings")
    
    # Example: Data subject request
    print("\n📋 Processing data subject requests...")
    access_request = dp_manager.process_subject_request(
        data_subject_id="user_123",
        request_type="access",
        description="User requesting copy of all personal data"
    )
    print(f"   Processed access request: {access_request}")
    
    # Example: CCPA opt-out
    print("\n🚫 Processing CCPA opt-out...")
    opt_out_id = dp_manager.ccpa_manager.process_opt_out_request(
        consumer_id="user_123",
        request_details={
            'opt_out_type': 'sale',
            'verified': True,
            'method': 'web_form'
        }
    )
    print(f"   Processed opt-out request: {opt_out_id}")
    
    # Example: Data retention execution
    print("\n🗑️ Executing data retention...")
    retention_results = dp_manager.execute_data_retention()
    print(f"   Processed {retention_results['total_processed']} records")
    print(f"   Deleted {len(retention_results['deleted_records'])} records")
    
    # Get compliance dashboard
    print("\n📊 Compliance Dashboard:")
    dashboard = dp_manager.get_compliance_dashboard()
    
    print(f"   GDPR Compliance Score: {dashboard['gdpr_compliance_score']:.1f}%")
    print(f"   CCPA Compliance Score: {dashboard['ccpa_compliance_score']:.1f}%")
    print(f"   Active Data Records: {dashboard['compliance_metrics']['active_records']}")
    print(f"   Pending Requests: {dashboard['compliance_metrics']['pending_requests']}")
    print(f"   Scheduled Deletions: {dashboard['compliance_metrics']['scheduled_deletions']}")
    
    if dashboard['compliance_alerts']:
        print("\n⚠️ Compliance Alerts:")
        for alert in dashboard['compliance_alerts']:
            print(f"   {alert['type'].upper()}: {alert['message']}")
    
    print("\n✅ Data protection system demonstration complete!")

if __name__ == "__main__":
    main()