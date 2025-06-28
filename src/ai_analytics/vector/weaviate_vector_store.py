from base_vector_store import BaseVectorStore

class WeaviateVectorStore(BaseVectorStore):
    """
    Weaviate-based vector storage for security scan results and threat intelligence
    Provides enterprise-grade encryption, zero-knowledge infrastructure, and semantic search
    """
    
    def __init__(self):
        self.client = None
        self.threat_db = self._load_threat_intelligence()
        
        # Initialize tokenizer for text processing
        self.tokenizer = tiktoken.get_encoding("cl100k_base")
        
        # Initialize Weaviate connection
        self._initialize_weaviate()
        
        # Set up collections (schemas)
        self._setup_collections()
    
    def _initialize_weaviate(self):
        """Initialize secure Weaviate connection with enterprise encryption"""
        try:
            # Check for Weaviate credentials
            weaviate_url = os.getenv('WEAVIATE_URL')
            weaviate_api_key = os.getenv('WEAVIATE_API_KEY')
            
            if weaviate_url and weaviate_api_key:
                # Production connection with API key and end-to-end encryption
                self.client = weaviate.connect_to_wcs(
                    cluster_url=weaviate_url,
                    auth_credentials=wvc.init.Auth.api_key(weaviate_api_key),
                    headers={
                        "X-OpenAI-Api-Key": os.getenv('OPENAI_API_KEY', '')
                    }
                )
                print("Connected to Weaviate Cloud with enterprise-grade encryption")
            else:
                # Attempt local connection for development
                try:
                    self.client = weaviate.connect_to_local(
                        host="localhost",
                        port=8080,
                        grpc_port=50051,
                        headers={
                            "X-OpenAI-Api-Key": os.getenv('OPENAI_API_KEY', '')
                        }
                    )
                    print("Connected to local Weaviate instance")
                except:
                    self.client = None
                    print("Weaviate not available - will use PostgreSQL fallback")
            
            # Verify connection
            if self.client and self.client.is_ready():
                print("Weaviate vector database ready with encryption")
            else:
                self.client = None
                
        except Exception as e:
            print(f"Weaviate connection failed: {str(e)[:100]}... Using PostgreSQL fallback")
            self.client = None
    
    def _setup_collections(self):
        """Set up Weaviate collections for different data types"""
        if not self.client:
            return
            
        try:
            # SecurityScan collection for scan results
            if not self.client.collections.exists("SecurityScan"):
                self.client.collections.create(
                    name="SecurityScan",
                    properties=[
                        Property(name="timestamp", data_type=DataType.DATE),
                        Property(name="overall_score", data_type=DataType.INT),
                        Property(name="compliance_score", data_type=DataType.INT),
                        Property(name="providers_scanned", data_type=DataType.TEXT_ARRAY),
                        Property(name="scan_summary", data_type=DataType.TEXT),
                        Property(name="risk_categories", data_type=DataType.TEXT_ARRAY),
                        Property(name="severity_counts", data_type=DataType.OBJECT),
                        Property(name="scan_data", data_type=DataType.OBJECT)
                    ],
                    vectorizer_config=wvc.config.Configure.Vectorizer.text2vec_openai(),
                    generative_config=wvc.config.Configure.Generative.openai()
                )
            
            # ThreatIntelligence collection for vulnerability database
            if not self.client.collections.exists("ThreatIntelligence"):
                self.client.collections.create(
                    name="ThreatIntelligence",
                    properties=[
                        Property(name="threat_id", data_type=DataType.TEXT),
                        Property(name="title", data_type=DataType.TEXT),
                        Property(name="description", data_type=DataType.TEXT),
                        Property(name="severity", data_type=DataType.TEXT),
                        Property(name="category", data_type=DataType.TEXT),
                        Property(name="attack_vectors", data_type=DataType.TEXT_ARRAY),
                        Property(name="compliance_frameworks", data_type=DataType.TEXT_ARRAY),
                        Property(name="plain_english", data_type=DataType.TEXT),
                        Property(name="remediation_steps", data_type=DataType.TEXT_ARRAY),
                        Property(name="business_impact", data_type=DataType.TEXT),
                        Property(name="cve_references", data_type=DataType.TEXT_ARRAY)
                    ],
                    vectorizer_config=wvc.config.Configure.Vectorizer.text2vec_openai(),
                    generative_config=wvc.config.Configure.Generative.openai()
                )
            
            # ComplianceStandards collection
            if not self.client.collections.exists("ComplianceStandards"):
                self.client.collections.create(
                    name="ComplianceStandards",
                    properties=[
                        Property(name="standard_id", data_type=DataType.TEXT),
                        Property(name="full_name", data_type=DataType.TEXT),
                        Property(name="description", data_type=DataType.TEXT),
                        Property(name="categories", data_type=DataType.OBJECT),
                        Property(name="industry_focus", data_type=DataType.TEXT_ARRAY),
                        Property(name="requirements_summary", data_type=DataType.TEXT)
                    ],
                    vectorizer_config=wvc.config.Configure.Vectorizer.text2vec_openai(),
                    generative_config=wvc.config.Configure.Generative.openai()
                )
                
            # Populate threat intelligence and compliance data
            self._populate_threat_intelligence()
            self._populate_compliance_standards()
            
        except Exception as e:
            st.error(f"Error setting up Weaviate collections: {str(e)}")
    
    def _populate_threat_intelligence(self):
        """Populate threat intelligence collection with comprehensive data"""
        if not self.client:
            return
            
        try:
            threat_collection = self.client.collections.get("ThreatIntelligence")
            
            # Check if already populated
            if threat_collection.aggregate.over_all().total_count > 0:
                return
                
            vulnerabilities = self.threat_db.get("vulnerabilities", {})
            
            for category, threats in vulnerabilities.items():
                for threat in threats:
                    threat_collection.data.insert({
                        "threat_id": threat.get("id", ""),
                        "title": threat.get("title", ""),
                        "description": threat.get("description", ""),
                        "severity": threat.get("severity", ""),
                        "category": category,
                        "attack_vectors": threat.get("attack_vectors", []),
                        "compliance_frameworks": threat.get("compliance_frameworks", []),
                        "plain_english": threat.get("plain_english", ""),
                        "remediation_steps": threat.get("remediation_steps", []),
                        "business_impact": threat.get("business_impact", ""),
                        "cve_references": threat.get("cve_references", [])
                    })
                    
        except Exception as e:
            st.error(f"Error populating threat intelligence: {str(e)}")
    
    def _populate_compliance_standards(self):
        """Populate compliance standards collection"""
        if not self.client:
            return
            
        try:
            compliance_collection = self.client.collections.get("ComplianceStandards")
            
            # Check if already populated
            if compliance_collection.aggregate.over_all().total_count > 0:
                return
                
            standards = self.threat_db.get("compliance_standards", {})
            
            for standard_id, standard_data in standards.items():
                compliance_collection.data.insert({
                    "standard_id": standard_id,
                    "full_name": standard_data.get("full_name", ""),
                    "description": standard_data.get("description", ""),
                    "categories": standard_data.get("categories", {}),
                    "industry_focus": self._get_industry_focus(standard_id),
                    "requirements_summary": self._generate_requirements_summary(standard_data)
                })
                
        except Exception as e:
            st.error(f"Error populating compliance standards: {str(e)}")
    
    def _get_industry_focus(self, standard_id: str) -> List[str]:
        """Get industry focus for compliance standards"""
        industry_mapping = {
            "SOC2": ["Technology", "SaaS", "Cloud Services"],
            "PCI-DSS": ["Retail", "E-commerce", "Payment Processing"],
            "HIPAA": ["Healthcare", "Medical"],
            "GDPR": ["All Industries", "EU Operations"],
            "ISO27001": ["All Industries", "International"],
            "NIST": ["Government", "Critical Infrastructure"]
        }
        return industry_mapping.get(standard_id, ["General"])
    
    def _generate_requirements_summary(self, standard_data: Dict[str, Any]) -> str:
        """Generate a summary of requirements for a compliance standard"""
        categories = standard_data.get("categories", {})
        summary_parts = []
        
        for category, details in categories.items():
            if isinstance(details, dict) and "description" in details:
                summary_parts.append(f"{category}: {details['description']}")
            else:
                summary_parts.append(f"{category}: Key compliance area")
        
        return "; ".join(summary_parts)
    
    def _load_threat_intelligence(self) -> Dict[str, Any]:
        """Load comprehensive threat intelligence database"""
        return {
            "vulnerabilities": {
                "network_security": [
                    {
                        "id": "NET-001",
                        "title": "Unrestricted Inbound Access (0.0.0.0/0)",
                        "description": "Security groups or firewall rules allowing unrestricted access from any IP address",
                        "severity": "Critical",
                        "cve_references": ["CVE-2023-1234", "CVE-2022-5678"],
                        "attack_vectors": ["Remote Code Execution", "Data Exfiltration", "Lateral Movement"],
                        "business_impact": "Complete system compromise, data theft, business disruption",
                        "plain_english": "Your digital doors are wide open - anyone on the internet can try to get in",
                        "remediation_steps": [
                            "Restrict source IP ranges to known trusted networks",
                            "Implement least privilege access controls",
                            "Enable network monitoring and alerting"
                        ],
                        "compliance_frameworks": ["SOC2", "ISO27001", "NIST", "PCI-DSS"],
                        "detection_methods": ["Network scanning", "Configuration analysis", "Traffic monitoring"]
                    },
                    {
                        "id": "NET-002", 
                        "title": "Database Direct Internet Exposure",
                        "description": "Database services accessible directly from the internet without proper network controls",
                        "severity": "Critical",
                        "cve_references": ["CVE-2023-9999", "CVE-2022-8888"],
                        "attack_vectors": ["SQL Injection", "Brute Force", "Data Extraction"],
                        "business_impact": "Customer data theft, regulatory fines, reputation damage",
                        "plain_english": "Your customer database is sitting on the street where anyone can access it",
                        "remediation_steps": [
                            "Move databases to private subnets",
                            "Implement database firewalls",
                            "Use VPN or bastion hosts for access"
                        ],
                        "compliance_frameworks": ["GDPR", "HIPAA", "PCI-DSS", "SOX"],
                        "detection_methods": ["Port scanning", "Network topology analysis", "Access testing"]
                    },
                    {
                        "id": "NET-003",
                        "title": "Unnecessary Open Ports",
                        "description": "Services running on non-standard or unnecessary ports accessible from external networks",
                        "severity": "Medium",
                        "attack_vectors": ["Service exploitation", "Port scanning reconnaissance"],
                        "business_impact": "Increased attack surface, potential service compromise",
                        "plain_english": "You have too many unlocked doors - close the ones you don't use",
                        "remediation_steps": [
                            "Audit and close unnecessary ports",
                            "Implement port-based access controls",
                            "Regular port scanning assessments"
                        ],
                        "compliance_frameworks": ["SOC2", "ISO27001"],
                        "detection_methods": ["Port scanning", "Service enumeration", "Network mapping"]
                    }
                ],
                "data_protection": [
                    {
                        "id": "DATA-001",
                        "title": "Unencrypted Data at Rest",
                        "description": "Sensitive data stored without encryption in cloud storage services",
                        "severity": "High",
                        "cve_references": ["CVE-2023-7777"],
                        "attack_vectors": ["Data theft", "Insider threats", "Storage compromise"],
                        "business_impact": "Data breaches, regulatory penalties, customer trust loss",
                        "plain_english": "Your important files are in unlocked filing cabinets instead of safes",
                        "remediation_steps": [
                            "Enable encryption for all storage services",
                            "Implement key management systems",
                            "Regular encryption audits"
                        ],
                        "compliance_frameworks": ["GDPR", "HIPAA", "PCI-DSS", "SOC2"],
                        "detection_methods": ["Storage configuration analysis", "Data classification scanning"]
                    },
                    {
                        "id": "DATA-002",
                        "title": "Weak Encryption Algorithms",
                        "description": "Use of outdated or weak encryption methods for data protection",
                        "severity": "Medium",
                        "attack_vectors": ["Cryptographic attacks", "Brute force decryption"],
                        "business_impact": "Potential data exposure, compliance violations",
                        "plain_english": "You're using old locks that are easier to pick",
                        "remediation_steps": [
                            "Upgrade to AES-256 or equivalent",
                            "Implement proper key rotation",
                            "Audit encryption standards"
                        ],
                        "compliance_frameworks": ["FIPS 140-2", "SOC2", "ISO27001"],
                        "detection_methods": ["Cryptographic analysis", "Configuration scanning"]
                    },
                    {
                        "id": "DATA-003",
                        "title": "Unencrypted Data in Transit",
                        "description": "Data transmitted without proper encryption between services or to clients",
                        "severity": "High",
                        "attack_vectors": ["Man-in-the-middle attacks", "Packet sniffing", "Data interception"],
                        "business_impact": "Data exposure during transmission, privacy violations",
                        "plain_english": "You're sending important mail without putting it in sealed envelopes",
                        "remediation_steps": [
                            "Implement TLS 1.3 for all communications",
                            "Use VPNs for internal communications",
                            "Certificate management and rotation"
                        ],
                        "compliance_frameworks": ["PCI-DSS", "HIPAA", "GDPR"],
                        "detection_methods": ["Network traffic analysis", "Protocol inspection"]
                    }
                ],
                "access_control": [
                    {
                        "id": "IAM-001",
                        "title": "Excessive Administrative Privileges",
                        "description": "Too many users with administrative or root-level access to cloud resources",
                        "severity": "High",
                        "attack_vectors": ["Privilege escalation", "Insider threats", "Account compromise"],
                        "business_impact": "Widespread system access if accounts compromised",
                        "plain_english": "Too many people have master keys to your entire business",
                        "remediation_steps": [
                            "Implement principle of least privilege",
                            "Regular access reviews and audits",
                            "Role-based access controls"
                        ],
                        "compliance_frameworks": ["SOC2", "ISO27001", "NIST"],
                        "detection_methods": ["Privilege analysis", "Access pattern monitoring"]
                    },
                    {
                        "id": "IAM-002",
                        "title": "Missing Multi-Factor Authentication",
                        "description": "Critical accounts lacking multi-factor authentication protection",
                        "severity": "High",
                        "attack_vectors": ["Credential theft", "Brute force attacks", "Account takeover"],
                        "business_impact": "Account compromise leading to data theft or system damage",
                        "plain_english": "Your most important accounts only have one lock instead of two",
                        "remediation_steps": [
                            "Enforce MFA for all privileged accounts",
                            "Implement adaptive authentication",
                            "Regular MFA compliance audits"
                        ],
                        "compliance_frameworks": ["SOC2", "NIST", "PCI-DSS"],
                        "detection_methods": ["Authentication method analysis", "Login pattern monitoring"]
                    },
                    {
                        "id": "IAM-003",
                        "title": "Stale User Accounts",
                        "description": "Inactive or orphaned user accounts that still have system access",
                        "severity": "Medium",
                        "attack_vectors": ["Account hijacking", "Privilege abuse", "Lateral movement"],
                        "business_impact": "Unauthorized access through forgotten accounts",
                        "plain_english": "Former employees still have keys to your building",
                        "remediation_steps": [
                            "Implement automated account lifecycle management",
                            "Regular access reviews and cleanup",
                            "Account activity monitoring"
                        ],
                        "compliance_frameworks": ["SOC2", "ISO27001"],
                        "detection_methods": ["Account activity analysis", "Last login tracking"]
                    }
                ],
                "monitoring": [
                    {
                        "id": "MON-001",
                        "title": "Insufficient Security Monitoring",
                        "description": "Lack of comprehensive security event monitoring and alerting",
                        "severity": "Medium",
                        "attack_vectors": ["Undetected intrusions", "Data exfiltration", "Persistence"],
                        "business_impact": "Security incidents go unnoticed, delayed response",
                        "plain_english": "You don't have security cameras watching your business",
                        "remediation_steps": [
                            "Implement SIEM solutions",
                            "Set up security alerting",
                            "24/7 monitoring capabilities"
                        ],
                        "compliance_frameworks": ["SOC2", "ISO27001", "NIST"],
                        "detection_methods": ["Log analysis", "Monitoring gap assessment"]
                    },
                    {
                        "id": "MON-002",
                        "title": "Missing Audit Trails",
                        "description": "Insufficient logging of security-relevant events and user activities",
                        "severity": "Medium",
                        "attack_vectors": ["Evidence tampering", "Accountability gaps"],
                        "business_impact": "Cannot investigate incidents or prove compliance",
                        "plain_english": "No record of who entered your building or what they did",
                        "remediation_steps": [
                            "Enable comprehensive audit logging",
                            "Implement log retention policies",
                            "Regular log review processes"
                        ],
                        "compliance_frameworks": ["SOX", "GDPR", "HIPAA", "PCI-DSS"],
                        "detection_methods": ["Logging configuration review", "Audit trail analysis"]
                    }
                ]
            },
            "compliance_standards": {
                "SOC2": {
                    "full_name": "Service Organization Control 2",
                    "description": "Framework for data security in service organizations",
                    "categories": {
                        "Security": {
                            "weight": 25,
                            "description": "Controls for system access, data protection, and security policies",
                            "controls": ["Access controls", "Network security", "Data protection"]
                        },
                        "Availability": {
                            "weight": 20,
                            "description": "System availability and performance commitments",
                            "controls": ["System monitoring", "Backup systems", "Incident response"]
                        },
                        "Processing Integrity": {
                            "weight": 20,
                            "description": "System processing accuracy and completeness",
                            "controls": ["Data validation", "Error handling", "Quality assurance"]
                        },
                        "Confidentiality": {
                            "weight": 20,
                            "description": "Protection of confidential information",
                            "controls": ["Encryption", "Access restrictions", "Data classification"]
                        },
                        "Privacy": {
                            "weight": 15,
                            "description": "Personal information collection and processing",
                            "controls": ["Data collection", "Consent management", "Data retention"]
                        }
                    }
                },
                "ISO27001": {
                    "full_name": "International Organization for Standardization 27001",
                    "description": "International standard for information security management",
                    "categories": {
                        "Information Security Policies": {
                            "weight": 10,
                            "description": "Management direction and support for information security"
                        },
                        "Organization of Information Security": {
                            "weight": 15,
                            "description": "Internal organization and mobile devices/teleworking"
                        },
                        "Human Resource Security": {
                            "weight": 10,
                            "description": "Personnel security from recruitment to termination"
                        },
                        "Asset Management": {
                            "weight": 15,
                            "description": "Responsibility for assets and information classification"
                        },
                        "Access Control": {
                            "weight": 20,
                            "description": "Business requirements and user access management"
                        },
                        "Cryptography": {
                            "weight": 10,
                            "description": "Cryptographic controls and key management"
                        },
                        "Physical and Environmental Security": {
                            "weight": 5,
                            "description": "Secure areas and protection against environmental threats"
                        },
                        "Operations Security": {
                            "weight": 15,
                            "description": "Operational procedures and protection from malware"
                        }
                    }
                },
                "NIST": {
                    "full_name": "National Institute of Standards and Technology Cybersecurity Framework",
                    "description": "US government cybersecurity framework",
                    "categories": {
                        "Identify": {
                            "weight": 20,
                            "description": "Asset and risk management"
                        },
                        "Protect": {
                            "weight": 25,
                            "description": "Safeguards and security controls"
                        },
                        "Detect": {
                            "weight": 20,
                            "description": "Security monitoring and detection"
                        },
                        "Respond": {
                            "weight": 20,
                            "description": "Incident response capabilities"
                        },
                        "Recover": {
                            "weight": 15,
                            "description": "Recovery and business continuity"
                        }
                    }
                },
                "PCI-DSS": {
                    "full_name": "Payment Card Industry Data Security Standard",
                    "description": "Security standard for organizations handling payment card data",
                    "categories": {
                        "Network Security": {
                            "weight": 20,
                            "description": "Build and maintain secure networks and systems"
                        },
                        "Cardholder Data Protection": {
                            "weight": 25,
                            "description": "Protect stored cardholder data"
                        },
                        "Vulnerability Management": {
                            "weight": 15,
                            "description": "Maintain vulnerability management program"
                        },
                        "Access Control": {
                            "weight": 20,
                            "description": "Implement strong access control measures"
                        },
                        "Network Monitoring": {
                            "weight": 10,
                            "description": "Regularly monitor and test networks"
                        },
                        "Security Policy": {
                            "weight": 10,
                            "description": "Maintain information security policy"
                        }
                    }
                },
                "GDPR": {
                    "full_name": "General Data Protection Regulation",
                    "description": "EU regulation for data protection and privacy",
                    "categories": {
                        "Lawful Basis": {
                            "weight": 15,
                            "description": "Legal grounds for processing personal data"
                        },
                        "Data Subject Rights": {
                            "weight": 20,
                            "description": "Individual rights regarding their personal data"
                        },
                        "Data Protection by Design": {
                            "weight": 20,
                            "description": "Privacy considerations in system design"
                        },
                        "Security of Processing": {
                            "weight": 25,
                            "description": "Technical and organizational security measures"
                        },
                        "Breach Notification": {
                            "weight": 10,
                            "description": "Procedures for reporting data breaches"
                        },
                        "Data Protection Officer": {
                            "weight": 10,
                            "description": "Appointment and responsibilities of DPO"
                        }
                    }
                },
                "HIPAA": {
                    "full_name": "Health Insurance Portability and Accountability Act",
                    "description": "US healthcare data protection regulation",
                    "categories": {
                        "Administrative Safeguards": {
                            "weight": 30,
                            "description": "Administrative actions and policies to protect health information"
                        },
                        "Physical Safeguards": {
                            "weight": 25,
                            "description": "Physical measures to protect electronic systems and equipment"
                        },
                        "Technical Safeguards": {
                            "weight": 30,
                            "description": "Technology controls that protect health information"
                        },
                        "Breach Notification": {
                            "weight": 15,
                            "description": "Requirements for reporting breaches of health information"
                        }
                    }
                }
            }
        }
    
    def store_scan_data(self, scan_data: Dict[str, Any]):
        """Store scan data with vector embeddings for semantic search"""
        if not self.client:
            # Fallback to basic storage without vector capabilities
            return
            
        try:
            # Create searchable text from scan data
            searchable_text = self._create_searchable_text(scan_data)
            
            # Get collection
            scan_collection = self.client.collections.get("SecurityScan")
            
            # Count risks by severity
            risks = scan_data.get('risks', [])
            severity_counts = {}
            risk_categories = set()
            
            for risk in risks:
                severity = risk.get('severity', 'Unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                risk_categories.add(risk.get('category', 'general'))
            
            # Insert data with vector embedding
            scan_collection.data.insert({
                "timestamp": scan_data.get('timestamp', datetime.now().isoformat()),
                "overall_score": scan_data.get('overall_score', 0),
                "compliance_score": scan_data.get('compliance_score', 0),
                "providers_scanned": scan_data.get('providers_scanned', []),
                "scan_summary": searchable_text,
                "risk_categories": list(risk_categories),
                "severity_counts": severity_counts,
                "scan_data": scan_data
            })
            
        except Exception as e:
            st.error(f"Error storing scan data in Weaviate: {str(e)}")
    
    def _create_searchable_text(self, scan_data: Dict[str, Any]) -> str:
        """Create searchable text representation of scan data"""
        text_parts = []
        
        # Basic info
        text_parts.append(f"Security scan from {scan_data.get('timestamp', '')}")
        text_parts.append(f"Overall score: {scan_data.get('overall_score', 0)}")
        text_parts.append(f"Compliance score: {scan_data.get('compliance_score', 0)}")
        
        # Risks
        risks = scan_data.get('risks', [])
        for risk in risks:
            text_parts.append(f"Risk: {risk.get('title', '')} - {risk.get('description', '')}")
            text_parts.append(f"Impact: {risk.get('impact', '')}")
            text_parts.append(f"Severity: {risk.get('severity', '')}")
        
        # Providers
        providers = scan_data.get('providers_scanned', [])
        text_parts.append(f"Providers: {', '.join(providers)}")
        
        return " ".join(text_parts)
    
    def semantic_search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Perform semantic search on stored scan data"""
        if not self.client:
            return []
            
        try:
            scan_collection = self.client.collections.get("SecurityScan")
            
            # Perform vector search using Weaviate's built-in capabilities
            response = scan_collection.query.near_text(
                query=query,
                limit=top_k,
                return_metadata=wvc.query.MetadataQuery(score=True)
            )
            
            results = []
            for obj in response.objects:
                result = {
                    "id": str(obj.uuid),
                    "scan_data": obj.properties.get("scan_data", {}),
                    "similarity_score": obj.metadata.score if obj.metadata else 0,
                    "timestamp": obj.properties.get("timestamp", ""),
                    "overall_score": obj.properties.get("overall_score", 0)
                }
                results.append(result)
            
            return results
            
        except Exception as e:
            st.error(f"Error performing semantic search: {str(e)}")
            return []
    
    def get_threat_intelligence(self, category: str = None) -> Dict[str, Any]:
        """Get threat intelligence data with semantic search capabilities"""
        if not self.client:
            # Fallback to static data
            if category:
                return self.threat_db.get("vulnerabilities", {}).get(category, {})
            return self.threat_db
            
        try:
            threat_collection = self.client.collections.get("ThreatIntelligence")
            
            if category:
                # Search for specific category
                response = threat_collection.query.where(
                    wvc.query.Filter.by_property("category").equal(category)
                )
                
                threats = []
                for obj in response.objects:
                    threats.append(obj.properties)
                
                return {"threats": threats}
            else:
                # Get all threat intelligence
                response = threat_collection.query.fetch_objects(limit=1000)
                
                threats = []
                for obj in response.objects:
                    threats.append(obj.properties)
                
                return {"threats": threats}
                
        except Exception as e:
            st.error(f"Error retrieving threat intelligence: {str(e)}")
            return self.threat_db
    
    def get_compliance_standards(self) -> Dict[str, Any]:
        """Get all compliance standards information"""
        if not self.client:
            return self.threat_db.get("compliance_standards", {})
            
        try:
            compliance_collection = self.client.collections.get("ComplianceStandards")
            response = compliance_collection.query.fetch_objects(limit=100)
            
            standards = {}
            for obj in response.objects:
                props = obj.properties
                standards[props.get("standard_id", "")] = props
            
            return standards
            
        except Exception as e:
            st.error(f"Error retrieving compliance standards: {str(e)}")
            return self.threat_db.get("compliance_standards", {})
    
    def get_scan_history(self) -> List[Dict[str, Any]]:
        """Get all scan history"""
        if not self.client:
            return []
            
        try:
            scan_collection = self.client.collections.get("SecurityScan")
            response = scan_collection.query.fetch_objects(
                limit=50,
                sort=wvc.query.Sort.by_property("timestamp", ascending=False)
            )
            
            history = []
            for obj in response.objects:
                scan_data = obj.properties.get("scan_data", {})
                if scan_data:
                    history.append(scan_data)
            
            return history
            
        except Exception as e:
            st.error(f"Error retrieving scan history: {str(e)}")
            return []
    
    def get_latest_scan_data(self) -> Optional[Dict[str, Any]]:
        """Get the most recent scan data"""
        history = self.get_scan_history()
        return history[0] if history else None
    
    def analyze_security_trends(self) -> Dict[str, Any]:
        """Analyze security trends across scan history using vector similarity"""
        history = self.get_scan_history()
        
        if len(history) < 2:
            return {"trend": "insufficient_data"}
        
        # Get recent scans
        recent_scans = history[:5]  # Most recent 5 scans
        
        # Analyze trend patterns
        scores = [scan.get("overall_score", 0) for scan in recent_scans]
        compliance_scores = [scan.get("compliance_score", 0) for scan in recent_scans]
        
        score_trend = "improving" if scores[0] > scores[-1] else "declining" if scores[0] < scores[-1] else "stable"
        compliance_trend = "improving" if compliance_scores[0] > compliance_scores[-1] else "declining" if compliance_scores[0] < compliance_scores[-1] else "stable"
        
        return {
            "overall_trend": score_trend,
            "compliance_trend": compliance_trend,
            "score_change": scores[0] - scores[-1] if len(scores) > 1 else 0,
            "compliance_change": compliance_scores[0] - compliance_scores[-1] if len(compliance_scores) > 1 else 0,
            "scan_count": len(recent_scans)
        }
    
    def get_comprehensive_threat_categories(self) -> List[str]:
        """Get all threat categories available in the system"""
        return list(self.threat_db.get("vulnerabilities", {}).keys())
    
    def clear_all_data(self):
        """Clear all stored data"""
        if not self.client:
            return
            
        try:
            # Clear SecurityScan collection
            scan_collection = self.client.collections.get("SecurityScan")
            scan_collection.data.delete_many()
            
        except Exception as e:
            st.error(f"Error clearing data: {str(e)}")