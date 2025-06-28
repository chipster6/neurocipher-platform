-- AuditHound Unified Database Schema
-- PostgreSQL initialization for unified repository

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create tenants table
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    config JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Indexing
    CONSTRAINT tenants_name_unique UNIQUE(name)
);

-- Create users table for authentication
CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    
    -- Constraints
    CONSTRAINT users_role_check CHECK (role IN ('admin', 'user', 'viewer', 'tenant_admin'))
);

-- Create security_scans table
CREATE TABLE IF NOT EXISTS security_scans (
    scan_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    scan_type VARCHAR(100) NOT NULL DEFAULT 'comprehensive',
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Configuration and targets
    scan_config JSONB DEFAULT '{}',
    targets JSONB DEFAULT '[]',
    
    -- Results
    results JSONB DEFAULT '{}',
    overall_score INTEGER DEFAULT 0,
    
    -- Metadata
    created_by UUID REFERENCES users(user_id),
    
    -- Constraints
    CONSTRAINT security_scans_status_check CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    CONSTRAINT security_scans_score_check CHECK (overall_score >= 0 AND overall_score <= 100)
);

-- Create findings table
CREATE TABLE IF NOT EXISTS findings (
    finding_id VARCHAR(255) PRIMARY KEY,
    scan_id VARCHAR(255) REFERENCES security_scans(scan_id) ON DELETE CASCADE,
    
    -- Finding details
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) DEFAULT 'Medium',
    category VARCHAR(100) DEFAULT 'general',
    status VARCHAR(20) DEFAULT 'open',
    
    -- Provider and location info
    provider VARCHAR(50),
    resource_id VARCHAR(255),
    region VARCHAR(100),
    
    -- Timing
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE,
    
    -- Additional metadata
    remediation TEXT,
    impact TEXT,
    cvss_score DECIMAL(3,1) DEFAULT 0.0,
    cve_id VARCHAR(50),
    
    -- Risk assessment
    risk_level VARCHAR(20) DEFAULT 'Medium',
    compliance_frameworks JSONB DEFAULT '[]',
    
    -- Assignment and workflow
    assigned_to UUID REFERENCES users(user_id),
    resolution_notes TEXT,
    
    -- Constraints
    CONSTRAINT findings_severity_check CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Info')),
    CONSTRAINT findings_status_check CHECK (status IN ('open', 'in_progress', 'resolved', 'false_positive', 'accepted_risk')),
    CONSTRAINT findings_risk_level_check CHECK (risk_level IN ('Critical', 'High', 'Medium', 'Low')),
    CONSTRAINT findings_cvss_check CHECK (cvss_score >= 0.0 AND cvss_score <= 10.0)
);

-- Create compliance_frameworks table
CREATE TABLE IF NOT EXISTS compliance_frameworks (
    framework_id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    version VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create compliance_controls table
CREATE TABLE IF NOT EXISTS compliance_controls (
    control_id VARCHAR(255) PRIMARY KEY,
    framework_id VARCHAR(100) REFERENCES compliance_frameworks(framework_id),
    control_number VARCHAR(50),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    control_type VARCHAR(100),
    severity VARCHAR(20) DEFAULT 'Medium',
    is_required BOOLEAN DEFAULT TRUE
);

-- Create compliance_assessments table
CREATE TABLE IF NOT EXISTS compliance_assessments (
    assessment_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    framework_id VARCHAR(100) REFERENCES compliance_frameworks(framework_id),
    scan_id VARCHAR(255) REFERENCES security_scans(scan_id),
    
    status VARCHAR(50) DEFAULT 'in_progress',
    overall_compliance_score INTEGER DEFAULT 0,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    
    results JSONB DEFAULT '{}',
    
    CONSTRAINT compliance_assessments_score_check CHECK (overall_compliance_score >= 0 AND overall_compliance_score <= 100)
);

-- Create audit_reports table
CREATE TABLE IF NOT EXISTS audit_reports (
    report_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    scan_id VARCHAR(255) REFERENCES security_scans(scan_id),
    
    report_type VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'generating',
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Report configuration
    config JSONB DEFAULT '{}',
    
    -- Generated content
    content JSONB DEFAULT '{}',
    file_path VARCHAR(500),
    file_format VARCHAR(20) DEFAULT 'pdf',
    
    -- Metadata
    generated_by UUID REFERENCES users(user_id),
    
    CONSTRAINT audit_reports_status_check CHECK (status IN ('generating', 'completed', 'failed'))
);

-- Create threat_intelligence table
CREATE TABLE IF NOT EXISTS threat_intelligence (
    threat_id VARCHAR(255) PRIMARY KEY,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) DEFAULT 'Medium',
    category VARCHAR(100),
    
    -- Threat details
    attack_vectors JSONB DEFAULT '[]',
    indicators_of_compromise JSONB DEFAULT '[]',
    mitigation_strategies JSONB DEFAULT '[]',
    
    -- Timing and source
    discovered_at TIMESTAMP WITH TIME ZONE,
    published_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    source VARCHAR(255),
    
    -- Classification
    threat_type VARCHAR(100),
    confidence_level VARCHAR(20) DEFAULT 'Medium',
    
    -- Compliance mapping
    compliance_frameworks JSONB DEFAULT '[]',
    
    CONSTRAINT threat_intelligence_severity_check CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Info')),
    CONSTRAINT threat_intelligence_confidence_check CHECK (confidence_level IN ('High', 'Medium', 'Low'))
);

-- Create sessions table for authentication
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE
);

-- Create api_keys table for API authentication
CREATE TABLE IF NOT EXISTS api_keys (
    key_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    
    key_name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    
    permissions JSONB DEFAULT '[]',
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used TIMESTAMP WITH TIME ZONE,
    
    is_active BOOLEAN DEFAULT TRUE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_security_scans_tenant_id ON security_scans(tenant_id);
CREATE INDEX IF NOT EXISTS idx_security_scans_status ON security_scans(status);
CREATE INDEX IF NOT EXISTS idx_security_scans_created_at ON security_scans(created_at);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at);
CREATE INDEX IF NOT EXISTS idx_findings_provider ON findings(provider);

CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_id ON api_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);

-- JSON indexes for better performance on JSONB columns
CREATE INDEX IF NOT EXISTS idx_security_scans_results_gin ON security_scans USING GIN(results);
CREATE INDEX IF NOT EXISTS idx_findings_compliance_gin ON findings USING GIN(compliance_frameworks);
CREATE INDEX IF NOT EXISTS idx_threat_intel_attack_vectors_gin ON threat_intelligence USING GIN(attack_vectors);

-- Insert default compliance frameworks
INSERT INTO compliance_frameworks (framework_id, name, description, version) VALUES
('iso27001', 'ISO 27001', 'Information Security Management Systems', '2013'),
('soc2', 'SOC 2', 'Service Organization Control 2', 'Type II'),
('gdpr', 'GDPR', 'General Data Protection Regulation', '2018'),
('hipaa', 'HIPAA', 'Health Insurance Portability and Accountability Act', '1996'),
('pci_dss', 'PCI DSS', 'Payment Card Industry Data Security Standard', '4.0'),
('nist_csf', 'NIST CSF', 'NIST Cybersecurity Framework', '1.1')
ON CONFLICT (framework_id) DO NOTHING;

-- Insert sample controls for ISO 27001
INSERT INTO compliance_controls (control_id, framework_id, control_number, title, description, control_type, severity) VALUES
('iso27001_a5_1_1', 'iso27001', 'A.5.1.1', 'Information Security Policy', 'An information security policy shall be defined, approved by management, published and communicated to employees and relevant external parties.', 'policy', 'High'),
('iso27001_a8_1_1', 'iso27001', 'A.8.1.1', 'Inventory of Assets', 'Assets associated with information and information processing facilities shall be identified and an inventory of these assets shall be drawn up and maintained.', 'technical', 'Medium'),
('iso27001_a9_1_1', 'iso27001', 'A.9.1.1', 'Access Control Policy', 'An access control policy shall be established, documented and reviewed based on business and information security requirements.', 'technical', 'High')
ON CONFLICT (control_id) DO NOTHING;

-- Create function to automatically update updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for automatic timestamp updates
CREATE TRIGGER update_tenants_updated_at BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create a default admin user (password: admin123 - CHANGE IN PRODUCTION!)
-- Password hash for 'admin123' using bcrypt
INSERT INTO tenants (tenant_id, name) VALUES ('default', 'Default Tenant') ON CONFLICT DO NOTHING;

INSERT INTO users (tenant_id, username, email, password_hash, role) VALUES 
('default', 'admin', 'admin@audithound.local', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/IEyGeHXXiEXL2g8Ce', 'admin')
ON CONFLICT (username) DO NOTHING;

-- Grant necessary permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO audithound;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO audithound;

-- Create views for common queries
CREATE OR REPLACE VIEW tenant_scan_summary AS
SELECT 
    t.tenant_id,
    t.name as tenant_name,
    COUNT(s.scan_id) as total_scans,
    COUNT(CASE WHEN s.status = 'completed' THEN 1 END) as completed_scans,
    AVG(s.overall_score) as avg_score,
    MAX(s.created_at) as last_scan_date
FROM tenants t
LEFT JOIN security_scans s ON t.tenant_id = s.tenant_id
WHERE t.is_active = true
GROUP BY t.tenant_id, t.name;

CREATE OR REPLACE VIEW finding_severity_summary AS
SELECT 
    s.tenant_id,
    f.severity,
    COUNT(*) as finding_count,
    COUNT(CASE WHEN f.status = 'open' THEN 1 END) as open_findings,
    COUNT(CASE WHEN f.status = 'resolved' THEN 1 END) as resolved_findings
FROM findings f
JOIN security_scans s ON f.scan_id = s.scan_id
GROUP BY s.tenant_id, f.severity;

-- Performance optimization: analyze tables
ANALYZE;