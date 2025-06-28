#!/usr/bin/env python3
"""
AuditHound Web-Based Installer
Provides a web interface for easy setup and configuration
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import os
import sys
import subprocess
import json
import yaml
import logging
from datetime import datetime
from typing import Dict, Any

app = Flask(__name__)
app.secret_key = 'audithound-installer-secret-key'

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AuditHoundInstaller:
    """Web-based installer for AuditHound"""
    
    def __init__(self):
        self.install_dir = os.path.expanduser('~/audithound')
        self.setup_data = {}
        
    def check_prerequisites(self) -> Dict[str, Any]:
        """Check system prerequisites"""
        checks = {
            'python': self._check_python(),
            'git': self._check_git(),
            'curl': self._check_curl(),
            'docker': self._check_docker(),
            'disk_space': self._check_disk_space(),
            'permissions': self._check_permissions()
        }
        
        checks['overall_status'] = all(check['status'] for check in checks.values() if check.get('required', True))
        return checks
    
    def _check_python(self) -> Dict[str, Any]:
        """Check Python version"""
        try:
            import sys
            version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            if sys.version_info >= (3, 8):
                return {'status': True, 'version': version, 'message': f'Python {version} (✓)', 'required': True}
            else:
                return {'status': False, 'version': version, 'message': f'Python {version} - Need 3.8+', 'required': True}
        except Exception as e:
            return {'status': False, 'message': f'Python check failed: {e}', 'required': True}
    
    def _check_git(self) -> Dict[str, Any]:
        """Check Git availability"""
        try:
            result = subprocess.run(['git', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                return {'status': True, 'message': f'Git available (✓)', 'required': True}
            else:
                return {'status': False, 'message': 'Git not found', 'required': True}
        except Exception:
            return {'status': False, 'message': 'Git not found', 'required': True}
    
    def _check_curl(self) -> Dict[str, Any]:
        """Check curl availability"""
        try:
            result = subprocess.run(['curl', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                return {'status': True, 'message': 'curl available (✓)', 'required': True}
            else:
                return {'status': False, 'message': 'curl not found', 'required': True}
        except Exception:
            return {'status': False, 'message': 'curl not found', 'required': True}
    
    def _check_docker(self) -> Dict[str, Any]:
        """Check Docker availability"""
        try:
            result = subprocess.run(['docker', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                return {'status': True, 'message': 'Docker available (✓)', 'required': False}
            else:
                return {'status': False, 'message': 'Docker not found (optional)', 'required': False}
        except Exception:
            return {'status': False, 'message': 'Docker not found (optional)', 'required': False}
    
    def _check_disk_space(self) -> Dict[str, Any]:
        """Check available disk space"""
        try:
            statvfs = os.statvfs(os.path.expanduser('~'))
            free_space_gb = (statvfs.f_frsize * statvfs.f_avail) / (1024**3)
            
            if free_space_gb >= 2:
                return {'status': True, 'message': f'{free_space_gb:.1f} GB available (✓)', 'required': True}
            else:
                return {'status': False, 'message': f'{free_space_gb:.1f} GB available - Need 2GB+', 'required': True}
        except Exception as e:
            return {'status': False, 'message': f'Disk space check failed: {e}', 'required': True}
    
    def _check_permissions(self) -> Dict[str, Any]:
        """Check write permissions"""
        try:
            test_dir = os.path.expanduser('~/audithound-test')
            os.makedirs(test_dir, exist_ok=True)
            
            test_file = os.path.join(test_dir, 'test.txt')
            with open(test_file, 'w') as f:
                f.write('test')
            
            os.remove(test_file)
            os.rmdir(test_dir)
            
            return {'status': True, 'message': 'Write permissions OK (✓)', 'required': True}
        except Exception as e:
            return {'status': False, 'message': f'Permission check failed: {e}', 'required': True}
    
    def generate_config(self, form_data: Dict[str, Any]) -> str:
        """Generate configuration from form data"""
        config = {
            'organization': {
                'name': form_data.get('org_name'),
                'admin_email': form_data.get('admin_email'),
                'service_tier': form_data.get('service_tier', 'starter')
            },
            'cloud_providers': {
                'aws': {
                    'enabled': form_data.get('enable_aws') == 'on',
                    'region': form_data.get('aws_region', 'us-west-2'),
                    'access_key_id': '${AWS_ACCESS_KEY_ID}',
                    'secret_access_key': '${AWS_SECRET_ACCESS_KEY}'
                },
                'gcp': {
                    'enabled': form_data.get('enable_gcp') == 'on',
                    'project_id': '${GCP_PROJECT_ID}',
                    'credentials_path': './credentials/gcp-service-account.json'
                },
                'azure': {
                    'enabled': form_data.get('enable_azure') == 'on',
                    'tenant_id': '${AZURE_TENANT_ID}',
                    'subscription_id': '${AZURE_SUBSCRIPTION_ID}',
                    'client_id': '${AZURE_CLIENT_ID}',
                    'client_secret': '${AZURE_CLIENT_SECRET}'
                }
            },
            'compliance_frameworks': {
                'soc2': {
                    'enabled': True,
                    'controls': ['CC6.1', 'CC6.2', 'CC6.3', 'CC7.1', 'CC8.1']
                }
            },
            'dashboard': {
                'host': '0.0.0.0',
                'port': int(form_data.get('dashboard_port', 5001)),
                'debug': False
            },
            'integrations': {
                'misp': {
                    'enabled': bool(form_data.get('misp_url')),
                    'url': form_data.get('misp_url', ''),
                    'api_key': '${MISP_API_KEY}',
                    'verify_ssl': True
                },
                'thehive': {
                    'enabled': bool(form_data.get('thehive_url')),
                    'url': form_data.get('thehive_url', ''),
                    'api_key': '${THEHIVE_API_KEY}'
                }
            },
            'notifications': {
                'slack': {
                    'enabled': bool(form_data.get('slack_webhook')),
                    'webhook_url': form_data.get('slack_webhook', ''),
                    'channel': form_data.get('slack_channel', '#security')
                }
            }
        }
        
        return yaml.dump(config, default_flow_style=False, sort_keys=False)
    
    def install_audithound(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform the actual installation"""
        try:
            # Create installation directory
            os.makedirs(self.install_dir, exist_ok=True)
            
            # Copy current directory (in production, would clone from repo)
            import shutil
            current_dir = os.path.dirname(os.path.abspath(__file__))
            
            for item in os.listdir(current_dir):
                if item not in ['.git', '__pycache__', 'venv', '.env']:
                    src = os.path.join(current_dir, item)
                    dst = os.path.join(self.install_dir, item)
                    
                    if os.path.isdir(src):
                        if os.path.exists(dst):
                            shutil.rmtree(dst)
                        shutil.copytree(src, dst)
                    else:
                        shutil.copy2(src, dst)
            
            # Generate configuration
            config_yaml = self.generate_config(config_data)
            with open(os.path.join(self.install_dir, 'config.yaml'), 'w') as f:
                f.write(config_yaml)
            
            # Create virtual environment
            venv_path = os.path.join(self.install_dir, 'venv')
            result = subprocess.run([sys.executable, '-m', 'venv', venv_path], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"Failed to create virtual environment: {result.stderr}")
            
            # Install dependencies
            pip_path = os.path.join(venv_path, 'bin', 'pip') if os.name != 'nt' else os.path.join(venv_path, 'Scripts', 'pip.exe')
            
            # Upgrade pip
            subprocess.run([pip_path, 'install', '--upgrade', 'pip'], check=True)
            
            # Install requirements
            requirements_file = os.path.join(self.install_dir, 'requirements.txt')
            if os.path.exists(requirements_file):
                subprocess.run([pip_path, 'install', '-r', requirements_file], check=True)
            
            # Create startup scripts
            self._create_startup_scripts()
            
            # Create environment template
            self._create_env_template(config_data)
            
            return {
                'success': True,
                'message': 'Installation completed successfully',
                'install_dir': self.install_dir
            }
            
        except Exception as e:
            logger.error(f"Installation failed: {e}")
            return {
                'success': False,
                'message': f'Installation failed: {str(e)}'
            }
    
    def _create_startup_scripts(self):
        """Create startup scripts"""
        # Create start script
        start_script = os.path.join(self.install_dir, 'start.sh')
        with open(start_script, 'w') as f:
            f.write('''#!/bin/bash
set -e

if [[ ! -d "venv" ]]; then
    echo "❌ Virtual environment not found"
    exit 1
fi

source venv/bin/activate

if [[ ! -f ".env" ]]; then
    cp .env.template .env
    echo "⚠️  Created .env from template - please configure your credentials"
fi

echo "🚀 Starting AuditHound..."
python run_unified_dashboard.py "$@"
''')
        
        os.chmod(start_script, 0o755)
        
        # Create Windows start script
        start_script_win = os.path.join(self.install_dir, 'start.bat')
        with open(start_script_win, 'w') as f:
            f.write('''@echo off
if not exist "venv" (
    echo Virtual environment not found
    exit /b 1
)

call venv\\Scripts\\activate.bat

if not exist ".env" (
    copy .env.template .env
    echo Created .env from template - please configure your credentials
)

echo Starting AuditHound...
python run_unified_dashboard.py %*
''')
    
    def _create_env_template(self, config_data: Dict[str, Any]):
        """Create environment template file"""
        env_template = os.path.join(self.install_dir, '.env.template')
        
        env_content = '''# AuditHound Environment Variables
# Configure your cloud provider credentials here

'''
        
        if config_data.get('enable_aws'):
            env_content += '''# AWS Credentials
# AWS_ACCESS_KEY_ID=your-aws-access-key
# AWS_SECRET_ACCESS_KEY=your-aws-secret-key

'''
        
        if config_data.get('enable_gcp'):
            env_content += '''# Google Cloud Credentials
# GCP_PROJECT_ID=your-gcp-project-id
# Place your service account JSON in ./credentials/gcp-service-account.json

'''
        
        if config_data.get('enable_azure'):
            env_content += '''# Azure Credentials
# AZURE_TENANT_ID=your-azure-tenant-id
# AZURE_SUBSCRIPTION_ID=your-azure-subscription-id
# AZURE_CLIENT_ID=your-azure-client-id
# AZURE_CLIENT_SECRET=your-azure-client-secret

'''
        
        if config_data.get('misp_url'):
            env_content += '''# MISP Integration
# MISP_API_KEY=your-misp-api-key

'''
        
        if config_data.get('thehive_url'):
            env_content += '''# TheHive Integration
# THEHIVE_API_KEY=your-thehive-api-key

'''
        
        with open(env_template, 'w') as f:
            f.write(env_content)

# Global installer instance
installer = AuditHoundInstaller()

@app.route('/')
def index():
    """Main installer page"""
    return render_template('web_installer.html')

@app.route('/api/prerequisites')
def check_prerequisites():
    """API endpoint to check prerequisites"""
    checks = installer.check_prerequisites()
    return jsonify(checks)

@app.route('/api/install', methods=['POST'])
def install():
    """API endpoint to perform installation"""
    try:
        form_data = request.get_json()
        
        # Validate required fields
        required_fields = ['org_name', 'admin_email', 'service_tier']
        for field in required_fields:
            if not form_data.get(field):
                return jsonify({
                    'success': False,
                    'message': f'Required field missing: {field}'
                }), 400
        
        # Perform installation
        result = installer.install_audithound(form_data)
        
        if result['success']:
            session['install_completed'] = True
            session['install_dir'] = result['install_dir']
            session['config'] = form_data
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Installation API error: {e}")
        return jsonify({
            'success': False,
            'message': f'Installation failed: {str(e)}'
        }), 500

@app.route('/complete')
def complete():
    """Installation complete page"""
    if not session.get('install_completed'):
        return redirect(url_for('index'))
    
    return render_template('install_complete.html', 
                         install_dir=session.get('install_dir'),
                         config=session.get('config'))

@app.route('/api/test-config', methods=['POST'])
def test_config():
    """Test configuration after installation"""
    try:
        install_dir = session.get('install_dir')
        if not install_dir:
            return jsonify({'success': False, 'message': 'No installation found'}), 400
        
        # Try to import and test the configuration
        sys.path.insert(0, os.path.join(install_dir, 'src'))
        
        # Basic configuration test
        config_file = os.path.join(install_dir, 'config.yaml')
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            return jsonify({
                'success': True,
                'message': 'Configuration is valid',
                'config_summary': {
                    'organization': config.get('organization', {}).get('name', 'Unknown'),
                    'enabled_providers': [
                        provider for provider, settings in config.get('cloud_providers', {}).items()
                        if settings.get('enabled', False)
                    ],
                    'dashboard_port': config.get('dashboard', {}).get('port', 5001)
                }
            })
        else:
            return jsonify({'success': False, 'message': 'Configuration file not found'}), 404
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Configuration test failed: {str(e)}'}), 500

# Create the installer template
if not os.path.exists('templates'):
    os.makedirs('templates')

# Create web installer template
with open('templates/web_installer.html', 'w') as f:
    f.write('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuditHound Installer</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .installer-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem 0;
            margin-bottom: 2rem;
        }
        .prerequisite-check {
            margin-bottom: 1rem;
        }
        .check-status {
            display: inline-block;
            width: 20px;
            text-align: center;
        }
        .step-content {
            display: none;
        }
        .step-content.active {
            display: block;
        }
        .progress-steps {
            margin-bottom: 2rem;
        }
        .step {
            display: inline-block;
            padding: 0.5rem 1rem;
            margin: 0.25rem;
            border-radius: 20px;
            background: #e9ecef;
            color: #6c757d;
        }
        .step.active {
            background: #0d6efd;
            color: white;
        }
        .step.completed {
            background: #198754;
            color: white;
        }
    </style>
</head>
<body>
    <div class="installer-header">
        <div class="container">
            <h1><i class="fas fa-shield-alt me-3"></i>AuditHound Installer</h1>
            <p class="mb-0">Unified Security Platform - One-click setup</p>
        </div>
    </div>

    <div class="container">
        <div class="progress-steps">
            <div class="step active" id="step-1">1. Prerequisites</div>
            <div class="step" id="step-2">2. Configuration</div>
            <div class="step" id="step-3">3. Installation</div>
            <div class="step" id="step-4">4. Complete</div>
        </div>

        <!-- Step 1: Prerequisites -->
        <div class="step-content active" id="content-1">
            <div class="card">
                <div class="card-header">
                    <h5><i class="fas fa-check-circle me-2"></i>System Prerequisites</h5>
                </div>
                <div class="card-body">
                    <div id="prerequisite-checks">
                        <div class="text-center">
                            <div class="spinner-border" role="status"></div>
                            <p class="mt-2">Checking system requirements...</p>
                        </div>
                    </div>
                    <div class="mt-3">
                        <button class="btn btn-primary" id="next-to-config" disabled>
                            <i class="fas fa-arrow-right me-2"></i>Continue to Configuration
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Step 2: Configuration -->
        <div class="step-content" id="content-2">
            <form id="config-form">
                <div class="row">
                    <div class="col-md-6">
                        <div class="card mb-3">
                            <div class="card-header">
                                <h6><i class="fas fa-building me-2"></i>Organization</h6>
                            </div>
                            <div class="card-body">
                                <div class="mb-3">
                                    <label class="form-label">Organization Name *</label>
                                    <input type="text" class="form-control" name="org_name" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Admin Email *</label>
                                    <input type="email" class="form-control" name="admin_email" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Service Tier</label>
                                    <select class="form-select" name="service_tier">
                                        <option value="starter">Starter (25 assets)</option>
                                        <option value="professional">Professional (100 assets)</option>
                                        <option value="enterprise">Enterprise (500 assets)</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card mb-3">
                            <div class="card-header">
                                <h6><i class="fas fa-cloud me-2"></i>Cloud Providers</h6>
                            </div>
                            <div class="card-body">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" name="enable_aws" id="enable_aws">
                                    <label class="form-check-label" for="enable_aws">Amazon Web Services</label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" name="enable_gcp" id="enable_gcp">
                                    <label class="form-check-label" for="enable_gcp">Google Cloud Platform</label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" name="enable_azure" id="enable_azure">
                                    <label class="form-check-label" for="enable_azure">Microsoft Azure</label>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="card mb-3">
                    <div class="card-header">
                        <h6><i class="fas fa-link me-2"></i>SOC Integrations (Optional)</h6>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-4">
                                <label class="form-label">MISP Server URL</label>
                                <input type="url" class="form-control" name="misp_url" placeholder="https://misp.yourdomain.com">
                            </div>
                            <div class="col-md-4">
                                <label class="form-label">TheHive Server URL</label>
                                <input type="url" class="form-control" name="thehive_url" placeholder="https://thehive.yourdomain.com">
                            </div>
                            <div class="col-md-4">
                                <label class="form-label">Slack Webhook URL</label>
                                <input type="url" class="form-control" name="slack_webhook" placeholder="https://hooks.slack.com/...">
                            </div>
                        </div>
                    </div>
                </div>

                <div class="card mb-3">
                    <div class="card-header">
                        <h6><i class="fas fa-cog me-2"></i>Dashboard Settings</h6>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <label class="form-label">Dashboard Port</label>
                                <input type="number" class="form-control" name="dashboard_port" value="5001" min="1024" max="65535">
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Slack Channel</label>
                                <input type="text" class="form-control" name="slack_channel" value="#security">
                            </div>
                        </div>
                    </div>
                </div>

                <div class="mt-3">
                    <button type="button" class="btn btn-secondary me-2" id="back-to-prereq">
                        <i class="fas fa-arrow-left me-2"></i>Back
                    </button>
                    <button type="button" class="btn btn-primary" id="start-install">
                        <i class="fas fa-download me-2"></i>Start Installation
                    </button>
                </div>
            </form>
        </div>

        <!-- Step 3: Installation -->
        <div class="step-content" id="content-3">
            <div class="card">
                <div class="card-header">
                    <h5><i class="fas fa-download me-2"></i>Installing AuditHound</h5>
                </div>
                <div class="card-body">
                    <div id="install-progress">
                        <div class="text-center">
                            <div class="spinner-border text-primary" role="status"></div>
                            <p class="mt-2">Installing AuditHound...</p>
                            <p class="text-muted">This may take a few minutes</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Step 4: Complete -->
        <div class="step-content" id="content-4">
            <div class="card border-success">
                <div class="card-header bg-success text-white">
                    <h5><i class="fas fa-check-circle me-2"></i>Installation Complete!</h5>
                </div>
                <div class="card-body">
                    <div id="install-summary"></div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let currentStep = 1;
        
        // Check prerequisites on load
        document.addEventListener('DOMContentLoaded', function() {
            checkPrerequisites();
        });
        
        function checkPrerequisites() {
            fetch('/api/prerequisites')
                .then(response => response.json())
                .then(data => {
                    displayPrerequisites(data);
                    if (data.overall_status) {
                        document.getElementById('next-to-config').disabled = false;
                    }
                })
                .catch(error => {
                    console.error('Error checking prerequisites:', error);
                });
        }
        
        function displayPrerequisites(checks) {
            const container = document.getElementById('prerequisite-checks');
            let html = '';
            
            for (const [key, check] of Object.entries(checks)) {
                if (key === 'overall_status') continue;
                
                const icon = check.status ? 'fa-check-circle text-success' : 'fa-times-circle text-danger';
                html += `
                    <div class="prerequisite-check d-flex align-items-center">
                        <span class="check-status">
                            <i class="fas ${icon}"></i>
                        </span>
                        <span class="ms-2">${check.message}</span>
                    </div>
                `;
            }
            
            container.innerHTML = html;
        }
        
        // Navigation
        document.getElementById('next-to-config').addEventListener('click', () => goToStep(2));
        document.getElementById('back-to-prereq').addEventListener('click', () => goToStep(1));
        document.getElementById('start-install').addEventListener('click', startInstallation);
        
        function goToStep(step) {
            // Hide current step
            document.getElementById(`content-${currentStep}`).classList.remove('active');
            document.getElementById(`step-${currentStep}`).classList.remove('active');
            
            // Show new step
            currentStep = step;
            document.getElementById(`content-${currentStep}`).classList.add('active');
            document.getElementById(`step-${currentStep}`).classList.add('active');
            
            // Mark previous steps as completed
            for (let i = 1; i < currentStep; i++) {
                document.getElementById(`step-${i}`).classList.add('completed');
            }
        }
        
        function startInstallation() {
            // Validate form
            const form = document.getElementById('config-form');
            if (!form.checkValidity()) {
                form.reportValidity();
                return;
            }
            
            // Collect form data
            const formData = new FormData(form);
            const config = {};
            for (const [key, value] of formData.entries()) {
                config[key] = value;
            }
            
            // Add checkbox values
            config.enable_aws = document.getElementById('enable_aws').checked;
            config.enable_gcp = document.getElementById('enable_gcp').checked;
            config.enable_azure = document.getElementById('enable_azure').checked;
            
            goToStep(3);
            
            // Start installation
            fetch('/api/install', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(config)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('install-summary').innerHTML = `
                        <div class="alert alert-success">
                            <h6>Installation Successful!</h6>
                            <p>AuditHound has been installed to: <code>${data.install_dir}</code></p>
                        </div>
                        <div class="mt-3">
                            <h6>Next Steps:</h6>
                            <ol>
                                <li>Configure your cloud credentials in the <code>.env</code> file</li>
                                <li>Start AuditHound: <code>cd ${data.install_dir} && ./start.sh</code></li>
                                <li>Access the dashboard at: <a href="http://localhost:${config.dashboard_port || 5001}" target="_blank">http://localhost:${config.dashboard_port || 5001}</a></li>
                            </ol>
                        </div>
                        <div class="mt-3">
                            <a href="/complete" class="btn btn-success">View Complete Setup Guide</a>
                        </div>
                    `;
                    goToStep(4);
                } else {
                    document.getElementById('install-progress').innerHTML = `
                        <div class="alert alert-danger">
                            <h6>Installation Failed</h6>
                            <p>${data.message}</p>
                        </div>
                        <button class="btn btn-primary" onclick="location.reload()">Try Again</button>
                    `;
                }
            })
            .catch(error => {
                console.error('Installation error:', error);
                document.getElementById('install-progress').innerHTML = `
                    <div class="alert alert-danger">
                        <h6>Installation Error</h6>
                        <p>An unexpected error occurred. Please try again.</p>
                    </div>
                    <button class="btn btn-primary" onclick="location.reload()">Try Again</button>
                `;
            });
        }
    </script>
</body>
</html>''')

# Create completion template
with open('templates/install_complete.html', 'w') as f:
    f.write('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuditHound - Installation Complete</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="text-center mb-5">
            <i class="fas fa-check-circle text-success" style="font-size: 4rem;"></i>
            <h1 class="mt-3">AuditHound Installation Complete!</h1>
            <p class="lead">Your unified security platform is ready to use</p>
        </div>

        <div class="row">
            <div class="col-md-8 mx-auto">
                <div class="card">
                    <div class="card-body">
                        <h5>Installation Summary</h5>
                        <ul class="list-unstyled">
                            <li><strong>Installation Directory:</strong> <code>{{ install_dir }}</code></li>
                            <li><strong>Organization:</strong> {{ config.org_name }}</li>
                            <li><strong>Service Tier:</strong> {{ config.service_tier }}</li>
                            <li><strong>Dashboard Port:</strong> {{ config.dashboard_port or 5001 }}</li>
                        </ul>

                        <h5 class="mt-4">Quick Start Commands</h5>
                        <div class="bg-dark text-light p-3 rounded">
                            <code>
                                # Navigate to installation<br>
                                cd {{ install_dir }}<br><br>
                                # Configure credentials<br>
                                cp .env.template .env<br>
                                nano .env<br><br>
                                # Start AuditHound<br>
                                ./start.sh<br>
                            </code>
                        </div>

                        <div class="mt-4">
                            <a href="http://localhost:{{ config.dashboard_port or 5001 }}" 
                               class="btn btn-primary btn-lg" target="_blank">
                                <i class="fas fa-external-link-alt me-2"></i>Open Dashboard
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>''')

if __name__ == '__main__':
    print("🌐 AuditHound Web Installer")
    print("Access the installer at: http://localhost:8000")
    print("Press Ctrl+C to stop")
    
    app.run(host='0.0.0.0', port=8000, debug=True)