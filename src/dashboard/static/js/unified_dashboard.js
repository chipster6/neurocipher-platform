/**
 * Unified Dashboard JavaScript
 * Handles compliance auditing + threat hunting + security analytics
 */

let complianceChart = null;
let threatChart = null;
let refreshInterval = null;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 Initializing AuditHound Unified Dashboard');
    
    // Load initial data
    loadDashboardSummary();
    loadAssets();
    loadFindings();
    
    // Setup auto-refresh
    setupAutoRefresh();
    
    // Setup event listeners
    setupEventListeners();
});

/**
 * Load dashboard summary data
 */
async function loadDashboardSummary() {
    try {
        const response = await fetch('/api/dashboard-summary');
        const data = await response.json();
        
        if (response.ok) {
            updateSummaryCards(data);
            updateCharts(data);
            updateRecentScans(data.recent_scans);
        } else {
            showError('Failed to load dashboard summary: ' + data.error);
        }
    } catch (error) {
        showError('Error loading dashboard summary: ' + error.message);
    }
}

/**
 * Update summary cards with data
 */
function updateSummaryCards(data) {
    document.getElementById('totalAssets').textContent = data.total_assets || 0;
    document.getElementById('complianceScore').textContent = Math.round(data.overall_compliance_score || 0) + '%';
    document.getElementById('avgRiskScore').textContent = Math.round(data.average_risk_score || 0);
    document.getElementById('activeThreats').textContent = data.threat_summary?.active || 0;
}

/**
 * Update compliance and threat charts
 */
function updateCharts(data) {
    // Compliance status chart
    if (complianceChart) {
        complianceChart.destroy();
    }
    
    const complianceCtx = document.getElementById('complianceChart').getContext('2d');
    complianceChart = new Chart(complianceCtx, {
        type: 'doughnut',
        data: {
            labels: ['Compliant', 'Partial', 'Non-Compliant'],
            datasets: [{
                data: [
                    data.compliance_summary?.compliant || 0,
                    data.compliance_summary?.partial || 0,
                    data.compliance_summary?.non_compliant || 0
                ],
                backgroundColor: ['#28a745', '#ffc107', '#dc3545'],
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
    
    // Threat status chart
    if (threatChart) {
        threatChart.destroy();
    }
    
    const threatCtx = document.getElementById('threatChart').getContext('2d');
    threatChart = new Chart(threatCtx, {
        type: 'bar',
        data: {
            labels: ['Resolved', 'Investigating', 'Active'],
            datasets: [{
                label: 'Threat Status',
                data: [
                    data.threat_summary?.resolved || 0,
                    data.threat_summary?.investigating || 0,
                    data.threat_summary?.active || 0
                ],
                backgroundColor: ['#28a745', '#17a2b8', '#dc3545'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

/**
 * Update recent scans display
 */
function updateRecentScans(scans) {
    const container = document.getElementById('recentScans');
    
    if (!scans || scans.length === 0) {
        container.innerHTML = '<div class="text-muted text-center">No recent scans available</div>';
        return;
    }
    
    const scansHtml = scans.map(scan => `
        <div class="card mb-2">
            <div class="card-body">
                <div class="row align-items-center">
                    <div class="col-md-3">
                        <strong>${scan.scan_id}</strong><br>
                        <small class="text-muted">${scan.scan_type}</small>
                    </div>
                    <div class="col-md-3">
                        <span class="badge ${getScanStatusBadgeClass(scan.status)}">${scan.status}</span>
                    </div>
                    <div class="col-md-3">
                        <div class="text-muted small">
                            ${scan.total_findings || 0} findings<br>
                            ${scan.duration_minutes || 0} minutes
                        </div>
                    </div>
                    <div class="col-md-3 text-end">
                        <button class="btn btn-sm btn-outline-primary" onclick="viewScanDetails('${scan.scan_id}')">
                            <i class="fas fa-eye"></i> View
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `).join('');
    
    container.innerHTML = scansHtml;
}

/**
 * Load asset inventory
 */
async function loadAssets() {
    try {
        const params = new URLSearchParams();
        
        const providerFilter = document.getElementById('providerFilter')?.value;
        const criticalityFilter = document.getElementById('criticalityFilter')?.value;
        
        if (providerFilter) params.append('provider', providerFilter);
        if (criticalityFilter) params.append('criticality', criticalityFilter);
        
        const response = await fetch(`/api/assets?${params.toString()}`);
        const data = await response.json();
        
        if (response.ok) {
            displayAssets(data.assets);
        } else {
            showError('Failed to load assets: ' + data.error);
        }
    } catch (error) {
        showError('Error loading assets: ' + error.message);
    }
}

/**
 * Display assets in grid format
 */
function displayAssets(assets) {
    const container = document.getElementById('assetInventory');
    
    if (!assets || assets.length === 0) {
        container.innerHTML = '<div class="text-muted text-center">No assets found</div>';
        return;
    }
    
    const assetsHtml = `
        <div class="asset-grid">
            ${assets.map(asset => `
                <div class="card asset-card">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-start mb-2">
                            <h6 class="card-title mb-0">${asset.name}</h6>
                            <span class="risk-badge risk-${asset.criticality}">${asset.criticality}</span>
                        </div>
                        
                        <div class="row mb-2">
                            <div class="col-6">
                                <small class="text-muted">Type:</small><br>
                                <span class="badge bg-secondary">${asset.type}</span>
                            </div>
                            <div class="col-6">
                                <small class="text-muted">Provider:</small><br>
                                <span class="badge bg-info">${asset.cloud_provider || 'N/A'}</span>
                            </div>
                        </div>
                        
                        <div class="row mb-2">
                            <div class="col-6">
                                <small class="text-muted">Compliance:</small><br>
                                <span class="risk-badge compliance-${asset.compliance_status}">${asset.compliance_status}</span>
                            </div>
                            <div class="col-6">
                                <small class="text-muted">Threat:</small><br>
                                <span class="risk-badge threat-${asset.threat_status}">${asset.threat_status}</span>
                            </div>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-12">
                                <small class="text-muted">Risk Score: ${asset.anomaly_score.toFixed(1)}/100</small>
                                <div class="progress mt-1">
                                    <div class="progress-bar ${getRiskProgressClass(asset.anomaly_score)}" 
                                         style="width: ${asset.anomaly_score}%"></div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="text-end">
                            <button class="btn btn-sm btn-outline-primary" onclick="viewAssetDetails('${asset.asset_id}')">
                                <i class="fas fa-info-circle"></i> Details
                            </button>
                        </div>
                    </div>
                </div>
            `).join('')}
        </div>
    `;
    
    container.innerHTML = assetsHtml;
}

/**
 * Load security findings
 */
async function loadFindings() {
    try {
        const params = new URLSearchParams();
        
        const typeFilter = document.getElementById('findingTypeFilter')?.value;
        const severityFilter = document.getElementById('severityFilter')?.value;
        const statusFilter = document.getElementById('statusFilter')?.value;
        
        if (typeFilter) params.append('type', typeFilter);
        if (severityFilter) params.append('severity', severityFilter);
        if (statusFilter) params.append('status', statusFilter);
        
        const response = await fetch(`/api/findings?${params.toString()}`);
        const data = await response.json();
        
        if (response.ok) {
            displayFindings(data.findings);
        } else {
            showError('Failed to load findings: ' + data.error);
        }
    } catch (error) {
        showError('Error loading findings: ' + error.message);
    }
}

/**
 * Display findings list
 */
function displayFindings(findings) {
    const container = document.getElementById('findingsList');
    
    if (!findings || findings.length === 0) {
        container.innerHTML = '<div class="text-muted text-center">No findings found</div>';
        return;
    }
    
    const findingsHtml = findings.map(finding => `
        <div class="card finding-card ${finding.severity} mb-3">
            <div class="card-body">
                <div class="row">
                    <div class="col-md-8">
                        <div class="d-flex justify-content-between align-items-start mb-2">
                            <h6 class="card-title mb-0">${finding.title}</h6>
                            <span class="risk-badge risk-${finding.severity}">${finding.severity}</span>
                        </div>
                        
                        <p class="card-text text-muted mb-2">${finding.description}</p>
                        
                        <div class="row mb-2">
                            <div class="col-md-4">
                                <small class="text-muted">Type:</small><br>
                                <span class="badge ${getFindingTypeBadgeClass(finding.finding_type)}">${finding.finding_type}</span>
                            </div>
                            <div class="col-md-4">
                                <small class="text-muted">Status:</small><br>
                                <span class="badge ${getStatusBadgeClass(finding.status)}">${finding.status}</span>
                            </div>
                            <div class="col-md-4">
                                <small class="text-muted">Risk Score:</small><br>
                                <strong>${finding.risk_score.toFixed(1)}/100</strong>
                            </div>
                        </div>
                        
                        ${finding.finding_type === 'compliance' || finding.finding_type === 'hybrid' ? `
                            <div class="mb-2">
                                <small class="text-muted">Control:</small>
                                <span class="badge bg-primary">${finding.control_id}</span>
                                <small class="text-muted ms-2">Score: ${finding.compliance_score?.toFixed(1) || 'N/A'}%</small>
                            </div>
                        ` : ''}
                        
                        ${finding.finding_type === 'threat' || finding.finding_type === 'hybrid' ? `
                            <div class="mb-2">
                                <small class="text-muted">MITRE Techniques:</small><br>
                                ${finding.mitre_techniques.map(technique => `
                                    <span class="mitre-technique">${technique}</span>
                                `).join('')}
                            </div>
                            
                            ${finding.iocs && finding.iocs.length > 0 ? `
                                <div class="mb-2">
                                    <small class="text-muted">IOCs:</small>
                                    ${finding.iocs.slice(0, 3).map(ioc => `
                                        <div class="ioc-item">${ioc.type}: ${ioc.value}</div>
                                    `).join('')}
                                    ${finding.iocs.length > 3 ? `<small class="text-muted">... and ${finding.iocs.length - 3} more</small>` : ''}
                                </div>
                            ` : ''}
                        ` : ''}
                        
                        <div class="mb-2">
                            <small class="text-muted">Affected Assets: ${finding.affected_assets.length}</small>
                        </div>
                    </div>
                    
                    <div class="col-md-4">
                        <div class="text-end">
                            <div class="btn-group-vertical w-100" role="group">
                                ${finding.finding_type === 'threat' || finding.finding_type === 'hybrid' ? `
                                    <button class="btn btn-sm btn-outline-warning" onclick="submitToMISP('${finding.finding_id}')">
                                        <i class="fas fa-share-alt"></i> Submit to MISP
                                    </button>
                                ` : ''}
                                
                                <button class="btn btn-sm btn-outline-info" onclick="createTheHiveCaseFromFinding('${finding.finding_id}')">
                                    <i class="fas fa-ticket-alt"></i> Create Case
                                </button>
                                
                                <button class="btn btn-sm btn-outline-primary" onclick="viewFindingDetails('${finding.finding_id}')">
                                    <i class="fas fa-eye"></i> View Details
                                </button>
                            </div>
                        </div>
                        
                        <div class="mt-3">
                            <small class="text-muted">
                                Created: ${new Date(finding.created_at).toLocaleString()}
                            </small>
                        </div>
                        
                        ${finding.misp_event_id ? `
                            <div class="mt-2">
                                <span class="badge bg-warning">MISP: ${finding.misp_event_id}</span>
                            </div>
                        ` : ''}
                        
                        ${finding.thehive_case_id ? `
                            <div class="mt-2">
                                <span class="badge bg-info">TheHive: ${finding.thehive_case_id}</span>
                            </div>
                        ` : ''}
                    </div>
                </div>
            </div>
        </div>
    `).join('');
    
    container.innerHTML = findingsHtml;
}

/**
 * Start unified scan with modal configuration
 */
function startUnifiedScan() {
    const modal = new bootstrap.Modal(document.getElementById('scanModal'));
    modal.show();
}

/**
 * Execute scan with selected configuration
 */
async function executeScan() {
    try {
        // Get selected providers
        const providers = [];
        if (document.getElementById('providerAll').checked) {
            providers.push('all');
        } else {
            if (document.getElementById('providerAws').checked) providers.push('aws');
            if (document.getElementById('providerGcp').checked) providers.push('gcp');
            if (document.getElementById('providerAzure').checked) providers.push('azure');
        }
        
        // Get selected frameworks
        const frameworks = [];
        if (document.getElementById('frameworkSoc2').checked) frameworks.push('soc2');
        if (document.getElementById('frameworkIso27001').checked) frameworks.push('iso27001');
        if (document.getElementById('frameworkCis').checked) frameworks.push('cis');
        
        // Get scan type
        const scanType = document.querySelector('input[name="scanType"]:checked').value;
        
        const scanConfig = {
            providers: providers,
            frameworks: frameworks,
            scan_type: scanType,
            hunting_rules: [] // Add specific rules if needed
        };
        
        const response = await fetch('/api/unified-scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(scanConfig)
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Close modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('scanModal'));
            modal.hide();
            
            showSuccess(`Scan started successfully! Scan ID: ${data.scan_id}`);
            
            // Start monitoring scan progress
            monitorScanProgress(data.scan_id);
        } else {
            showError('Failed to start scan: ' + data.error);
        }
    } catch (error) {
        showError('Error starting scan: ' + error.message);
    }
}

/**
 * Monitor scan progress
 */
function monitorScanProgress(scanId) {
    const checkProgress = async () => {
        try {
            const response = await fetch(`/api/unified-scan/${scanId}`);
            const data = await response.json();
            
            if (response.ok) {
                if (data.status === 'completed') {
                    showSuccess(`Scan ${scanId} completed successfully!`);
                    loadDashboardSummary(); // Refresh dashboard
                    return; // Stop monitoring
                } else if (data.status === 'failed') {
                    showError(`Scan ${scanId} failed`);
                    return; // Stop monitoring
                }
                
                // Continue monitoring if still running
                setTimeout(checkProgress, 5000);
            }
        } catch (error) {
            console.error('Error checking scan progress:', error);
        }
    };
    
    // Start monitoring
    setTimeout(checkProgress, 2000);
}

/**
 * Submit finding to MISP
 */
async function submitToMISP(findingId) {
    try {
        const response = await fetch('/api/soc-integration/misp/submit', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ finding_id: findingId })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showSuccess(`Successfully submitted to MISP. Event UUID: ${data.misp_event_uuid}`);
            loadFindings(); // Refresh findings
        } else {
            showError('Failed to submit to MISP: ' + data.error);
        }
    } catch (error) {
        showError('Error submitting to MISP: ' + error.message);
    }
}

/**
 * Create TheHive case from finding
 */
async function createTheHiveCaseFromFinding(findingId) {
    try {
        const response = await fetch('/api/soc-integration/thehive/create-case', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ finding_id: findingId })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showSuccess(`Successfully created TheHive case: ${data.case_id}`);
            loadFindings(); // Refresh findings
        } else {
            showError('Failed to create TheHive case: ' + data.error);
        }
    } catch (error) {
        showError('Error creating TheHive case: ' + error.message);
    }
}

/**
 * Correlate threat intelligence
 */
async function correlateThreatIntelligence() {
    try {
        const iocValue = document.getElementById('iocValue').value;
        const iocType = document.getElementById('iocType').value;
        
        if (!iocValue) {
            showError('Please enter an IOC value');
            return;
        }
        
        const response = await fetch('/api/threat-intelligence/correlate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                ioc_value: iocValue,
                ioc_type: iocType
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            displayMISPResults(data);
        } else {
            showError('Failed to correlate IOC: ' + data.error);
        }
    } catch (error) {
        showError('Error correlating IOC: ' + error.message);
    }
}

/**
 * Display MISP correlation results
 */
function displayMISPResults(data) {
    const container = document.getElementById('mispResults');
    
    if (data.sources.length === 0) {
        container.innerHTML = '<div class="alert alert-info">No threat intelligence found for this IOC</div>';
        return;
    }
    
    const resultsHtml = `
        <div class="alert alert-${data.threat_score > 70 ? 'danger' : data.threat_score > 40 ? 'warning' : 'success'}">
            <strong>Threat Score: ${data.threat_score.toFixed(1)}/100</strong>
        </div>
        
        <div class="mt-3">
            <h6>Intelligence Sources:</h6>
            ${data.sources.map(source => `
                <div class="card mt-2">
                    <div class="card-body">
                        <h6>${source.name}</h6>
                        <p>Confidence: ${source.confidence}%</p>
                        ${source.events ? `<p>Events: ${source.events.length}</p>` : ''}
                    </div>
                </div>
            `).join('')}
        </div>
        
        ${data.recommendations.length > 0 ? `
            <div class="mt-3">
                <h6>Recommendations:</h6>
                <ul>
                    ${data.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                </ul>
            </div>
        ` : ''}
    `;
    
    container.innerHTML = resultsHtml;
}

/**
 * Create TheHive case from SOC integration tab
 */
async function createTheHiveCase() {
    const findingId = document.getElementById('findingId').value;
    
    if (!findingId) {
        showError('Please enter a finding ID');
        return;
    }
    
    await createTheHiveCaseFromFinding(findingId);
}

/**
 * Utility functions
 */
function getScanStatusBadgeClass(status) {
    const classes = {
        'completed': 'bg-success',
        'running': 'bg-primary',
        'failed': 'bg-danger',
        'cancelled': 'bg-secondary'
    };
    return classes[status] || 'bg-secondary';
}

function getFindingTypeBadgeClass(type) {
    const classes = {
        'compliance': 'bg-primary',
        'threat': 'bg-danger',
        'hybrid': 'bg-warning'
    };
    return classes[type] || 'bg-secondary';
}

function getStatusBadgeClass(status) {
    const classes = {
        'open': 'bg-danger',
        'investigating': 'bg-warning',
        'resolved': 'bg-success',
        'false_positive': 'bg-secondary'
    };
    return classes[status] || 'bg-secondary';
}

function getRiskProgressClass(score) {
    if (score >= 80) return 'bg-danger';
    if (score >= 60) return 'bg-warning';
    if (score >= 40) return 'bg-info';
    return 'bg-success';
}

/**
 * View details functions (to be implemented)
 */
function viewScanDetails(scanId) {
    console.log('View scan details:', scanId);
    // Implement scan details modal/page
}

function viewAssetDetails(assetId) {
    console.log('View asset details:', assetId);
    // Implement asset details modal/page
}

function viewFindingDetails(findingId) {
    console.log('View finding details:', findingId);
    // Implement finding details modal/page
}

/**
 * Setup functions
 */
function setupAutoRefresh() {
    // Refresh dashboard every 30 seconds
    refreshInterval = setInterval(() => {
        loadDashboardSummary();
    }, 30000);
}

function setupEventListeners() {
    // Tab change events
    document.querySelectorAll('[data-bs-toggle="tab"]').forEach(tab => {
        tab.addEventListener('shown.bs.tab', function(event) {
            const target = event.target.getAttribute('data-bs-target');
            
            // Load data when switching to specific tabs
            if (target === '#assets') {
                loadAssets();
            } else if (target === '#findings') {
                loadFindings();
            }
        });
    });
}

function refreshDashboard() {
    loadDashboardSummary();
    loadAssets();
    loadFindings();
    showSuccess('Dashboard refreshed');
}

/**
 * Notification functions
 */
function showSuccess(message) {
    showNotification(message, 'success');
}

function showError(message) {
    showNotification(message, 'danger');
}

function showNotification(message, type) {
    // Create toast notification
    const toastHtml = `
        <div class="toast align-items-center text-white bg-${type} border-0" role="alert">
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `;
    
    // Add to toast container (create if doesn't exist)
    let toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toastContainer';
        toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
        toastContainer.style.zIndex = '9999';
        document.body.appendChild(toastContainer);
    }
    
    toastContainer.insertAdjacentHTML('beforeend', toastHtml);
    
    // Show toast
    const toastElement = toastContainer.lastElementChild;
    const toast = new bootstrap.Toast(toastElement);
    toast.show();
    
    // Remove from DOM after hidden
    toastElement.addEventListener('hidden.bs.toast', function() {
        toastElement.remove();
    });
}