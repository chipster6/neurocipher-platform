// AuditHound Dashboard JavaScript
let complianceData = [];

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', function() {
    loadComplianceSummary();
    loadComplianceDetails();
    
    // Set up filter change handlers
    document.getElementById('provider-filter').addEventListener('change', loadComplianceDetails);
    document.getElementById('framework-filter').addEventListener('change', loadComplianceDetails);
});

// Load compliance summary data
async function loadComplianceSummary() {
    try {
        const response = await fetch('/api/compliance-summary');
        const data = await response.json();
        
        document.getElementById('compliant-count').textContent = data.compliant;
        document.getElementById('partial-count').textContent = data.partial;
        document.getElementById('non-compliant-count').textContent = data.non_compliant;
        document.getElementById('overall-score').textContent = data.overall_score.toFixed(1) + '%';
        document.getElementById('last-updated').textContent = new Date(data.last_updated).toLocaleString();
        
    } catch (error) {
        console.error('Error loading compliance summary:', error);
        showError('Failed to load compliance summary');
    }
}

// Load detailed compliance data
async function loadComplianceDetails() {
    const provider = document.getElementById('provider-filter').value;
    const framework = document.getElementById('framework-filter').value;
    
    const tbody = document.getElementById('compliance-tbody');
    tbody.innerHTML = '<tr><td colspan="7" class="text-center"><div class="loading"></div> Loading...</td></tr>';
    
    try {
        const response = await fetch(`/api/compliance-details?provider=${provider}&framework=${framework}`);
        complianceData = await response.json();
        
        displayComplianceTable(complianceData);
        updateSummaryFromDetails(complianceData);
        
    } catch (error) {
        console.error('Error loading compliance details:', error);
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-danger">Error loading data</td></tr>';
    }
}

// Display compliance data in table
function displayComplianceTable(data) {
    const tbody = document.getElementById('compliance-tbody');
    
    if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">No data available</td></tr>';
        return;
    }
    
    tbody.innerHTML = data.map(item => `
        <tr>
            <td><strong>${item.control_id}</strong></td>
            <td>${item.description}</td>
            <td>
                <span class="badge bg-secondary">${item.cloud_provider.toUpperCase()}</span>
            </td>
            <td><span class="badge bg-info">${item.framework}</span></td>
            <td>
                <span class="${getScoreClass(item.overall_score)}">
                    ${item.overall_score.toFixed(1)}%
                </span>
            </td>
            <td>
                <span class="status-badge ${getStatusClass(item.compliance_status)}">
                    ${getStatusIcon(item.compliance_status)} ${item.compliance_status.replace('_', ' ')}
                </span>
            </td>
            <td>
                <button class="btn btn-sm btn-outline-primary" onclick="showControlDetails('${item.control_id}', '${item.cloud_provider}')">
                    <i class="fas fa-eye"></i> Details
                </button>
            </td>
        </tr>
    `).join('');
}

// Update summary cards from detailed data
function updateSummaryFromDetails(data) {
    const summary = data.reduce((acc, item) => {
        acc[item.compliance_status] = (acc[item.compliance_status] || 0) + 1;
        return acc;
    }, {});
    
    document.getElementById('compliant-count').textContent = summary.compliant || 0;
    document.getElementById('partial-count').textContent = summary.partial || 0;
    document.getElementById('non-compliant-count').textContent = summary.non_compliant || 0;
    
    // Calculate overall score
    const totalScore = data.reduce((sum, item) => sum + item.overall_score, 0);
    const avgScore = data.length > 0 ? totalScore / data.length : 0;
    document.getElementById('overall-score').textContent = avgScore.toFixed(1) + '%';
}

// Get CSS class for score display
function getScoreClass(score) {
    if (score >= 90) return 'score-high';
    if (score >= 70) return 'score-medium';
    return 'score-low';
}

// Get CSS class for status badge
function getStatusClass(status) {
    switch (status) {
        case 'compliant': return 'status-compliant';
        case 'partial': return 'status-partial';
        case 'non_compliant': return 'status-non-compliant';
        default: return 'status-partial';
    }
}

// Get icon for status
function getStatusIcon(status) {
    switch (status) {
        case 'compliant': return '<i class="fas fa-check"></i>';
        case 'partial': return '<i class="fas fa-exclamation-triangle"></i>';
        case 'non_compliant': return '<i class="fas fa-times"></i>';
        default: return '<i class="fas fa-question"></i>';
    }
}

// Show control details modal
function showControlDetails(controlId, provider) {
    const control = complianceData.find(item => 
        item.control_id === controlId && item.cloud_provider === provider
    );
    
    if (!control) {
        showError('Control details not found');
        return;
    }
    
    document.getElementById('modal-title').textContent = 
        `${control.control_id} - ${control.description} (${control.cloud_provider.toUpperCase()})`;
    
    const modalBody = document.getElementById('modal-body');
    modalBody.innerHTML = `
        <div class="row">
            <div class="col-md-6">
                <h6>Overall Score</h6>
                <div class="progress mb-3">
                    <div class="progress-bar ${getProgressBarClass(control.overall_score)}" 
                         style="width: ${control.overall_score}%">
                        ${control.overall_score.toFixed(1)}%
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <h6>Compliance Status</h6>
                <span class="status-badge ${getStatusClass(control.compliance_status)}">
                    ${getStatusIcon(control.compliance_status)} ${control.compliance_status.replace('_', ' ')}
                </span>
            </div>
        </div>
        
        <h6 class="mt-4">Component Scores</h6>
        <div class="row">
            ${Object.entries(control.component_scores || {}).map(([component, score]) => `
                <div class="col-md-6 mb-3">
                    <label class="form-label">${component.replace('_', ' ').toUpperCase()}</label>
                    <div class="progress">
                        <div class="progress-bar ${getProgressBarClass(score)}" 
                             style="width: ${score}%">
                            ${score.toFixed(1)}%
                        </div>
                    </div>
                </div>
            `).join('')}
        </div>
        
        <div class="mt-4">
            <h6>Recommendations</h6>
            <ul class="list-group list-group-flush">
                ${generateRecommendations(control).map(rec => `
                    <li class="list-group-item">${rec}</li>
                `).join('')}
            </ul>
        </div>
    `;
    
    new bootstrap.Modal(document.getElementById('controlModal')).show();
}

// Get progress bar class based on score
function getProgressBarClass(score) {
    if (score >= 90) return 'bg-success';
    if (score >= 70) return 'bg-warning';
    return 'bg-danger';
}

// Generate recommendations based on control data
function generateRecommendations(control) {
    const recommendations = [];
    
    if (control.overall_score < 90) {
        recommendations.push('Review and strengthen access control policies');
    }
    
    if (control.component_scores) {
        Object.entries(control.component_scores).forEach(([component, score]) => {
            if (score < 80) {
                recommendations.push(`Improve ${component.replace('_', ' ')} configuration`);
            }
        });
    }
    
    if (control.compliance_status === 'non_compliant') {
        recommendations.push('Immediate attention required for compliance');
    }
    
    return recommendations.length > 0 ? recommendations : ['No specific recommendations at this time'];
}

// Refresh all data
function refreshData() {
    loadComplianceSummary();
    loadComplianceDetails();
    showSuccess('Data refreshed successfully');
}

// Generate compliance report
async function generateReport() {
    const provider = document.getElementById('provider-filter').value;
    const framework = document.getElementById('framework-filter').value;
    
    try {
        const response = await fetch(`/api/generate-report?provider=${provider}&framework=${framework}`);
        const data = await response.json();
        
        showSuccess(`Report ${data.report_id} generated successfully`);
        
    } catch (error) {
        console.error('Error generating report:', error);
        showError('Failed to generate report');
    }
}

// Show success message
function showSuccess(message) {
    showToast(message, 'success');
}

// Show error message
function showError(message) {
    showToast(message, 'danger');
}

// Show toast notification
function showToast(message, type) {
    const toast = document.createElement('div');
    toast.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    toast.style = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    toast.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
        }
    }, 5000);
}