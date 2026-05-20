// SecurFlow CTI Dashboard - Main JavaScript
// This file handles all dashboard interactions and data visualization

// Global state
let reportData = null;
let currentFilter = 'all';

// Initialize dashboard
document.addEventListener('DOMContentLoaded', async () => {
    console.log('🚀 SecurFlow Dashboard initializing...');
    
    // Load report data
    await loadReportData();
    
    // Initialize UI components
    initializeUI();
    
    // Render dashboard
    renderDashboard();
    
    // Start live updates
    startLiveUpdates();
});

// Load report data from JSON file
async function loadReportData() {
    // Try report.json first (highest priority)
    try {
        const response = await fetch('report.json');
        if (response.ok) {
            reportData = await response.json();
            console.log('📊 Report data loaded from report.json:', reportData);
            return;
        }
    } catch (error) {
        console.log('⚠️ report.json not found, trying fallbacks...');
    }
    
    // Fallback paths
    const fallbackPaths = [
        './shared/3_final_report.json',
        '../shared/3_final_report.json',
        './3_final_report.json'
    ];
    
    for (const path of fallbackPaths) {
        try {
            const response = await fetch(path);
            if (response.ok) {
                reportData = await response.json();
                console.log('📊 Report data loaded from fallback:', path, reportData);
                return;
            }
        } catch (error) {
            console.log('⚠️ Failed to load from:', path, error);
        }
    }
    
    console.error('❌ All paths failed - dashboard will show error state');
    showErrorMessage('Impossible de charger les données du pipeline - vérifiez le déploiement');
    // Keep reportData as null to show error state
    reportData = null;
}

// Initialize UI components
function initializeUI() {
    // Update timestamp
    updateTimestamp();
    
    // Setup filter buttons
    setupFilters();
    
    // Setup refresh button
    setupRefreshButton();
}

// Render main dashboard
function renderDashboard() {
    if (!reportData) return;
    
    // Update banner
    updateBanner();
    
    // Render KPIs
    renderKPIs();
    
    // Render vulnerability table
    renderVulnerabilityTable();
    
    // Render charts
    renderCharts();
    
    // Update metadata
    updateMetadata();
}

// Update banner status
function updateBanner() {
    const banner = document.getElementById('banner');
    const bIcon = document.getElementById('b-icon');
    const bTitle = document.getElementById('b-title');
    const bSub = document.getElementById('b-sub');
    const bLink = document.getElementById('b-link');
    
    const decisions = reportData.decision_metadata?.decisions || {};
    const blockerCount = decisions.BLOQUER || 0;
    
    if (blockerCount > 0) {
        banner.className = 'banner bloquer';
        bIcon.textContent = '🛔';
        bTitle.textContent = `${blockerCount} faille(s) critique(s) détectée(s)`;
        bSub.textContent = 'Déploiement bloqué - Action requise';
        bLink.style.display = 'inline';
    } else {
        banner.className = 'banner passer';
        bIcon.textContent = '✅';
        bTitle.textContent = 'Aucune faille critique détectée';
        bSub.textContent = 'Pipeline terminé avec succès';
        bLink.style.display = 'none';
    }
}

// Render KPI cards
function renderKPIs() {
    const kpiGrid = document.getElementById('kpi-grid');
    if (!kpiGrid) return;
    
    const decisions = reportData.decision_metadata?.decisions || {};
    const metadata = reportData.decision_metadata || {};
    
    const kpis = [
        {
            title: 'Total Scanné',
            value: metadata.total_processed || 0,
            icon: '🔍',
            color: '#3b82f6'
        },
        {
            title: 'À Bloquer',
            value: decisions.BLOQUER || 0,
            icon: '🛑',
            color: '#dc3545'
        },
        {
            title: 'À Alerter',
            value: decisions.ALERTER || 0,
            icon: '⚠️',
            color: '#ffc107'
        },
        {
            title: 'À Passer',
            value: decisions.PASSER || 0,
            icon: '✅',
            color: '#28a745'
        },
        {
            title: 'Score SRP Moyen',
            value: (metadata.average_srp || 0).toFixed(1),
            icon: '📊',
            color: '#6f42c1'
        }
    ];
    
    kpiGrid.innerHTML = kpis.map(kpi => `
        <div class="kpi-card" style="border-left: 4px solid ${kpi.color}">
            <div class="kpi-header">
                <span class="kpi-icon">${kpi.icon}</span>
                <span class="kpi-title">${kpi.title}</span>
            </div>
            <div class="kpi-value">${kpi.value}</div>
        </div>
    `).join('');
}

// Render vulnerability table
function renderVulnerabilityTable() {
    const vulnerabilities = reportData.vulnerability_decisions || [];
    const tableContainer = document.getElementById('vuln-table');
    if (!tableContainer) return;
    
    if (vulnerabilities.length === 0) {
        tableContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🛡️</div>
                <div class="empty-text">Aucune vulnérabilité détectée</div>
                <div class="empty-sub">Le pipeline s'est exécuté avec succès</div>
            </div>
        `;
        return;
    }
    
    const tableHTML = `
        <div class="table-header">
            <div class="table-title">Vulnérabilités Détectées</div>
            <div class="table-filters">
                <button class="filter-btn ${currentFilter === 'all' ? 'active' : ''}" onclick="filterVulnerabilities('all')">Tous</button>
                <button class="filter-btn ${currentFilter === 'BLOQUER' ? 'active' : ''}" onclick="filterVulnerabilities('BLOQUER')">Bloquer</button>
                <button class="filter-btn ${currentFilter === 'ALERTER' ? 'active' : ''}" onclick="filterVulnerabilities('ALERTER')">Alerter</button>
                <button class="filter-btn ${currentFilter === 'PASSER' ? 'active' : ''}" onclick="filterVulnerabilities('PASSER')">Passer</button>
            </div>
        </div>
        <div class="table-body">
            ${vulnerabilities.map(vuln => createVulnerabilityRow(vuln)).join('')}
        </div>
    `;
    
    tableContainer.innerHTML = tableHTML;
}

// Create vulnerability row HTML
function createVulnerabilityRow(vuln) {
    const decisionColors = {
        'BLOQUER': '#dc3545',
        'ALERTER': '#ffc107',
        'PASSER': '#28a745'
    };
    
    const decision = vuln.decision || 'UNKNOWN';
    const color = decisionColors[decision] || '#6c757d';
    
    return `
        <div class="vuln-row" data-decision="${decision}">
            <div class="vuln-cve">
                <div class="cve-id">${vuln.cve_id || 'N/A'}</div>
                <div class="srp-score">SRP: ${(vuln.srp_score || 0).toFixed(1)}</div>
            </div>
            <div class="vuln-details">
                <div class="vuln-package">${vuln.package || 'N/A'}</div>
                <div class="vuln-decision" style="background-color: ${color}; color: white;">
                    ${decision}
                </div>
            </div>
            <div class="vuln-ai">
                <div class="ai-explanation">${vuln.ai_explanation || 'En attente d\'analyse...'}</div>
                <div class="ai-fix">${vuln.ai_fix || 'En attente d\'analyse...'}</div>
            </div>
        </div>
    `;
}

// Filter vulnerabilities
function filterVulnerabilities(filter) {
    currentFilter = filter;
    
    // Update button states
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.textContent.toLowerCase().includes(filter.toLowerCase()));
    });
    
    // Re-render table
    renderVulnerabilityTable();
}

// Render charts
function renderCharts() {
    renderSRPChart();
    renderDecisionChart();
}

// Render SRP distribution chart
function renderSRPChart() {
    const canvas = document.getElementById('srpChart');
    if (!canvas || !reportData) return;
    
    const vulnerabilities = reportData.vulnerability_decisions || [];
    const srpData = vulnerabilities.map(v => v.srp_score || 0);
    
    // Create distribution
    const distribution = {
        '0-3': 0,
        '4-6': 0,
        '7-10': 0
    };
    
    srpData.forEach(srp => {
        if (srp <= 3) distribution['0-3']++;
        else if (srp <= 6) distribution['4-6']++;
        else distribution['7-10']++;
    });
    
    // Simple bar chart
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;
    
    // Clear canvas
    ctx.clearRect(0, 0, width, height);
    
    // Draw bars
    const barWidth = width / 4 - 20;
    const maxValue = Math.max(...Object.values(distribution));
    
    Object.entries(distribution).forEach(([range, count], index) => {
        const barHeight = (count / maxValue) * (height - 40);
        const x = 30 + index * (barWidth + 20);
        const y = height - barHeight - 20;
        
        // Draw bar
        ctx.fillStyle = ['#28a745', '#ffc107', '#dc3545'][index];
        ctx.fillRect(x, y, barWidth, barHeight);
        
        // Draw label
        ctx.fillStyle = '#333';
        ctx.font = '12px Arial';
        ctx.textAlign = 'center';
        ctx.fillText(range, x + barWidth/2, height - 5);
        ctx.fillText(count, x + barWidth/2, y - 5);
    });
}

// Render decision distribution chart
function renderDecisionChart() {
    const canvas = document.getElementById('decisionChart');
    if (!canvas || !reportData) return;
    
    const decisions = reportData.decision_metadata?.decisions || {};
    const data = [
        { label: 'Bloquer', value: decisions.BLOQUER || 0, color: '#dc3545' },
        { label: 'Alerter', value: decisions.ALERTER || 0, color: '#ffc107' },
        { label: 'Passer', value: decisions.PASSER || 0, color: '#28a745' }
    ];
    
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;
    
    // Clear canvas
    ctx.clearRect(0, 0, width, height);
    
    // Draw pie chart
    const total = data.reduce((sum, item) => sum + item.value, 0);
    if (total === 0) return;
    
    let currentAngle = -Math.PI / 2;
    
    data.forEach(item => {
        const sliceAngle = (item.value / total) * 2 * Math.PI;
        
        // Draw slice
        ctx.beginPath();
        ctx.moveTo(width/2, height/2);
        ctx.arc(width/2, height/2, Math.min(width, height)/3, currentAngle, currentAngle + sliceAngle);
        ctx.closePath();
        ctx.fillStyle = item.color;
        ctx.fill();
        
        // Draw label
        const labelAngle = currentAngle + sliceAngle / 2;
        const labelX = width/2 + Math.cos(labelAngle) * (Math.min(width, height)/4);
        const labelY = height/2 + Math.sin(labelAngle) * (Math.min(width, height)/4);
        
        ctx.fillStyle = '#fff';
        ctx.font = 'bold 12px Arial';
        ctx.textAlign = 'center';
        ctx.fillText(`${item.label} (${item.value})`, labelX, labelY);
        
        currentAngle += sliceAngle;
    });
}

// Update metadata panel
function updateMetadata() {
    const metaRow = document.getElementById('meta-row');
    if (!metaRow || !reportData) return;
    
    const metadata = reportData.decision_metadata || {};
    
    metaRow.innerHTML = `
        <div class="meta-item">
            <span class="meta-label">Dernière analyse:</span>
            <span class="meta-value">${formatTimestamp(metadata.timestamp)}</span>
        </div>
        <div class="meta-item">
            <span class="meta-label">Modèle IA:</span>
            <span class="meta-value">${metadata.ai_model || 'N/A'}</span>
        </div>
        <div class="meta-item">
            <span class="meta-label">Total traité:</span>
            <span class="meta-value">${metadata.total_processed || 0}</span>
        </div>
        <div class="meta-item">
            <span class="meta-label">Statut pipeline:</span>
            <span class="meta-value">${metadata.pipeline_status || 'Inconnu'}</span>
        </div>
    `;
}

// Setup filter buttons
function setupFilters() {
    // Filters are already set up in renderVulnerabilityTable
}

// Setup refresh button
function setupRefreshButton() {
    const refreshBtn = document.createElement('button');
    refreshBtn.className = 'refresh-btn';
    refreshBtn.innerHTML = '🔄 Actualiser';
    refreshBtn.onclick = () => window.location.reload();
    
    // Add to header
    const header = document.querySelector('.header-right');
    if (header) {
        header.appendChild(refreshBtn);
    }
}

// Update timestamp
function updateTimestamp() {
    const tsElement = document.getElementById('header-ts');
    if (tsElement && reportData?.decision_metadata?.timestamp) {
        tsElement.textContent = formatTimestamp(reportData.decision_metadata.timestamp);
    }
}

// Start live updates
function startLiveUpdates() {
    // Update every 30 seconds
    setInterval(async () => {
        await loadReportData();
        renderDashboard();
    }, 30000);
}

// Utility functions
function formatTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    return new Date(timestamp).toLocaleString('fr-FR', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function showErrorMessage(message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message';
    errorDiv.innerHTML = `
        <div class="error-icon">⚠️</div>
        <div class="error-text">${message}</div>
    `;
    
    document.body.prepend(errorDiv);
    
    setTimeout(() => {
        errorDiv.remove();
    }, 5000);
}

// Get dummy data for demo
function getDummyData() {
    return {
        decision_metadata: {
            timestamp: new Date().toISOString(),
            total_processed: 0,
            decisions: { BLOQUER: 0, ALERTER: 0, PASSER: 0 },
            average_srp: 0.0,
            ai_model: 'Demo Mode',
            pipeline_status: 'En attente de données'
        },
        vulnerability_decisions: []
    };
}

console.log('✅ SecurFlow Dashboard loaded successfully!');
