/**
 * RedTeamKa - Findings Module
 */

const Findings = {
    /**
     * Load Findings View
     */
    async load() {
        const contentArea = document.getElementById('contentArea');
        if (!contentArea) return;
        
        contentArea.innerHTML = '<div class="loader"></div>';
        
        try {
            const findings = await RedTeamKa.apiGet('/findings');
            const stats = await this.calculateStats(findings);
            this.render(findings, stats);
        } catch (error) {
            contentArea.innerHTML = '<div class="error">Failed to load findings</div>';
        }
    },
    
    /**
     * Calculate Statistics
     */
    async calculateStats(findings) {
        return {
            total: findings.length,
            critical: findings.filter(f => f.severity === 'Critical').length,
            high: findings.filter(f => f.severity === 'High').length,
            medium: findings.filter(f => f.severity === 'Medium').length,
            low: findings.filter(f => f.severity === 'Low').length
        };
    },
    
    /**
     * Render Findings View
     */
    render(findings, stats) {
        const contentArea = document.getElementById('contentArea');
        
        contentArea.innerHTML = `
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-title">Total Findings</div>
                    <div class="stat-value">${stats.total}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">Critical</div>
                    <div class="stat-value" style="color: #ff3366;">${stats.critical}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">High</div>
                    <div class="stat-value" style="color: #ff6600;">${stats.high}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">Medium / Low</div>
                    <div class="stat-value">${stats.medium + stats.low}</div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h2>Security Findings</h2>
                    <button class="btn-secondary" onclick="Findings.exportCSV()">
                        <i class="fas fa-download"></i> Export CSV
                    </button>
                </div>
                <div class="card-body">
                    <div class="filters">
                        <select id="severityFilter" onchange="Findings.filterBySeverity()">
                            <option value="all">All Severities</option>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                        </select>
                        <input type="text" id="searchFindings" placeholder="Search findings..." onkeyup="Findings.search()">
                    </div>
                    
                    <div id="findingsList">
                        ${this.renderFindingsList(findings)}
                    </div>
                </div>
            </div>
        `;
    },
    
    /**
     * Render Findings List
     */
    renderFindingsList(findings) {
        if (!findings || findings.length === 0) {
            return '<div class="text-center">No findings found</div>';
        }
        
        return findings.map(finding => `
            <div class="finding finding-${finding.severity.toLowerCase()}" data-severity="${finding.severity}" data-title="${finding.title.toLowerCase()}">
                <div class="finding-header">
                    <span class="severity-badge severity-${finding.severity.toLowerCase()}">${finding.severity}</span>
                    <span class="finding-title">${finding.title}</span>
                    <span class="finding-target">${finding.scan_target || 'N/A'}</span>
                </div>
                <div class="finding-body">
                    <p><strong>Description:</strong> ${finding.description}</p>
                    <p><strong>Remediation:</strong> ${finding.remediation}</p>
                    <p><strong>CVSS Score:</strong> ${finding.cvss_score || 'N/A'}</p>
                    <p><strong>Discovered:</strong> ${new Date(finding.created_at).toLocaleString()}</p>
                    <button class="btn-sm" onclick="Findings.acknowledge('${finding.id}')">Acknowledge</button>
                </div>
            </div>
        `).join('');
    },
    
    /**
     * Filter by Severity
     */
    filterBySeverity() {
        const severity = document.getElementById('severityFilter').value;
        const findings = document.querySelectorAll('.finding');
        
        findings.forEach(finding => {
            if (severity === 'all' || finding.dataset.severity.toLowerCase() === severity) {
                finding.style.display = 'block';
            } else {
                finding.style.display = 'none';
            }
        });
    },
    
    /**
     * Search Findings
     */
    search() {
        const searchTerm = document.getElementById('searchFindings').value.toLowerCase();
        const findings = document.querySelectorAll('.finding');
        
        findings.forEach(finding => {
            const title = finding.dataset.title;
            if (title.includes(searchTerm) || searchTerm === '') {
                finding.style.display = 'block';
            } else {
                finding.style.display = 'none';
            }
        });
    },
    
    /**
     * Acknowledge Finding
     */
    async acknowledge(findingId) {
        try {
            await RedTeamKa.apiPost(`/findings/${findingId}/acknowledge`);
            RedTeamKa.showNotification('Finding acknowledged', 'success');
            this.load();
        } catch (error) {
            RedTeamKa.showNotification('Failed to acknowledge finding', 'error');
        }
    },
    
    /**
     * Export to CSV
     */
    async exportCSV() {
        window.open('/api/findings/export/csv', '_blank');
    }
};

// Export module
window.Findings = Findings;