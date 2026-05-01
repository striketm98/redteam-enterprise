/**
 * RedTeamKa - Scans Module
 */

const Scans = {
    /**
     * Load Scans List
     */
    async loadScansList() {
        const contentArea = document.getElementById('contentArea');
        if (!contentArea) return;
        
        contentArea.innerHTML = '<div class="loader"></div>';
        
        try {
            const scans = await RedTeamKa.apiGet('/scans');
            this.renderScansList(scans);
        } catch (error) {
            contentArea.innerHTML = '<div class="error">Failed to load scans</div>';
        }
    },
    
    /**
     * Render Scans List
     */
    renderScansList(scans) {
        const contentArea = document.getElementById('contentArea');
        const isPentest = RedTeamKa.isPentester();
        
        contentArea.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <h2>Scan History</h2>
                    ${isPentest ? '<button class="btn-primary" onclick="Scans.loadScanForm()">New Scan</button>' : ''}
                </div>
                <div class="card-body">
                    <div class="scans-table">
                        <table>
                            <thead>
                                <tr>
                                    <th>Target</th>
                                    <th>Type</th>
                                    <th>Status</th>
                                    <th>Findings</th>
                                    <th>Duration</th>
                                    <th>Date</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${scans.map(scan => this.renderScanRow(scan)).join('')}
                                ${scans.length === 0 ? '<tr><td colspan="7" class="text-center">No scans yet</td></tr>' : ''}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    },
    
    /**
     * Render Scan Row
     */
    renderScanRow(scan) {
        const isPentest = RedTeamKa.isPentester();
        
        return `
            <tr>
                <td><strong>${scan.target}</strong></td>
                <td><span class="badge">${scan.scan_type}</span></td>
                <td><span class="status-badge status-${scan.status}">${scan.status}</span></td>
                <td>${scan.findings_count}</td>
                <td>${scan.duration ? scan.duration + 's' : '-'}</td>
                <td>${new Date(scan.created_at).toLocaleString()}</td>
                <td>
                    <button class="btn-sm" onclick="Scans.viewScan('${scan.id}')">View</button>
                    ${isPentest ? `<button class="btn-sm" onclick="Scans.generateReport('${scan.id}')">Report</button>` : ''}
                    <button class="btn-sm" onclick="Scans.deleteScan('${scan.id}')">Delete</button>
                </td>
            </tr>
        `;
    },
    
    /**
     * Load Scan Form
     */
    loadScanForm() {
        if (!RedTeamKa.isPentester()) {
            RedTeamKa.showNotification('Only pentesters can perform scans', 'error');
            return;
        }
        
        const contentArea = document.getElementById('contentArea');
        
        contentArea.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <h2>New Security Scan</h2>
                </div>
                <div class="card-body">
                    <form id="scanForm">
                        <div class="form-group">
                            <label>Target IP / Domain</label>
                            <input type="text" id="scanTarget" placeholder="e.g., 192.168.1.1 or example.com" required>
                        </div>
                        <div class="form-group">
                            <label>Scan Type</label>
                            <select id="scanType">
                                <option value="quick">Quick Scan (Common Ports)</option>
                                <option value="full">Full Scan (All Ports + Services)</option>
                                <option value="web">Web Scan (HTTP/HTTPS)</option>
                                <option value="network">Network Scan (CIDR Range)</option>
                            </select>
                        </div>
                        <button type="submit" class="btn-primary">Start Scan</button>
                    </form>
                    <div id="scanStatus" class="hidden mt-20">
                        <div class="loader"></div>
                        <p id="scanStatusMessage" class="text-center">Scanning in progress...</p>
                    </div>
                </div>
            </div>
        `;
        
        document.getElementById('scanForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.startScan();
        });
    },
    
    /**
     * Start Scan
     */
    async startScan() {
        const target = document.getElementById('scanTarget').value;
        const scanType = document.getElementById('scanType').value;
        
        if (!target) {
            RedTeamKa.showNotification('Please enter a target', 'error');
            return;
        }
        
        const statusDiv = document.getElementById('scanStatus');
        statusDiv.classList.remove('hidden');
        
        try {
            const result = await RedTeamKa.apiPost('/scans/start', { target, scan_type: scanType });
            
            if (result.success) {
                RedTeamKa.showNotification(`Scan started on ${target}`, 'success');
                
                // Poll for status
                this.pollScanStatus(result.scan_id);
            }
        } catch (error) {
            RedTeamKa.showNotification('Failed to start scan: ' + error.message, 'error');
            statusDiv.classList.add('hidden');
        }
    },
    
    /**
     * Poll Scan Status
     */
    async pollScanStatus(scanId) {
        const interval = setInterval(async () => {
            try {
                const status = await RedTeamKa.apiGet(`/scans/${scanId}/status`);
                
                if (status.status === 'completed') {
                    clearInterval(interval);
                    RedTeamKa.showNotification('Scan completed!', 'success');
                    this.loadScansList();
                } else if (status.status === 'failed') {
                    clearInterval(interval);
                    RedTeamKa.showNotification('Scan failed', 'error');
                    this.loadScansList();
                }
            } catch (error) {
                clearInterval(interval);
            }
        }, 2000);
    },
    
    /**
     * View Scan Details
     */
    async viewScan(scanId) {
        const contentArea = document.getElementById('contentArea');
        contentArea.innerHTML = '<div class="loader"></div>';
        
        try {
            const scan = await RedTeamKa.apiGet(`/scans/${scanId}/results`);
            this.renderScanDetails(scan);
        } catch (error) {
            contentArea.innerHTML = '<div class="error">Failed to load scan details</div>';
        }
    },
    
    /**
     * Render Scan Details
     */
    renderScanDetails(scan) {
        const contentArea = document.getElementById('contentArea');
        
        contentArea.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <h2>Scan Results: ${scan.target}</h2>
                    <button class="btn-secondary" onclick="Scans.loadScansList()">Back</button>
                </div>
                <div class="card-body">
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-title">Scan Type</div>
                            <div class="stat-value">${scan.scan_type}</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-title">Status</div>
                            <div class="stat-value ${scan.status}">${scan.status}</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-title">Duration</div>
                            <div class="stat-value">${scan.duration || '-'}s</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-title">Findings</div>
                            <div class="stat-value">${scan.findings?.length || 0}</div>
                        </div>
                    </div>
                    
                    <h3>Open Ports</h3>
                    <div class="open-ports">
                        ${this.renderOpenPorts(scan.results?.open_ports || [])}
                    </div>
                    
                    <h3 class="mt-20">Findings</h3>
                    <div class="findings-list">
                        ${this.renderFindings(scan.findings || [])}
                    </div>
                    
                    ${scan.ai_analysis ? `
                        <h3 class="mt-20">AI Analysis</h3>
                        <div class="card bg-dark">
                            <div class="card-body">
                                <p><strong>Risk Score:</strong> ${scan.ai_analysis.risk_score}%</p>
                                <p><strong>Summary:</strong> ${scan.ai_analysis.summary}</p>
                                <p><strong>Recommendations:</strong></p>
                                <ul>
                                    ${scan.ai_analysis.recommendations?.map(r => `<li>${r}</li>`).join('')}
                                </ul>
                            </div>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    },
    
    /**
     * Render Open Ports
     */
    renderOpenPorts(ports) {
        if (!ports || ports.length === 0) {
            return '<p>No open ports detected.</p>';
        }
        
        return `
            <div class="port-list">
                ${ports.map(port => `
                    <span class="port-badge">Port ${port}</span>
                `).join('')}
            </div>
        `;
    },
    
    /**
     * Render Findings
     */
    renderFindings(findings) {
        if (!findings || findings.length === 0) {
            return '<p>No findings detected.</p>';
        }
        
        return findings.map(finding => `
            <div class="finding finding-${finding.severity.toLowerCase()}">
                <div class="finding-header">
                    <span class="severity-badge severity-${finding.severity.toLowerCase()}">${finding.severity}</span>
                    <span class="finding-title">${finding.title}</span>
                </div>
                <div class="finding-body">
                    <p><strong>Description:</strong> ${finding.description}</p>
                    <p><strong>Remediation:</strong> ${finding.remediation}</p>
                </div>
            </div>
        `).join('');
    },
    
    /**
     * Generate Report
     */
    async generateReport(scanId) {
        try {
            const result = await RedTeamKa.apiPost('/reports/generate', {
                scan_ids: [scanId],
                type: 'technical',
                format: 'html'
            });
            
            if (result.success) {
                RedTeamKa.showNotification('Report generated', 'success');
                window.open(result.download_url, '_blank');
            }
        } catch (error) {
            RedTeamKa.showNotification('Failed to generate report', 'error');
        }
    },
    
    /**
     * Delete Scan
     */
    async deleteScan(scanId) {
        if (!confirm('Are you sure you want to delete this scan?')) return;
        
        try {
            await RedTeamKa.apiDelete(`/scans/${scanId}`);
            RedTeamKa.showNotification('Scan deleted', 'success');
            this.loadScansList();
        } catch (error) {
            RedTeamKa.showNotification('Failed to delete scan', 'error');
        }
    }
};

// Export module
window.Scans = Scans;