/**
 * RedTeamKa - Dashboard Module
 */

const Dashboard = {
    /**
     * Load Dashboard View
     */
    async load() {
        const contentArea = document.getElementById('contentArea');
        if (!contentArea) return;
        
        contentArea.innerHTML = '<div class="loader"></div>';
        
        try {
            const [stats, recent, trends] = await Promise.all([
                this.fetchStats(),
                this.fetchRecent(),
                this.fetchTrends()
            ]);
            
            this.render(stats, recent, trends);
        } catch (error) {
            contentArea.innerHTML = '<div class="error">Failed to load dashboard</div>';
            console.error('Dashboard load error:', error);
        }
    },
    
    /**
     * Fetch Dashboard Statistics
     */
    async fetchStats() {
        return await RedTeamKa.apiGet('/dashboard/stats');
    },
    
    /**
     * Fetch Recent Scans
     */
    async fetchRecent() {
        return await RedTeamKa.apiGet('/dashboard/recent');
    },
    
    /**
     * Fetch Trends Data
     */
    async fetchTrends() {
        return await RedTeamKa.apiGet('/dashboard/trends');
    },
    
    /**
     * Render Dashboard
     */
    render(stats, recent, trends) {
        const contentArea = document.getElementById('contentArea');
        
        contentArea.innerHTML = `
            <!-- Stats Grid -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-chart-line"></i></div>
                    <div class="stat-title">Total Scans</div>
                    <div class="stat-value">${stats.scans?.total || 0}</div>
                    <div class="stat-trend">
                        <span class="stat-trend-up"><i class="fas fa-arrow-up"></i> +12%</span>
                        vs last month
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-bug"></i></div>
                    <div class="stat-title">Critical Findings</div>
                    <div class="stat-value">${stats.findings?.critical || 0}</div>
                    <div class="stat-trend">
                        <span class="stat-trend-${stats.findings?.critical > 0 ? 'up' : 'down'}">
                            <i class="fas fa-arrow-${stats.findings?.critical > 0 ? 'up' : 'down'}"></i> 
                            ${stats.findings?.critical > 0 ? '+' : ''}${stats.findings?.critical || 0}
                        </span>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-shield-alt"></i></div>
                    <div class="stat-title">High Findings</div>
                    <div class="stat-value">${stats.findings?.high || 0}</div>
                    <div class="stat-trend">
                        <span class="stat-trend-up"><i class="fas fa-arrow-up"></i> +5%</span>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-globe"></i></div>
                    <div class="stat-title">Unique Targets</div>
                    <div class="stat-value">${stats.unique_targets || 0}</div>
                    <div class="stat-trend">
                        <span class="stat-trend-up"><i class="fas fa-arrow-up"></i> +3</span>
                        new this week
                    </div>
                </div>
            </div>
            
            <!-- Charts Row -->
            <div class="charts-container">
                <div class="chart-card">
                    <div class="chart-title">Scan Trends (30 Days)</div>
                    <canvas id="trendChart"></canvas>
                </div>
                <div class="chart-card">
                    <div class="chart-title">Findings by Severity</div>
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
            
            <!-- Risk Meter -->
            <div class="risk-meter">
                <div class="risk-meter-title">
                    <span>Overall Security Risk Score</span>
                    <span id="riskScore">${this.calculateRiskScore(stats)}%</span>
                </div>
                <div class="risk-meter-bar">
                    <div class="risk-meter-fill" style="width: ${this.calculateRiskScore(stats)}%"></div>
                </div>
                <div class="risk-levels">
                    <span>Low</span>
                    <span>Medium</span>
                    <span>High</span>
                    <span>Critical</span>
                </div>
            </div>
            
            <!-- Recent Scans -->
            <div class="card">
                <div class="card-header">
                    <h2>Recent Scans</h2>
                    <button class="btn-secondary" onclick="window.RedTeamKa.switchView('scans')">View All</button>
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
                                    <th>Date</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody id="recentScansBody">
                                ${this.renderRecentScans(recent)}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <!-- Quick Actions -->
            <div class="quick-actions">
                <div class="quick-action-btn" onclick="window.RedTeamKa.switchView('scan')">
                    <i class="fas fa-search quick-action-icon"></i>
                    <span class="quick-action-label">New Scan</span>
                </div>
                <div class="quick-action-btn" onclick="window.RedTeamKa.switchView('reports')">
                    <i class="fas fa-file-alt quick-action-icon"></i>
                    <span class="quick-action-label">Generate Report</span>
                </div>
                <div class="quick-action-btn" onclick="window.RedTeamKa.switchView('labs')">
                    <i class="fas fa-flask quick-action-icon"></i>
                    <span class="quick-action-label">Launch Lab</span>
                </div>
                <div class="quick-action-btn" onclick="window.RedTeamKa.switchView('tools')">
                    <i class="fas fa-tools quick-action-icon"></i>
                    <span class="quick-action-label">Security Tools</span>
                </div>
            </div>
        `;
        
        // Render charts
        this.renderTrendChart(trends);
        this.renderSeverityChart(stats);
    },
    
    /**
     * Render Recent Scans Table
     */
    renderRecentScans(scans) {
        if (!scans || scans.length === 0) {
            return '<tr><td colspan="6" class="text-center">No scans yet</td></tr>';
        }
        
        return scans.map(scan => `
            <tr>
                <td>${scan.target}</td>
                <td>${scan.scan_type}</td>
                <td><span class="status-badge status-${scan.status}">${scan.status}</span></td>
                <td>${scan.findings_count}</td>
                <td>${new Date(scan.created_at).toLocaleDateString()}</td>
                <td>
                    <button class="btn-sm" onclick="window.Dashboard.viewScan('${scan.id}')">View</button>
                </td>
            </tr>
        `).join('');
    },
    
    /**
     * Render Trend Chart
     */
    renderTrendChart(trends) {
        const canvas = document.getElementById('trendChart');
        if (!canvas || !trends) return;
        
        const ctx = canvas.getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: trends.dates?.slice(0, 30).reverse() || [],
                datasets: [
                    {
                        label: 'Scans',
                        data: trends.scans?.slice(0, 30).reverse() || [],
                        borderColor: '#ff3366',
                        backgroundColor: 'rgba(255, 51, 102, 0.1)',
                        tension: 0.4,
                        fill: true
                    },
                    {
                        label: 'Findings',
                        data: trends.findings?.slice(0, 30).reverse() || [],
                        borderColor: '#00d4ff',
                        backgroundColor: 'rgba(0, 212, 255, 0.1)',
                        tension: 0.4,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#e0e0e0' }
                    }
                },
                scales: {
                    y: {
                        grid: { color: 'rgba(255,255,255,0.1)' },
                        ticks: { color: '#e0e0e0' }
                    },
                    x: {
                        grid: { color: 'rgba(255,255,255,0.1)' },
                        ticks: { color: '#e0e0e0', maxRotation: 45, minRotation: 45 }
                    }
                }
            }
        });
    },
    
    /**
     * Render Severity Chart
     */
    renderSeverityChart(stats) {
        const canvas = document.getElementById('severityChart');
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [
                        stats.findings?.critical || 0,
                        stats.findings?.high || 0,
                        stats.findings?.medium || 0,
                        stats.findings?.low || 0
                    ],
                    backgroundColor: ['#ff3366', '#ff6600', '#ffaa00', '#00ff88'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#e0e0e0' }
                    }
                }
            }
        });
    },
    
    /**
     * Calculate Risk Score
     */
    calculateRiskScore(stats) {
        const critical = stats.findings?.critical || 0;
        const high = stats.findings?.high || 0;
        const total = stats.findings?.total || 0;
        
        if (total === 0) return 0;
        
        const score = ((critical * 10 + high * 7) / (total * 10)) * 100;
        return Math.min(Math.round(score), 100);
    },
    
    /**
     * View Scan Details
     */
    viewScan(scanId) {
        if (window.Scans) {
            Scans.viewScan(scanId);
        }
    }
};

// Export module
window.Dashboard = Dashboard;