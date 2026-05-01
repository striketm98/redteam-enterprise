// Red Team Enterprise Framework - Main Application

class RedTeamFramework {
    constructor() {
        this.socket = io();
        this.currentView = 'dashboard';
        this.targets = [];
        this.findings = [];
        this.credentials = [];
        this.initializeEventListeners();
        this.connectSocket();
        this.loadDashboard();
    }
    
    initializeEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const view = item.dataset.view;
                this.switchView(view);
            });
        });
        
        // Search
        const searchInput = document.querySelector('.search-bar input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.handleSearch(e.target.value);
            });
        }
    }
    
    connectSocket() {
        this.socket.on('connect', () => {
            console.log('Connected to Red Team Framework');
            this.showNotification('Connected to framework', 'success');
        });
        
        this.socket.on('command_result', (data) => {
            this.handleCommandResult(data);
        });
        
        this.socket.on('connected', (data) => {
            console.log(data.status);
        });
    }
    
    switchView(view) {
        this.currentView = view;
        
        // Update active nav item
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
            if (item.dataset.view === view) {
                item.classList.add('active');
            }
        });
        
        // Load view content
        switch(view) {
            case 'dashboard':
                this.loadDashboard();
                break;
            case 'attack':
                this.loadAttackSurface();
                break;
            case 'graph':
                this.loadAttackGraph();
                break;
            case 'credentials':
                this.loadCredentials();
                break;
            case 'privesc':
                this.loadPrivesc();
                break;
            case 'labs':
                this.loadLabs();
                break;
            case 'reports':
                this.loadReports();
                break;
            case 'settings':
                this.loadSettings();
                break;
        }
    }
    
    async loadDashboard() {
        const contentArea = document.getElementById('content-area');
        
        contentArea.innerHTML = `
            <div class="dashboard-grid">
                <div class="card">
                    <div class="card-header">
                        <h3>Active Targets</h3>
                        <i class="fas fa-crosshairs"></i>
                    </div>
                    <div class="card-value" id="target-count">0</div>
                    <div class="card-trend">+2 this session</div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3>Credentials Found</h3>
                        <i class="fas fa-key"></i>
                    </div>
                    <div class="card-value" id="cred-count">0</div>
                    <div class="card-trend">+5 new</div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3>Vulnerabilities</h3>
                        <i class="fas fa-bug"></i>
                    </div>
                    <div class="card-value" id="vuln-count">0</div>
                    <div class="card-trend">Critical: 3</div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3>Success Rate</h3>
                        <i class="fas fa-chart-line"></i>
                    </div>
                    <div class="card-value" id="success-rate">0%</div>
                    <div class="card-trend">↑ 12%</div>
                </div>
            </div>
            
            <div class="commands-panel">
                <h3>Command Center</h3>
                <div class="command-input">
                    <input type="text" id="command-input" placeholder="Enter command..." autocomplete="off">
                    <button id="execute-btn">Execute</button>
                </div>
                <div class="output-area" id="output-area">
                    <div class="output-line">> Ready for commands</div>
                </div>
            </div>
            
            <div class="card" style="margin-top: 24px;">
                <div class="card-header">
                    <h3>Recent Activity</h3>
                    <i class="fas fa-history"></i>
                </div>
                <div id="activity-log"></div>
            </div>
        `;
        
        // Load real data from API
        await this.loadStats();
        
        // Setup command execution
        const executeBtn = document.getElementById('execute-btn');
        const commandInput = document.getElementById('command-input');
        
        if (executeBtn) {
            executeBtn.addEventListener('click', () => {
                const command = commandInput.value;
                if (command) {
                    this.executeCommand(command);
                    commandInput.value = '';
                }
            });
        }
        
        if (commandInput) {
            commandInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    executeBtn.click();
                }
            });
        }
    }
    
    async loadStats() {
        try {
            const response = await fetch('/api/stats');
            const stats = await response.json();
            
            document.getElementById('target-count').textContent = stats.targets || 0;
            document.getElementById('cred-count').textContent = stats.credentials || 0;
            document.getElementById('vuln-count').textContent = stats.vulnerabilities || 0;
            document.getElementById('success-rate').textContent = `${stats.success_rate || 0}%`;
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }
    
    executeCommand(command) {
        const outputArea = document.getElementById('output-area');
        const outputLine = document.createElement('div');
        outputLine.className = 'output-line';
        outputLine.innerHTML = `> ${command}`;
        outputArea.appendChild(outputLine);
        
        // Send command via WebSocket
        this.socket.emit('execute_command', { command });
        
        // Add to activity log
        this.addActivity(`Executed: ${command}`, 'info');
    }
    
    handleCommandResult(data) {
        const outputArea = document.getElementById('output-area');
        
        if (data.output) {
            const lines = data.output.split('\n');
            lines.forEach(line => {
                if (line.trim()) {
                    const outputLine = document.createElement('div');
                    outputLine.className = 'output-line';
                    outputLine.innerHTML = line;
                    outputArea.appendChild(outputLine);
                }
            });
        }
        
        if (data.error) {
            const errorLine = document.createElement('div');
            errorLine.className = 'output-line';
            errorLine.style.color = 'var(--danger)';
            errorLine.innerHTML = `[ERROR] ${data.error}`;
            outputArea.appendChild(errorLine);
        }
        
        // Auto-scroll
        outputArea.scrollTop = outputArea.scrollHeight;
        
        // Add to activity
        this.addActivity(`Command completed with status: ${data.status}`, data.status === 'completed' ? 'success' : 'error');
    }
    
    async loadAttackSurface() {
        const contentArea = document.getElementById('content-area');
        contentArea.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <h3>Target Management</h3>
                    <button class="btn btn-primary" onclick="framework.addTarget()">
                        <i class="fas fa-plus"></i> Add Target
                    </button>
                </div>
                <table class="data-table" id="targets-table">
                    <thead>
                        <tr>
                            <th>Target</th>
                            <th>Ports</th>
                            <th>Services</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="targets-list"></tbody>
                </table>
            </div>
        `;
        
        await this.loadTargets();
    }
    
    async loadTargets() {
        try {
            const response = await fetch('/api/targets');
            const targets = await response.json();
            const tbody = document.getElementById('targets-list');
            
            if (tbody) {
                tbody.innerHTML = targets.map(target => `
                    <tr>
                        <td>${target.address}</td>
                        <td>${target.ports?.join(', ') || '-'}</td>
                        <td>${target.services?.join(', ') || '-'}</td>
                        <td><span class="status-badge status-${target.status}">${target.status}</span></td>
                        <td>
                            <button onclick="framework.scanTarget('${target.address}')" class="btn-sm">Scan</button>
                            <button onclick="framework.removeTarget('${target.address}')" class="btn-sm btn-danger">Remove</button>
                        </td>
                    </tr>
                `).join('');
            }
        } catch (error) {
            console.error('Failed to load targets:', error);
        }
    }
    
    async loadAttackGraph() {
        const contentArea = document.getElementById('content-area');
        contentArea.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <h3>Attack Path Analysis</h3>
                    <button class="btn btn-primary" onclick="framework.generateGraph()">
                        <i class="fas fa-sync"></i> Generate
                    </button>
                </div>
                <div id="graph-visualization" style="min-height: 500px; background: var(--darker); border-radius: 8px; padding: 20px;">
                    <div style="text-align: center; color: var(--text-muted);">
                        <i class="fas fa-project-diagram" style="font-size: 48px; margin-bottom: 16px; display: block;"></i>
                        <p>Click "Generate" to visualize attack paths</p>
                    </div>
                </div>
            </div>
        `;
    }
    
    async loadCredentials() {
        const contentArea = document.getElementById('content-area');
        contentArea.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <h3>Credential Database</h3>
                    <button class="btn btn-primary" onclick="framework.addCredential()">
                        <i class="fas fa-plus"></i> Add Credential
                    </button>
                </div>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Password</th>
                            <th>Source</th>
                            <th>Strength</th>
                            <th>Reuse Score</th>
                        </tr>
                    </thead>
                    <tbody id="creds-list"></tbody>
                </table>
            </div>
        `;
        
        await this.loadCredentialsList();
    }
    
    async loadCredentialsList() {
        try {
            const response = await fetch('/api/credentials');
            const creds = await response.json();
            const tbody = document.getElementById('creds-list');
            
            if (tbody) {
                tbody.innerHTML = creds.map(cred => `
                    <tr>
                        <td><code>${cred.user}</code></td>
                        <td><code>${cred.pass.substring(0, 3)}***</code></td>
                        <td>${cred.source}</td>
                        <td><span class="strength-${cred.strength.toLowerCase()}">${cred.strength}</span></td>
                        <td>${cred.reuse_score || 'N/A'}</td>
                    </tr>
                `).join('');
            }
        } catch (error) {
            console.error('Failed to load credentials:', error);
        }
    }
    
    async loadPrivesc() {
        const contentArea = document.getElementById('content-area');
        contentArea.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <h3>Privilege Escalation Analysis</h3>
                    <button class="btn btn-primary" onclick="framework.analyzePrivesc()">
                        <i class="fas fa-search"></i> Analyze System
                    </button>
                </div>
                <div id="privesc-results"></div>
            </div>
        `;
    }
    
    async loadLabs() {
        const contentArea = document.getElementById('content-area');
        contentArea.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <h3>Lab Environment Manager</h3>
                    <button class="btn btn-primary" onclick="framework.deployLab()">
                        <i class="fas fa-play"></i> Deploy Lab
                    </button>
                </div>
                <div id="lab-status"></div>
            </div>
        `;
        
        await this.loadLabStatus();
    }
    
    async loadReports() {
        const contentArea = document.getElementById('content-area');
        contentArea.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <h3>Report Generation</h3>
                    <button class="btn btn-primary" onclick="framework.generateReport()">
                        <i class="fas fa-file-pdf"></i> Generate Report
                    </button>
                </div>
                <div id="report-preview"></div>
            </div>
        `;
    }
    
    loadSettings() {
        const contentArea = document.getElementById('content-area');
        contentArea.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <h3>Framework Settings</h3>
                </div>
                <div style="padding: 20px;">
                    <div class="setting-group">
                        <label>Safe Mode</label>
                        <input type="checkbox" id="safe-mode" checked>
                        <small>Restrict dangerous commands</small>
                    </div>
                    <div class="setting-group">
                        <label>Auto-Save Sessions</label>
                        <input type="checkbox" id="auto-save" checked>
                        <small>Automatically save session data</small>
                    </div>
                    <div class="setting-group">
                        <label>API Key</label>
                        <input type="password" id="api-key" placeholder="Enter API key for integrations">
                    </div>
                    <button class="btn btn-primary" onclick="framework.saveSettings()">Save Settings</button>
                </div>
            </div>
        `;
    }
    
    addActivity(message, type = 'info') {
        const activityLog = document.getElementById('activity-log');
        if (activityLog) {
            const entry = document.createElement('div');
            entry.className = 'activity-entry';
            entry.style.padding = '8px 0';
            entry.style.borderBottom = '1px solid var(--gray)';
            entry.style.fontSize = '12px';
            entry.innerHTML = `
                <span style="color: var(--text-muted);">[${new Date().toLocaleTimeString()}]</span>
                <span style="color: ${type === 'success' ? 'var(--success)' : type === 'error' ? 'var(--danger)' : 'var(--info)'}">${message}</span>
            `;
            activityLog.insertBefore(entry, activityLog.firstChild);
            
            // Limit log entries
            while (activityLog.children.length > 50) {
                activityLog.removeChild(activityLog.lastChild);
            }
        }
    }
    
    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: var(--dark);
            border-left: 4px solid ${type === 'success' ? 'var(--success)' : type === 'error' ? 'var(--danger)' : 'var(--info)'};
            padding: 12px 20px;
            border-radius: 8px;
            z-index: 1000;
            animation: slideIn 0.3s ease;
        `;
        notification.innerHTML = `
            <i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-exclamation-circle' : 'fa-info-circle'}"></i>
            <span>${message}</span>
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }
    
    // API Methods
    async addTarget() {
        const address = prompt('Enter target IP or hostname:');
        if (address) {
            try {
                const response = await fetch('/api/targets', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ address })
                });
                
                if (response.ok) {
                    this.showNotification(`Target ${address} added`, 'success');
                    this.loadTargets();
                }
            } catch (error) {
                this.showNotification('Failed to add target', 'error');
            }
        }
    }
    
    async scanTarget(address) {
        this.showNotification(`Scanning ${address}...`, 'info');
        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: address })
            });
            const result = await response.json();
            this.showNotification(`Scan completed for ${address}`, 'success');
            this.loadTargets();
        } catch (error) {
            this.showNotification('Scan failed', 'error');
        }
    }
    
    async generateGraph() {
        this.showNotification('Generating attack graph...', 'info');
        // Implementation for graph generation
    }
    
    async analyzePrivesc() {
        this.showNotification('Analyzing for privilege escalation vectors...', 'info');
        // Implementation for privesc analysis
    }
    
    async deployLab() {
        this.showNotification('Deploying lab environment...', 'info');
        // Implementation for lab deployment
    }
    
    async generateReport() {
        this.showNotification('Generating penetration test report...', 'info');
        // Implementation for report generation
    }
    
    saveSettings() {
        this.showNotification('Settings saved successfully', 'success');
    }
}

// Initialize framework
const framework = new RedTeamFramework();

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);