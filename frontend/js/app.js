/**
 * RedTeamKa - Main Application Entry Point
 * Enterprise Red Team Automation Platform
 */

// Global App Object
const RedTeamKa = {
    // Configuration
    config: {
        apiBase: '/api',
        wsBase: window.location.origin,
        version: '3.0.0',
        debug: false
    },
    
    // State
    state: {
        token: null,
        user: null,
        currentView: 'dashboard',
        isLoading: false,
        notifications: [],
        webSocket: null
    },
    
    // DOM Elements
    elements: {
        loginScreen: null,
        dashboard: null,
        sidebar: null,
        mainContent: null,
        contentArea: null,
        pageTitle: null,
        userName: null,
        userRole: null,
        userAvatar: null,
        menuToggle: null,
        logoutBtn: null
    },
    
    /**
     * Initialize Application
     */
    async init() {
        console.log('🚀 RedTeamKa v' + this.config.version + ' initializing...');
        
        this.cacheElements();
        this.bindEvents();
        await this.checkAuth();
        this.initWebSocket();
        
        console.log('✅ RedTeamKa initialized');
    },
    
    /**
     * Cache DOM Elements
     */
    cacheElements() {
        this.elements = {
            loginScreen: document.getElementById('loginScreen'),
            dashboard: document.getElementById('dashboard'),
            sidebar: document.getElementById('sidebar'),
            mainContent: document.getElementById('mainContent'),
            contentArea: document.getElementById('contentArea'),
            pageTitle: document.getElementById('pageTitle'),
            userName: document.getElementById('userName'),
            userRole: document.getElementById('userRole'),
            userAvatar: document.getElementById('userAvatar'),
            menuToggle: document.getElementById('menuToggle'),
            logoutBtn: document.getElementById('logoutBtn'),
            loginForm: document.getElementById('loginForm'),
            loginUsername: document.getElementById('loginUsername'),
            loginPassword: document.getElementById('loginPassword')
        };
    },
    
    /**
     * Bind Event Listeners
     */
    bindEvents() {
        // Login form
        if (this.elements.loginForm) {
            this.elements.loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.login();
            });
        }
        
        // Logout button
        if (this.elements.logoutBtn) {
            this.elements.logoutBtn.addEventListener('click', () => {
                this.logout();
            });
        }
        
        // Menu toggle for mobile
        if (this.elements.menuToggle) {
            this.elements.menuToggle.addEventListener('click', () => {
                this.toggleMobileMenu();
            });
        }
        
        // Navigation items
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const view = item.dataset.view;
                if (view) {
                    this.switchView(view);
                }
            });
        });
        
        // Close mobile menu on window resize
        window.addEventListener('resize', () => {
            if (window.innerWidth > 768) {
                this.closeMobileMenu();
            }
        });
    },
    
    /**
     * Toggle Mobile Menu
     */
    toggleMobileMenu() {
        this.elements.sidebar.classList.toggle('mobile-open');
    },
    
    /**
     * Close Mobile Menu
     */
    closeMobileMenu() {
        this.elements.sidebar.classList.remove('mobile-open');
    },
    
    /**
     * Initialize WebSocket Connection
     */
    initWebSocket() {
        this.state.webSocket = io();
        
        this.state.webSocket.on('connect', () => {
            console.log('🔌 WebSocket connected');
            this.showNotification('Connected to server', 'success');
        });
        
        this.state.webSocket.on('disconnect', () => {
            console.log('🔌 WebSocket disconnected');
            this.showNotification('Disconnected from server', 'warning');
        });
        
        this.state.webSocket.on('scan_status', (data) => {
            this.handleScanStatus(data);
        });
        
        this.state.webSocket.on('scan_completed', (data) => {
            this.handleScanCompleted(data);
        });
        
        this.state.webSocket.on('scan_failed', (data) => {
            this.handleScanFailed(data);
        });
        
        this.state.webSocket.on('connected', (data) => {
            console.log('📡 Server message:', data.message);
        });
    },
    
    /**
     * Check Authentication Status
     */
    async checkAuth() {
        const token = localStorage.getItem('redteamka_token');
        const savedUser = localStorage.getItem('redteamka_user');
        
        if (token && savedUser) {
            this.state.token = token;
            this.state.user = JSON.parse(savedUser);
            
            try {
                const response = await this.apiGet('/auth/me');
                if (response.ok) {
                    this.showDashboard();
                    return;
                }
            } catch (error) {
                console.error('Auth check failed:', error);
            }
        }
        
        this.showLogin();
    },
    
    /**
     * Show Login Screen
     */
    showLogin() {
        if (this.elements.loginScreen) {
            this.elements.loginScreen.style.display = 'flex';
        }
        if (this.elements.dashboard) {
            this.elements.dashboard.style.display = 'none';
        }
    },
    
    /**
     * Show Dashboard
     */
    showDashboard() {
        if (this.elements.loginScreen) {
            this.elements.loginScreen.style.display = 'none';
        }
        if (this.elements.dashboard) {
            this.elements.dashboard.style.display = 'block';
        }
        
        this.updateUserInfo();
        this.updateRoleBasedUI();
        this.switchView('dashboard');
    },
    
    /**
     * Update User Information in UI
     */
    updateUserInfo() {
        if (this.elements.userName) {
            this.elements.userName.textContent = this.state.user.username;
        }
        
        if (this.elements.userAvatar) {
            const initial = this.state.user.username.substring(0, 2).toUpperCase();
            this.elements.userAvatar.textContent = initial;
        }
        
        if (this.elements.userRole) {
            const roleText = this.state.user.role === 'pentest' ? 'PENTESTER' : 'CLIENT';
            this.elements.userRole.textContent = roleText;
            if (this.state.user.role === 'client') {
                this.elements.userRole.classList.add('client');
            }
        }
    },
    
    /**
     * Update UI Based on User Role
     */
    updateRoleBasedUI() {
        const isPentest = this.state.user.role === 'pentest';
        
        document.querySelectorAll('.pentest-only').forEach(el => {
            el.style.display = isPentest ? 'flex' : 'none';
        });
    },
    
    /**
     * Login User
     */
    async login() {
        const username = this.elements.loginUsername?.value;
        const password = this.elements.loginPassword?.value;
        
        if (!username || !password) {
            this.showNotification('Please enter username and password', 'error');
            return;
        }
        
        this.setLoading(true);
        
        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.state.token = data.token;
                this.state.user = data.user;
                
                localStorage.setItem('redteamka_token', this.state.token);
                localStorage.setItem('redteamka_user', JSON.stringify(this.state.user));
                
                this.showNotification(`Welcome back, ${data.user.username}!`, 'success');
                this.showDashboard();
            } else {
                this.showNotification(data.message || 'Login failed', 'error');
            }
        } catch (error) {
            this.showNotification('Login error: ' + error.message, 'error');
        } finally {
            this.setLoading(false);
        }
    },
    
    /**
     * Logout User
     */
    async logout() {
        if (this.state.token) {
            try {
                await this.apiPost('/auth/logout');
            } catch (error) {
                console.error('Logout error:', error);
            }
        }
        
        localStorage.removeItem('redteamka_token');
        localStorage.removeItem('redteamka_user');
        
        this.state.token = null;
        this.state.user = null;
        
        if (this.state.webSocket) {
            this.state.webSocket.disconnect();
        }
        
        this.showLogin();
        this.clearForms();
        this.showNotification('Logged out successfully', 'success');
    },
    
    /**
     * Switch View
     */
    switchView(view) {
        this.state.currentView = view;
        
        // Update active nav item
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
            if (item.dataset.view === view) {
                item.classList.add('active');
            }
        });
        
        // Update page title
        const titles = {
            dashboard: 'Dashboard',
            scan: 'New Security Scan',
            scans: 'Scan History',
            exploits: 'Exploit Framework',
            findings: 'Security Findings',
            reports: 'Reports',
            labs: 'Lab Environment',
            tools: 'Security Tools',
            admin: 'Administration'
        };
        
        if (this.elements.pageTitle) {
            this.elements.pageTitle.textContent = titles[view] || 'Dashboard';
        }
        
        // Load view content
        this.loadView(view);
    },
    
    /**
     * Load View Content
     */
    loadView(view) {
        if (!this.elements.contentArea) return;
        
        this.elements.contentArea.innerHTML = '<div class="loader"></div>';
        
        switch(view) {
            case 'dashboard':
                if (window.Dashboard) Dashboard.load();
                break;
            case 'scan':
                if (window.Scans) Scans.loadScanForm();
                break;
            case 'scans':
                if (window.Scans) Scans.loadScansList();
                break;
            case 'exploits':
                if (window.Exploits) Exploits.load();
                break;
            case 'findings':
                if (window.Findings) Findings.load();
                break;
            case 'reports':
                if (window.Reports) Reports.load();
                break;
            case 'labs':
                if (window.Labs) Labs.load();
                break;
            case 'tools':
                if (window.Tools) Tools.load();
                break;
            case 'admin':
                if (window.Admin) Admin.load();
                break;
            default:
                if (window.Dashboard) Dashboard.load();
        }
    },
    
    /**
     * API GET Request
     */
    async apiGet(endpoint) {
        return this.apiRequest('GET', endpoint);
    },
    
    /**
     * API POST Request
     */
    async apiPost(endpoint, data = null) {
        return this.apiRequest('POST', endpoint, data);
    },
    
    /**
     * API PUT Request
     */
    async apiPut(endpoint, data = null) {
        return this.apiRequest('PUT', endpoint, data);
    },
    
    /**
     * API DELETE Request
     */
    async apiDelete(endpoint) {
        return this.apiRequest('DELETE', endpoint);
    },
    
    /**
     * Generic API Request
     */
    async apiRequest(method, endpoint, data = null) {
        const url = this.config.apiBase + endpoint;
        const options = {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        };
        
        if (this.state.token) {
            options.headers['Authorization'] = `Bearer ${this.state.token}`;
        }
        
        if (data) {
            options.body = JSON.stringify(data);
        }
        
        try {
            const response = await fetch(url, options);
            const result = await response.json();
            
            if (!response.ok) {
                throw new Error(result.message || result.error || 'Request failed');
            }
            
            return result;
        } catch (error) {
            console.error(`API ${method} ${endpoint} error:`, error);
            throw error;
        }
    },
    
    /**
     * Handle Scan Status Update
     */
    handleScanStatus(data) {
        const statusDiv = document.getElementById('scanStatus');
        const statusMessage = document.getElementById('scanStatusMessage');
        
        if (statusDiv && statusMessage) {
            statusDiv.classList.remove('hidden');
            statusMessage.textContent = data.message;
        }
        
        this.showNotification(data.message, 'info');
    },
    
    /**
     * Handle Scan Completion
     */
    handleScanCompleted(data) {
        this.showNotification(data.message, 'success');
        
        if (this.state.currentView === 'scans') {
            if (window.Scans) Scans.loadScansList();
        }
        
        if (this.state.currentView === 'dashboard') {
            if (window.Dashboard) Dashboard.load();
        }
    },
    
    /**
     * Handle Scan Failure
     */
    handleScanFailed(data) {
        this.showNotification(`Scan failed: ${data.error}`, 'error');
        
        const statusDiv = document.getElementById('scanStatus');
        if (statusDiv) {
            statusDiv.classList.add('hidden');
        }
    },
    
    /**
     * Show Notification
     */
    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        
        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };
        
        notification.innerHTML = `
            <i class="fas ${icons[type] || icons.info}"></i>
            <span>${message}</span>
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.classList.add('fade-out');
            setTimeout(() => notification.remove(), 300);
        }, 5000);
    },
    
    /**
     * Set Loading State
     */
    setLoading(isLoading) {
        this.state.isLoading = isLoading;
        
        const loader = document.querySelector('.global-loader');
        if (isLoading) {
            if (!loader) {
                const loaderDiv = document.createElement('div');
                loaderDiv.className = 'global-loader';
                loaderDiv.innerHTML = '<div class="loader"></div>';
                document.body.appendChild(loaderDiv);
            }
        } else if (loader) {
            loader.remove();
        }
    },
    
    /**
     * Clear Form Inputs
     */
    clearForms() {
        if (this.elements.loginUsername) {
            this.elements.loginUsername.value = '';
        }
        if (this.elements.loginPassword) {
            this.elements.loginPassword.value = '';
        }
    },
    
    /**
     * Get Current User
     */
    getCurrentUser() {
        return this.state.user;
    },
    
    /**
     * Get Auth Token
     */
    getToken() {
        return this.state.token;
    },
    
    /**
     * Check if User is Pentester
     */
    isPentester() {
        return this.state.user && this.state.user.role === 'pentest';
    },
    
    /**
     * Check if User is Client
     */
    isClient() {
        return this.state.user && this.state.user.role === 'client';
    }
};

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.RedTeamKa = RedTeamKa;
    RedTeamKa.init();
});