#!/bin/bash

# Red Team Enterprise Framework - Fixed Deployment Script
# Compatible with Kali Linux and WSL

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║     RED TEAM ENTERPRISE FRAMEWORK - PROFESSIONAL EDITION          ║
║                      Deployment Script v2.1                       ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Create project structure
echo -e "${YELLOW}[*] Creating project structure...${NC}"

# Create main directories
mkdir -p redteam-enterprise
cd redteam-enterprise

# Create backend directory structure properly
echo -e "${YELLOW}[*] Creating backend directory structure...${NC}"
mkdir -p backend/core
mkdir -p backend/graph
mkdir -p backend/lab
mkdir -p backend/report
mkdir -p backend/api
mkdir -p backend/sessions

# Create __init__.py files in each directory
touch backend/core/__init__.py
touch backend/graph/__init__.py
touch backend/lab/__init__.py
touch backend/report/__init__.py
touch backend/api/__init__.py

# Create frontend directories
echo -e "${YELLOW}[*] Creating frontend directory structure...${NC}"
mkdir -p frontend/css
mkdir -p frontend/js

# Create other directories
mkdir -p sessions
mkdir -p generated_reports

echo -e "${GREEN}[✓] Directory structure created${NC}"

# Create requirements.txt
echo -e "${YELLOW}[*] Creating requirements.txt...${NC}"
cat > backend/requirements.txt << 'EOF'
Flask==2.3.3
Flask-CORS==4.0.0
flask-socketio==5.3.4
python-socketio==5.9.0
eventlet==0.33.3
requests==2.31.0
python-dotenv==1.0.0
neo4j==5.14.0
docker==6.1.3
paramiko==3.3.1
cryptography==41.0.7
jinja2==3.1.2
reportlab==4.0.4
EOF

# Create .env file
cat > .env << 'EOF'
SECRET_KEY=redteam-enterprise-secure-key-2024
NEO4J_USER=redteam
NEO4J_PASS=SecurePass123!
FLASK_ENV=production
EOF

# Create docker-compose.yml
echo -e "${YELLOW}[*] Creating docker-compose.yml...${NC}"
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  backend:
    build: ./backend
    container_name: redteam-backend
    ports:
      - "5000:5000"
    volumes:
      - ./backend:/app
      - ./sessions:/app/sessions
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - FLASK_ENV=production
      - SECRET_KEY=${SECRET_KEY:-redteam-secret-key-2024}
      - NEO4J_URI=${NEO4J_URI:-bolt://neo4j:7687}
      - NEO4J_USER=${NEO4J_USER:-neo4j}
      - NEO4J_PASS=${NEO4J_PASS:-password}
    networks:
      - redteam-network
    restart: unless-stopped

  frontend:
    build: ./frontend
    container_name: redteam-frontend
    ports:
      - "80:80"
    depends_on:
      - backend
    networks:
      - redteam-network
    restart: unless-stopped

  neo4j:
    image: neo4j:5-enterprise
    container_name: redteam-neo4j
    ports:
      - "7474:7474"
      - "7687:7687"
    environment:
      - NEO4J_AUTH=${NEO4J_USER:-neo4j}/${NEO4J_PASS:-password}
      - NEO4J_ACCEPT_LICENSE_AGREEMENT=yes
    volumes:
      - neo4j-data:/data
      - neo4j-logs:/logs
    networks:
      - redteam-network
    restart: unless-stopped

networks:
  redteam-network:
    driver: bridge

volumes:
  neo4j-data:
  neo4j-logs:
EOF

# Create backend Dockerfile
echo -e "${YELLOW}[*] Creating backend Dockerfile...${NC}"
cat > backend/Dockerfile << 'EOF'
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    nmap \
    hydra \
    gobuster \
    nikto \
    whatweb \
    enum4linux \
    smbclient \
    sshpass \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p sessions generated_reports

EXPOSE 5000

CMD ["python", "app.py"]
EOF

# Create frontend Dockerfile
echo -e "${YELLOW}[*] Creating frontend Dockerfile...${NC}"
cat > frontend/Dockerfile << 'EOF'
FROM nginx:alpine

COPY nginx.conf /etc/nginx/nginx.conf
COPY index.html /usr/share/nginx/html/
COPY css/ /usr/share/nginx/html/css/
COPY js/ /usr/share/nginx/html/js/

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
EOF

# Create nginx config
echo -e "${YELLOW}[*] Creating nginx configuration...${NC}"
cat > frontend/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    server {
        listen 80;
        server_name localhost;

        root /usr/share/nginx/html;
        index index.html;

        location / {
            try_files $uri $uri/ /index.html;
        }

        location /api {
            proxy_pass http://backend:5000;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_cache_bypass $http_upgrade;
        }

        location /socket.io {
            proxy_pass http://backend:5000/socket.io;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }
    }
}
EOF

# Create a simple frontend index.html
echo -e "${YELLOW}[*] Creating frontend HTML...${NC}"
cat > frontend/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Red Team Enterprise Framework</title>
    <meta charset="UTF-8">
    <style>
        body {
            margin: 0;
            padding: 0;
            font-family: 'Courier New', monospace;
            background: #0a0e27;
            color: #00d4ff;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container {
            text-align: center;
        }
        h1 {
            font-size: 2em;
            margin-bottom: 20px;
        }
        .status {
            color: #00ff88;
        }
        .loader {
            border: 2px solid #f3f3f3;
            border-top: 2px solid #00d4ff;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Red Team Enterprise Framework</h1>
        <p>Status: <span class="status" id="status">Initializing...</span></p>
        <div class="loader" id="loader"></div>
        <p id="message">Setting up your environment...</p>
    </div>
    <script>
        let attempts = 0;
        const maxAttempts = 30;
        
        function checkStatus() {
            fetch('/api/health')
                .then(response => {
                    if (response.ok) {
                        document.getElementById('status').textContent = 'Online';
                        document.getElementById('status').style.color = '#00ff88';
                        document.getElementById('loader').style.display = 'none';
                        document.getElementById('message').innerHTML = '✅ Framework ready! Redirecting to dashboard...';
                        setTimeout(() => {
                            window.location.href = 'http://localhost:5000';
                        }, 2000);
                    } else {
                        throw new Error('Not ready');
                    }
                })
                .catch(error => {
                    attempts++;
                    if (attempts < maxAttempts) {
                        document.getElementById('message').innerHTML = `Waiting for services... (${attempts}/${maxAttempts})`;
                        setTimeout(checkStatus, 2000);
                    } else {
                        document.getElementById('status').textContent = 'Timeout';
                        document.getElementById('status').style.color = '#ff3366';
                        document.getElementById('message').innerHTML = '⚠️ Services taking longer than expected. Try accessing <a href="http://localhost:5000">http://localhost:5000</a> directly.';
                        document.getElementById('loader').style.display = 'none';
                    }
                });
        }
        
        setTimeout(checkStatus, 3000);
    </script>
</body>
</html>
EOF

# Create basic CSS file
echo -e "${YELLOW}[*] Creating CSS files...${NC}"
cat > frontend/css/style.css << 'EOF'
body {
    margin: 0;
    padding: 0;
    font-family: 'Courier New', monospace;
    background: #0a0e27;
    color: #00d4ff;
}
EOF

# Create basic JS file
echo -e "${YELLOW}[*] Creating JavaScript files...${NC}"
cat > frontend/js/app.js << 'EOF'
console.log('Red Team Enterprise Framework - Frontend Loaded');
EOF

cat > frontend/js/dashboard.js << 'EOF'
console.log('Dashboard module loaded');
EOF

# Create the main app.py (simplified but functional)
echo -e "${YELLOW}[*] Creating backend app.py...${NC}"
cat > backend/app.py << 'EOF'
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO
import os
import platform
import subprocess

app = Flask(__name__, static_folder='../frontend', static_url_path='')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'redteam-secret-key-2024')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Store targets in memory
targets = []

@app.route('/')
def serve_frontend():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': __import__('datetime').datetime.now().isoformat(),
        'version': '2.0.0',
        'system': platform.node()
    })

@app.route('/api/status')
def status():
    return jsonify({
        'status': 'online',
        'version': '2.0.0',
        'message': 'Red Team Enterprise Framework is running',
        'targets': len(targets),
        'python_version': platform.python_version(),
        'system': platform.system()
    })

@app.route('/api/targets', methods=['GET'])
def get_targets():
    return jsonify(targets)

@app.route('/api/targets', methods=['POST'])
def add_target():
    import datetime
    data = request.json
    target = {
        'id': len(targets) + 1,
        'address': data.get('address'),
        'status': 'pending',
        'created': datetime.datetime.now().isoformat()
    }
    targets.append(target)
    return jsonify(target), 201

@app.route('/api/execute', methods=['POST'])
def execute_command():
    import subprocess
    import shlex
    data = request.json
    command = data.get('command', '')
    
    # Basic command validation
    dangerous = ['rm -rf', 'dd if=', 'mkfs', ':(){', 'fork bomb']
    if any(danger in command.lower() for danger in dangerous):
        return jsonify({'error': 'Command blocked for safety'}), 400
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        return jsonify({
            'output': result.stdout,
            'error': result.stderr,
            'returncode': result.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Command timed out'}), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500

from flask import request

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    socketio.emit('connected', {'status': 'Connected to Red Team Framework'})

@socketio.on('execute_command')
def handle_command(data):
    import subprocess
    command = data.get('command', '')
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        socketio.emit('command_result', {
            'output': result.stdout,
            'error': result.stderr,
            'status': 'completed' if result.returncode == 0 else 'failed'
        })
    except Exception as e:
        socketio.emit('command_result', {'error': str(e), 'status': 'error'})

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║     RED TEAM ENTERPRISE FRAMEWORK - PROFESSIONAL EDITION   ║
    ║                                                            ║
    ║  Access: http://localhost:5000                            ║
    ║  API: http://localhost:5000/api                           ║
    ║                                                            ║
    ║  ⚠️  Educational Purpose Only                            ║
    ║  ⚠️  Use only in authorized environments                 ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
EOF

# Make the script executable
chmod +x deploy.sh

# Build and start containers
echo -e "${YELLOW}[*] Building Docker containers...${NC}"
docker-compose build --no-cache

echo -e "${YELLOW}[*] Starting services...${NC}"
docker-compose up -d

# Wait for services
echo -e "${YELLOW}[*] Waiting for services to be ready...${NC}"
sleep 15

# Check service status
echo -e "${YELLOW}[*] Checking service status...${NC}"
docker-compose ps

# Display completion message
echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    DEPLOYMENT COMPLETE!                    ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${GREEN}[✓] Red Team Enterprise Framework is now running${NC}"
echo ""
echo -e "${BLUE}Access URLs:${NC}"
echo "  • Web Interface: http://localhost:5000"
echo "  • API Endpoint: http://localhost:5000/api"
echo "  • Neo4j Browser: http://localhost:7474 (neo4j/redteam)"
echo ""
echo -e "${BLUE}Useful Commands:${NC}"
echo "  • View logs: docker-compose logs -f"
echo "  • Stop services: docker-compose down"
echo "  • Restart services: docker-compose restart"
echo "  • Check status: docker-compose ps"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT NOTES:${NC}"
echo "  • This framework is for EDUCATIONAL purposes only"
echo "  • Only use in authorized environments"
echo "  • Change default Neo4j password: neo4j/redteam"
echo ""

# Try to open browser
if command -v xdg-open &> /dev/null; then
    echo -e "${BLUE}Opening browser...${NC}"
    xdg-open http://localhost:5000
elif command -v open &> /dev/null; then
    open http://localhost:5000
fi
