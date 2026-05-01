#!/bin/bash

# Red Team Enterprise Framework - Working Deployment Script

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║     RED TEAM ENTERPRISE FRAMEWORK - WORKING EDITION              ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Create directory structure
echo -e "${YELLOW}[*] Creating directory structure...${NC}"
mkdir -p redteam-enterprise/backend/{core,graph,lab,report,api,sessions}
mkdir -p redteam-enterprise/frontend/{css,js}
mkdir -p redteam-enterprise/{sessions,generated_reports}

cd redteam-enterprise

# Create __init__.py files
touch backend/{core,graph,lab,report,api}/__init__.py

# Create requirements.txt
cat > backend/requirements.txt << 'EOF'
Flask==2.3.3
Flask-CORS==4.0.0
flask-socketio==5.3.4
python-socketio==5.9.0
eventlet==0.33.3
requests==2.31.0
python-dotenv==1.0.0
EOF

# Create working Dockerfile
cat > backend/Dockerfile << 'EOF'
FROM python:3.11-slim

WORKDIR /app

# Install system tools (only those that exist)
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    wget \
    openssh-client \
    procps \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create directories
RUN mkdir -p sessions generated_reports

EXPOSE 5000

CMD ["python", "app.py"]
EOF

# Create docker-compose.yml
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
    environment:
      - FLASK_ENV=production
      - SECRET_KEY=redteam-secret-key-2024
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

networks:
  redteam-network:
    driver: bridge
EOF

# Create frontend files
cat > frontend/Dockerfile << 'EOF'
FROM nginx:alpine
COPY nginx.conf /etc/nginx/nginx.conf
COPY index.html /usr/share/nginx/html/
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
EOF

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

        location / {
            root /usr/share/nginx/html;
            index index.html;
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

# Create simple index.html
cat > frontend/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Red Team Framework</title>
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
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Red Team Enterprise Framework</h1>
        <p>Status: <span class="status" id="status">Checking...</span></p>
        <p id="message">Loading dashboard...</p>
    </div>
    <script>
        fetch('/api/health')
            .then(response => response.json())
            .then(data => {
                document.getElementById('status').textContent = 'Online';
                document.getElementById('message').innerHTML = 'Redirecting to dashboard...';
                setTimeout(() => {
                    window.location.href = 'http://localhost:5000';
                }, 2000);
            })
            .catch(() => {
                document.getElementById('message').innerHTML = 'Access dashboard directly at <a href="http://localhost:5000">http://localhost:5000</a>';
            });
    </script>
</body>
</html>
EOF

# Create working app.py
cat > backend/app.py << 'EOF'
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO
import os
import platform
import subprocess
from datetime import datetime

app = Flask(__name__, static_folder='../frontend', static_url_path='')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'redteam-secret-key-2024')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

targets = []

@app.route('/')
def serve_frontend():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0'
    })

@app.route('/api/status')
def status():
    return jsonify({
        'status': 'online',
        'version': '2.0.0',
        'targets': len(targets),
        'system': platform.system()
    })

@app.route('/api/targets', methods=['GET'])
def get_targets():
    return jsonify(targets)

@app.route('/api/targets', methods=['POST'])
def add_target():
    from flask import request
    data = request.json
    target = {
        'id': len(targets) + 1,
        'address': data.get('address'),
        'status': 'pending',
        'created': datetime.now().isoformat()
    }
    targets.append(target)
    return jsonify(target), 201

@app.route('/api/execute', methods=['POST'])
def execute_command():
    from flask import request
    data = request.json
    command = data.get('command', '')
    
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

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    socketio.emit('connected', {'status': 'Connected'})

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║     RED TEAM ENTERPRISE FRAMEWORK                         ║
    ║     Access: http://localhost:5000                        ║
    ║     API: http://localhost:5000/api                       ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
EOF

# Build and run
echo -e "${YELLOW}[*] Building Docker images...${NC}"
docker-compose build --no-cache

echo -e "${YELLOW}[*] Starting services...${NC}"
docker-compose up -d

echo -e "${YELLOW}[*] Waiting for services...${NC}"
sleep 10

echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    DEPLOYMENT COMPLETE!                    ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${GREEN}[✓] Framework is running${NC}"
echo ""
echo -e "${BLUE}Access URLs:${NC}"
echo "  • Web Interface: http://localhost:5000"
echo "  • API: http://localhost:5000/api"
echo ""
echo -e "${BLUE}Useful Commands:${NC}"
echo "  • View logs: docker-compose logs -f"
echo "  • Stop: docker-compose down"
echo "  • Restart: docker-compose restart"
echo ""

# Try to open browser
if command -v xdg-open &> /dev/null; then
    xdg-open http://localhost:5000
fi
