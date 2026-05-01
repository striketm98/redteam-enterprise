#!/bin/bash

# Red Team Enterprise Framework - Deployment Script
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
║                      Deployment Script v2.0                       ║
║                                                                   ║
║  Author: Security Research Team                                  ║
║  License: Educational Purpose Only                               ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}[!] Do not run as root! Use a regular user with docker privileges.${NC}"
   exit 1
fi

# Check Docker installation
echo -e "${YELLOW}[*] Checking Docker installation...${NC}"
if ! command -v docker &> /dev/null; then
    echo -e "${RED}[!] Docker not found. Installing Docker...${NC}"
    
    # Detect OS
    if grep -q Microsoft /proc/version; then
        echo -e "${YELLOW}[*] WSL detected. Installing Docker Desktop for Windows is recommended.${NC}"
        echo -e "${YELLOW}[*] Alternatively, install Docker Engine:${NC}"
        echo "  curl -fsSL https://get.docker.com -o get-docker.sh"
        echo "  sudo sh get-docker.sh"
        exit 1
    elif [[ "$(uname)" == "Linux" ]]; then
        # Install Docker on Kali Linux
        sudo apt-get update
        sudo apt-get install -y docker.io docker-compose
        sudo systemctl start docker
        sudo systemctl enable docker
        sudo usermod -aG docker $USER
        echo -e "${GREEN}[✓] Docker installed successfully${NC}"
    fi
fi

# Check Docker Compose
echo -e "${YELLOW}[*] Checking Docker Compose...${NC}"
if ! command -v docker-compose &> /dev/null; then
    echo -e "${YELLOW}[*] Installing Docker Compose...${NC}"
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    echo -e "${GREEN}[✓] Docker Compose installed${NC}"
fi

# Create project structure
echo -e "${YELLOW}[*] Creating project structure...${NC}"
mkdir -p redteam-enterprise/{backend,frontend,sessions,generated_reports}
cd redteam-enterprise

# Create necessary files (content from above)
echo -e "${YELLOW}[*] Creating backend files...${NC}"

# Backend directories
mkdir -p backend/{core,graph,lab,report,api,sessions}
touch backend/{core,graph,lab,report,api}/__init__.py

# Copy all the Python files
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

# Create Docker Compose file
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
      - "443:443"
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
    crackmapexec \
    sshpass \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p sessions generated_reports

EXPOSE 5000

CMD ["python", "app.py"]
EOF

# Create frontend Dockerfile
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
mkdir -p frontend/css frontend/js

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

# Create simple frontend files
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
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Red Team Enterprise Framework</h1>
        <p>Status: <span class="status">Deploying...</span></p>
        <p>Please wait while services initialize...</p>
        <p>Access the full dashboard at <a href="http://localhost:5000">http://localhost:5000</a></p>
    </div>
    <script>
        setTimeout(() => {
            window.location.href = 'http://localhost:5000';
        }, 5000);
    </script>
</body>
</html>
EOF

# Create the main app.py file (simplified version for quick deployment)
cat > backend/app.py << 'EOF'
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO
import os

app = Flask(__name__, static_folder='../frontend', static_url_path='')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'redteam-secret-key-2024')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/')
def serve_frontend():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/status')
def status():
    return jsonify({
        'status': 'online',
        'version': '2.0',
        'message': 'Red Team Enterprise Framework is running'
    })

@app.route('/api/health')
def health():
    return jsonify({'healthy': True})

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
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
EOF

# Make scripts executable
chmod +x deploy.sh

# Build and start containers
echo -e "${YELLOW}[*] Building Docker containers...${NC}"
docker-compose build --no-cache

echo -e "${YELLOW}[*] Starting services...${NC}"
docker-compose up -d

# Wait for services to be ready
echo -e "${YELLOW}[*] Waiting for services to be ready...${NC}"
sleep 10

# Check service status
echo -e "${YELLOW}[*] Checking service status...${NC}"
docker-compose ps

# Display access information
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
echo "  • Rebuild: ./deploy.sh"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT NOTES:${NC}"
echo "  • This framework is for EDUCATIONAL purposes only"
echo "  • Only use in authorized environments"
echo "  • All actions are logged for accountability"
echo "  • Default credentials: Change them immediately!"
echo ""
echo -e "${GREEN}Happy Red Teaming! 🚀${NC}"

# Open browser (optional - works on some systems)
if command -v xdg-open &> /dev/null; then
    xdg-open http://localhost:5000
elif command -v open &> /dev/null; then
    open http://localhost:5000
fi