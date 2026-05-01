FROM python:3.11-slim

# Install system dependencies and Kali Linux tools
RUN apt-get update && apt-get install -y \
    # Network scanning tools
    nmap \
    masscan \
    netcat-openbsd \
    tcpdump \
    wireshark \
    # Web application tools
    gobuster \
    nikto \
    whatweb \
    wpscan \
    dirb \
    ffuf \
    # Password attacks
    hydra \
    john \
    hashcat \
    # Exploitation tools
    metasploit-framework \
    sqlmap \
    # Additional utilities
    curl \
    wget \
    git \
    vim \
    nano \
    procps \
    iputils-ping \
    dnsutils \
    openssh-client \
    sudo \
    # Python build dependencies
    gcc \
    g++ \
    make \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p reports \
    /var/log/redteamka \
    /app/sessions \
    /app/uploads \
    /tmp/wordlists

# Download common wordlists (optional)
RUN mkdir -p /usr/share/wordlists && \
    if [ -f /usr/share/wordlists/dirb/common.txt ]; then \
        echo "Wordlist already exists"; \
    else \
        echo "Wordlist not found - will use built-in"; \
    fi

# Set environment variables
ENV FLASK_ENV=production \
    FLASK_APP=app.py \
    PYTHONUNBUFFERED=1 \
    TZ=UTC

# Expose port
EXPOSE 8888

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8888/api/health || exit 1

# Run the application
CMD ["python", "app.py"]
